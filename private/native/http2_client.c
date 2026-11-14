// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

#include <nghttp2/nghttp2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum { H2_OK, H2_PROTOCOL, H2_LIMIT, H2_MEMORY, H2_BUSY, H2_UNKNOWN };
enum { H2_PENDING, H2_COMPLETE, H2_RESET, H2_TOO_LARGE };
enum { MAX_FIELDS = 128, MAX_HEADER_BYTES = 32768 };
static const uint8_t empty_bytes[] = "";

typedef struct {
    const uint8_t *name;
    const uint8_t *value;
    int32_t name_size;
    int32_t value_size;
} http2_field;

typedef struct {
    uint8_t *bytes;
    int32_t name_size;
    int32_t value_size;
    int trailer;
} stored_field;

typedef struct {
    int32_t id;
    int32_t status;
    int32_t result;
    uint32_t error;
    int final_head;
    int too_large;
    int32_t field_count;
    size_t field_bytes;
    unsigned informational;
    stored_field fields[MAX_FIELDS];
    uint8_t *request;
    size_t request_size;
    size_t sent;
    uint8_t *body;
    size_t body_size;
    size_t body_capacity;
} http2_stream;

typedef struct {
    nghttp2_session *session;
    http2_stream *streams;
    int32_t stream_count;
    size_t body_limit;
} http2_client;

static void clear_fields(http2_stream *stream) {
    for (int i = 0; i < stream->field_count; ++i) free(stream->fields[i].bytes);
    stream->field_count = 0;
    stream->field_bytes = 0;
}

static void clear_stream(http2_stream *stream) {
    clear_fields(stream);
    free(stream->body);
    free(stream->request);
    memset(stream, 0, sizeof(*stream));
}

static http2_stream *find_stream(http2_client *client, int32_t id) {
    if (id <= 0) return NULL;
    for (int i = 0; i < client->stream_count; ++i) {
        if (client->streams[i].id == id) return &client->streams[i];
    }
    return NULL;
}

static int reject_limit(nghttp2_session *session, http2_stream *stream) {
    if (!stream->too_large) {
        stream->too_large = 1;
        if (nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream->id, NGHTTP2_ENHANCE_YOUR_CALM))
            return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

static int receive_header(nghttp2_session *session, const nghttp2_frame *frame,
                          const uint8_t *name, size_t name_size, const uint8_t *value,
                          size_t value_size, uint8_t flags, void *opaque) {
    (void)flags;
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    http2_stream *stream = find_stream(opaque, frame->hd.stream_id);
    if (!stream || stream->too_large) return 0;
    if (name_size == 7 && memcmp(name, ":status", 7) == 0) {
        if (value_size != 3 || stream->final_head || value[0] < '1' || value[0] > '5' ||
            value[1] < '0' || value[1] > '9' || value[2] < '0' || value[2] > '9')
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        stream->status = (value[0] - '0') * 100 + (value[1] - '0') * 10 + value[2] - '0';
        return 0;
    }
    if (stream->field_count == MAX_FIELDS || name_size > MAX_HEADER_BYTES ||
        value_size > MAX_HEADER_BYTES || name_size + value_size + 32 + stream->field_bytes > MAX_HEADER_BYTES)
        return reject_limit(session, stream);

    uint8_t *bytes = malloc(name_size + value_size);
    if (!bytes) return NGHTTP2_ERR_CALLBACK_FAILURE;
    memcpy(bytes, name, name_size);
    if (value_size) memcpy(bytes + name_size, value, value_size);
    stream->fields[stream->field_count++] = (stored_field){
        bytes, (int32_t)name_size, (int32_t)value_size, stream->final_head
    };
    stream->field_bytes += name_size + value_size + 32;
    return 0;
}

static int receive_frame(nghttp2_session *session, const nghttp2_frame *frame, void *opaque) {
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    http2_stream *stream = find_stream(opaque, frame->hd.stream_id);
    if (!stream || stream->too_large || stream->final_head) return 0;
    if (stream->status < 200) {
        if (++stream->informational > 16) return reject_limit(session, stream);
        clear_fields(stream);
        stream->status = 0;
    } else {
        stream->final_head = 1;
    }
    return 0;
}

static int receive_data(nghttp2_session *session, uint8_t flags, int32_t id,
                        const uint8_t *bytes, size_t size, void *opaque) {
    (void)flags;
    http2_client *client = opaque;
    http2_stream *stream = find_stream(client, id);
    if (!stream || stream->too_large || !size) return 0;
    if (size > client->body_limit - stream->body_size) return reject_limit(session, stream);

    size_t need = stream->body_size + size;
    if (need > stream->body_capacity) {
        size_t capacity = stream->body_capacity ? stream->body_capacity * 2 : 4096;
        if (capacity < need) capacity = need;
        if (capacity > client->body_limit) capacity = client->body_limit;
        uint8_t *body = realloc(stream->body, capacity);
        if (!body) return NGHTTP2_ERR_CALLBACK_FAILURE;
        stream->body = body;
        stream->body_capacity = capacity;
    }
    memcpy(stream->body + stream->body_size, bytes, size);
    stream->body_size = need;
    return 0;
}

static int close_stream(nghttp2_session *session, int32_t id, uint32_t code, void *opaque) {
    (void)session;
    http2_stream *stream = find_stream(opaque, id);
    if (stream) {
        stream->error = code;
        stream->result = stream->too_large ? H2_TOO_LARGE :
            code == NGHTTP2_NO_ERROR && stream->final_head ? H2_COMPLETE : H2_RESET;
        free(stream->request);
        stream->request = NULL;
        if (stream->result != H2_COMPLETE) {
            clear_fields(stream);
            free(stream->body);
            stream->body = NULL;
            stream->body_size = 0;
        }
    }
    return 0;
}

static nghttp2_ssize send_body(nghttp2_session *session, int32_t id, uint8_t *output,
                              size_t capacity, uint32_t *flags,
                              nghttp2_data_source *source, void *opaque) {
    (void)session; (void)id; (void)opaque;
    http2_stream *stream = source->ptr;
    size_t count = stream->request_size - stream->sent;
    if (count > capacity) count = capacity;
    if (count) memcpy(output, stream->request + stream->sent, count);
    stream->sent += count;
    if (stream->sent == stream->request_size) {
        *flags |= NGHTTP2_DATA_FLAG_EOF;
        free(stream->request);
        stream->request = NULL;
    }
    return (nghttp2_ssize)count;
}

static void nyra_http2_drop(http2_client *client) {
    if (!client) return;
    if (client->session) nghttp2_session_del(client->session);
    for (int i = 0; i < client->stream_count; ++i) clear_stream(&client->streams[i]);
    free(client->streams);
    free(client);
}

static http2_client *nyra_http2_new(int32_t slots, int32_t limit) {
    if (slots < 1 || slots > 16 || limit < 1 || limit > 16777216) return NULL;
    http2_client *client = calloc(1, sizeof(*client));
    nghttp2_session_callbacks *callbacks = NULL;
    nghttp2_option *options = NULL;
    if (!client) return NULL;
    client->streams = calloc((size_t)slots, sizeof(*client->streams));
    if (!client->streams) goto failed;
    client->stream_count = slots;
    client->body_limit = (size_t)limit;
    if (nghttp2_session_callbacks_new(&callbacks) || nghttp2_option_new(&options)) goto failed;
    nghttp2_session_callbacks_set_on_header_callback(callbacks, receive_header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, receive_frame);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, receive_data);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, close_stream);
    nghttp2_option_set_max_reserved_remote_streams(options, 0);
    nghttp2_option_set_max_settings(options, 32);
    nghttp2_option_set_max_outbound_ack(options, 64);
    nghttp2_option_set_max_continuations(options, 16);
    if (nghttp2_session_client_new2(&client->session, callbacks, client, options)) goto failed;
    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
        {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, MAX_HEADER_BYTES},
    };
    if (nghttp2_submit_settings(client->session, NGHTTP2_FLAG_NONE, settings, 2)) goto failed;
    nghttp2_session_callbacks_del(callbacks);
    nghttp2_option_del(options);
    return client;
failed:
    if (callbacks) nghttp2_session_callbacks_del(callbacks);
    if (options) nghttp2_option_del(options);
    nyra_http2_drop(client);
    return NULL;
}

static int nyra_http2_submit(http2_client *client, const http2_field *fields, int32_t count,
                      const uint8_t *body, int32_t length, int32_t *id, int32_t *detail) {
    if (count < 4 || count > MAX_FIELDS || length < 0 || (size_t)length > client->body_limit)
        return H2_LIMIT;
    if (!nghttp2_session_check_request_allowed(client->session)) return H2_PROTOCOL;
    http2_stream *stream = NULL;
    for (int i = 0; i < client->stream_count; ++i) {
        if (!client->streams[i].id) {
            stream = &client->streams[i];
            break;
        }
    }
    if (!stream) return H2_BUSY;

    nghttp2_nv headers[MAX_FIELDS];
    size_t total = 0;
    for (int i = 0; i < count; ++i) {
        const http2_field *field = &fields[i];
        total += (size_t)field->name_size + (size_t)field->value_size + 32;
        if (total > MAX_HEADER_BYTES) return H2_LIMIT;
        uint8_t flags = NGHTTP2_NV_FLAG_NONE;
        if ((field->name_size == 13 && !memcmp(field->name, "authorization", 13)) ||
            (field->name_size == 6 && !memcmp(field->name, "cookie", 6)))
            flags = NGHTTP2_NV_FLAG_NO_INDEX;
        headers[i] = (nghttp2_nv){(uint8_t *)field->name,
            (uint8_t *)(field->value_size ? field->value : empty_bytes),
            (size_t)field->name_size, (size_t)field->value_size, flags};
    }

    nghttp2_data_provider2 provider = {{.ptr = stream}, send_body};
    if (length) {
        stream->request = malloc((size_t)length);
        if (!stream->request) return H2_MEMORY;
        memcpy(stream->request, body, (size_t)length);
        stream->request_size = (size_t)length;
    }
    int32_t result = nghttp2_submit_request2(client->session, NULL, headers, (size_t)count,
                                             length ? &provider : NULL, stream);
    if (result < 0) {
        clear_stream(stream);
        *detail = result;
        return result == NGHTTP2_ERR_NOMEM ? H2_MEMORY : H2_PROTOCOL;
    }
    stream->id = result;
    *id = result;
    return H2_OK;
}

static intptr_t nyra_http2_output(http2_client *client, const uint8_t **data) {
    return (intptr_t)nghttp2_session_mem_send2(client->session, data);
}

static intptr_t nyra_http2_input(http2_client *client, const uint8_t *bytes, intptr_t length) {
    return (intptr_t)nghttp2_session_mem_recv2(client->session, bytes, (size_t)length);
}

static int nyra_http2_wants_input(http2_client *client) {
    return nghttp2_session_want_read(client->session);
}

static int nyra_http2_stream(http2_client *client, int32_t id, int32_t *state,
                      int32_t *status, int32_t *code, int32_t *fields,
                      const uint8_t **body, int32_t *size) {
    http2_stream *stream = find_stream(client, id);
    if (!stream) return H2_UNKNOWN;
    *state = stream->result;
    *status = stream->status;
    *code = (int32_t)stream->error;
    *fields = stream->field_count;
    *body = stream->body;
    *size = (int32_t)stream->body_size;
    return H2_OK;
}

static int nyra_http2_field(http2_client *client, int32_t id, int32_t index, http2_field *value) {
    http2_stream *stream = find_stream(client, id);
    if (!stream || index < 0 || index >= stream->field_count) return -1;
    stored_field *field = &stream->fields[index];
    *value = (http2_field){field->bytes, field->bytes + field->name_size, field->name_size, field->value_size};
    return field->trailer;
}

static void nyra_http2_release(http2_client *client, int32_t id) {
    http2_stream *stream = find_stream(client, id);
    if (stream && stream->result != H2_PENDING) clear_stream(stream);
}

typedef struct {
    http2_client *(*create_session)(int32_t, int32_t);
    void (*drop_session)(http2_client *);
    intptr_t (*output)(http2_client *, const uint8_t **);
    intptr_t (*input)(http2_client *, const uint8_t *, intptr_t);
    int (*wants_input)(http2_client *);
    int (*submit)(http2_client *, const http2_field *, int32_t, const uint8_t *,
                  int32_t, int32_t *, int32_t *);
    int (*stream)(http2_client *, int32_t, int32_t *, int32_t *, int32_t *, int32_t *,
                  const uint8_t **, int32_t *);
    int (*field)(http2_client *, int32_t, int32_t, http2_field *);
    void (*release_stream)(http2_client *, int32_t);
} http2_provider_api;

#ifdef _WIN32
__declspec(dllexport)
#else
__attribute__((visibility("default")))
#endif
int nyra_http2_provider(int32_t version, http2_provider_api *api) {
    if (version != 1 || !api) return 0;
    *api = (http2_provider_api){
        .create_session = nyra_http2_new,
        .drop_session = nyra_http2_drop,
        .output = nyra_http2_output,
        .input = nyra_http2_input,
        .wants_input = nyra_http2_wants_input,
        .submit = nyra_http2_submit,
        .stream = nyra_http2_stream,
        .field = nyra_http2_field,
        .release_stream = nyra_http2_release,
    };
    return 1;
}
