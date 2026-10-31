// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

module HttpExchange;
part "upload.ny";
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/client.ni";
import "interface/url.ni";
import "interface/redirect.ni";
import "private/grammar.ny";
import "private/http.ny";
import "private/body.ny";
import "private/body_writer.ny";
import "private/response.ny";

/** @brief Bounded request upload and response pull events shared across transports. */

struct HttpExchangeData {
  request: HttpHead;
  head_wire: NetBuffer;
  body: NetBuffer;
  head_length: intptr;
  body_length: intptr;
  head_cursor: intptr;
  body_cursor: intptr;
  writer: HttpBodyWriter;
  response: HttpResponseParser;
  decoder: HttpBodyDecoder;
  limits: HttpClientLimits;
  pending: NetBuffer;
  pending_cursor: intptr;
  input: NetBuffer;
  input_cursor: intptr;
  eof: bool;
  finish_queued: bool;
  has_head: bool;
  complete: bool;
  failure: HttpError?;
  stats: HttpClientStats;
  streaming: bool;
  await_continue: bool;
  stopped: bool;
  partial_head: bool;
  supplied: uint64;
  scratch: <uint8>[16384];
}

/**
 * @brief Move-only, single-caller exchange with bounded incoming/outgoing blocks and no
 *   transport operations.
 */
pub struct HttpClientExchange {
  cell: arc<HttpExchangeData>?;
}

method(HttpExchangeData) Fail(error: HttpError) -> HttpError {
  self.failure = error;

  return error;
}

// Validate shared head/framing limits before either upload mode is admitted.
static method(HttpClientExchange) NewWithMode(
  head: ref NetBuffer,
  body: ref NetBuffer,
  limits: ref HttpClientLimits,
  streaming: bool
) -> Result<HttpClientExchange, HttpError> {
  var caps: HttpClientLimits = limits;
  if caps.max_retained_request_bytes == 0 {
    caps.max_retained_request_bytes = 16777216;
  }

  if caps.max_retained_request_bytes < 1 || caps.max_retained_request_bytes > 1073741824 {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  let budget: intptr = caps.max_retained_request_bytes as intptr;
  if head.RetainedBytes() > budget || body.RetainedBytes() > budget - head.RetainedBytes() {
    return HttpError{kind: HttpErrorKind.LimitExceeded};
  }

  var parsed: Result<HttpHeadParser, HttpError> = HttpHeadParser.NewRequest(caps.request_head);
  if parsed.IsErr() {
    return (parsed.get_if<HttpError>()) as HttpError;
  }

  var parser: HttpHeadParser = move((parsed.get_if<HttpHeadParser>()) as HttpHeadParser);
  let fed: Result<intptr, HttpError> = parser.Push(head.Bytes());
  if fed.IsErr() {
    return (fed.get_if<HttpError>()) as HttpError;
  }

  if !parser.IsComplete() {
    return HttpError{kind: HttpErrorKind.UnexpectedEof};
  }

  if ((fed.get_if<intptr>()) as intptr) != head.Len() {
    return HttpError{kind: HttpErrorKind.InvalidFraming};
  }

  let request: HttpHead = (parser.Head().get_if<HttpHead>()) as HttpHead;
  if request.MinorVersion() != 1 || request.Method().Equal("CONNECT") {
    return HttpError{kind: HttpErrorKind.Unsupported};
  }

  var expect: bool = false;
  var i: int32 = 0;
  while i < request.FieldCount() {
    let field: HttpField = (request.FieldAt(i).get_if<HttpField>()) as HttpField;
    if (field.name).EqualAsciiIgnoreCase("Upgrade") {
      return HttpError{kind: HttpErrorKind.Unsupported};
    }

    if (field.name).EqualAsciiIgnoreCase("Expect") {
      if !streaming || expect || !(field.value).EqualAsciiIgnoreCase("100-continue") {
        return HttpError{kind: HttpErrorKind.Unsupported};
      }

      expect = true;
    }

    i = i + 1;
  }

  let plan: HttpBodyPlan = (request.BodyPlan().get_if<HttpBodyPlan>()) as HttpBodyPlan;
  if expect
    && (plan.kind == HttpBodyKind.None || (plan.kind == HttpBodyKind.ContentLength && plan.length == 0u64)) {
    return HttpError{kind: HttpErrorKind.InvalidFraming};
  }

  if !streaming
    && (
      (plan.kind == HttpBodyKind.None && body.Len() != (0ip)) || (
        plan.kind == HttpBodyKind.ContentLength && plan.length != body.Len() as uint64
      )
    ) {
    return HttpError{kind: HttpErrorKind.InvalidFraming};
  }

  var max_body: uint64 = caps.body.max_body_bytes;
  if max_body == 0u64 {
    max_body = 16777216u64;
  }

  if (body.Len() as uint64) > max_body {
    return HttpError{kind: HttpErrorKind.LimitExceeded};
  }

  var writer: Result<HttpBodyWriter, HttpError> = HttpBodyWriter.New(request, caps.body);
  if writer.IsErr() {
    return (writer.get_if<HttpError>()) as HttpError;
  }

  var response: Result<HttpResponseParser, HttpError> = HttpResponseParser.New(
    request.Method(),
    caps.response
  );
  if response.IsErr() {
    return (response.get_if<HttpError>()) as HttpError;
  }

  return HttpClientExchange{cell: new arc<HttpExchangeData>{
    request: request,
    head_wire: head,
    body: body,
    head_length: head.Len(),
    body_length: body.Len(),
    limits: caps,
    streaming: streaming,
    await_continue: expect,
    finish_queued: streaming
      && (plan.kind == HttpBodyKind.None || (plan.kind == HttpBodyKind.ContentLength && plan.length == 0u64)),
    writer: move((writer.get_if<HttpBodyWriter>()) as HttpBodyWriter),
    response: move((response.get_if<HttpResponseParser>()) as HttpResponseParser)
  }};
}

/**
 * @brief Validate and retain one HTTP/1.1 request head and immutable body before transport
 *   adoption.
 * @returns Ok with HttpClientExchange on success; Err with HttpError on the failure paths
 *   described above.
 * @note Head must contain exactly one head, fixed length must match body, and no-body must be
 *   empty. Expect, Upgrade and CONNECT are unsupported. Request backing charges entire head/body
 *   owners, including slices; fixed parser storage and at most two 16 KiB blocks are outside that
 *   budget. Request upload precedes response reading; no early-final/100-continue upload gating is
 *   supplied.
 */
pub static method(HttpClientExchange) New(
  head: ref NetBuffer,
  body: ref NetBuffer,
  limits: ref HttpClientLimits
) -> Result<HttpClientExchange, HttpError> {
  return HttpClientExchange.NewWithMode(head, body, limits, false);
}

/**
 * @brief Construct a transport-independent streamed request, retaining no complete body.
 * @returns Ok with HttpClientExchange on success; Err with HttpError on the failure paths
 *   described above.
 * @note Supports fixed/chunked framing and one strict case-insensitive Expect: 100-continue
 *   field. Expect requires a nonempty fixed body or chunked producer. Other expectations are
 *   Unsupported. Each supplied immutable owner is at most 16 KiB including its backing allocation.
 *   Head and current payload obey max_retained_request_bytes; body limits count cumulative
 *   supplied bytes. Callers drive reads and writes, retain original controls and never reuse the
 *   connection. Existing immutable clients and automatic redirect snapshots do not use this
 *   constructor.
 */
pub static method(HttpClientExchange) NewStreaming(
  head: ref NetBuffer,
  limits: ref HttpClientLimits
) -> Result<HttpClientExchange, HttpError> {
  return HttpClientExchange.NewWithMode(head, NetBuffer{}, limits, true);
}

method(HttpExchangeData) HeadSent() -> bool {
  return self.stats.request_bytes_sent >= self.head_length as uint64;
}

method(HttpExchangeData) IsReading() -> bool {
  return self.input_cursor < self.input.Len() || self.partial_head || self.eof;
}

/**
 * @brief Transfer the cursor, retained request and pending blocks.
 * @returns The HttpClientExchange value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpClientExchange) operator move() -> HttpClientExchange {
  let cell: arc<HttpExchangeData>? = self.cell;
  self.cell = nil;

  return HttpClientExchange{cell: cell};
}

/** @brief Release retained request and cursor storage. */
pub method(HttpClientExchange) operator drop() -> void {
  self.cell = nil;
}

/**
 * @brief Owned unacknowledged wire suffix, at most 16 KiB; repeated calls preserve bytes until
 *   acknowledged.
 * @returns Ok with NetBuffer on success; Err with HttpError on the failure paths described
 *   above.
 * @note Streaming output pauses for continue/response parsing or producer input; consult
 *   UploadState. An early final head revokes any unsent suffix. A previously retained output owner
 *   stays valid as data but must never be sent after revocation. No implicit transport
 *   cancellation occurs.
 */
pub method(HttpClientExchange) Output() -> Result<NetBuffer, HttpError> {
  if self.cell == nil {
    return HttpError{kind: HttpErrorKind.Closed};
  }

  var s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.failure != nil {
    return s.failure as HttpError;
  }

  if s.streaming
    && (s.stopped || (s).IsReading() || (s.await_continue && (s).HeadSent())) {
    return NetBuffer{};
  }

  if s.pending_cursor < s.pending.Len() {
    return (s.pending.Slice(
      s.pending_cursor,
      s.pending.Len() - s.pending_cursor
    ).get_if<NetBuffer>()) as NetBuffer;
  }

  s.pending = NetBuffer{};
  s.pending_cursor = 0ip;
  if s.head_cursor < s.head_length {
    var size: intptr = s.head_length - s.head_cursor;
    if size >(16384ip) {
      size = 16384ip;
    }

    let bytes: NetBytes = (s.head_wire.Bytes().Slice(s.head_cursor, size).get_if<NetBytes>()) as NetBytes;
    let copied: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(bytes);
    if copied.IsErr() {
      return (s).Fail(HttpError{kind: HttpErrorKind.ResourceExhausted});
    }

    s.pending = (copied.get_if<NetBuffer>()) as NetBuffer;
    s.head_cursor = s.head_cursor + size;
    if s.head_cursor == s.head_length {
      s.head_wire = NetBuffer{};
    }

    return s.pending;
  }

  if !s.streaming && s.body_cursor == s.body_length && !s.finish_queued {
    let finish: Result<bool, HttpError> = s.writer.Finish(new <HttpField>[0]);
    if finish.IsErr() {
      return (s).Fail((finish.get_if<HttpError>()) as HttpError);
    }

    s.finish_queued = true;
    s.body = NetBuffer{};
  }

  if s.writer.IsComplete() {
    return NetBuffer{};
  }

  var bytes: NetBytes = NetBytes{};
  if s.body_cursor < s.body_length {
    bytes = (s.body.Bytes().Slice(
      s.body_cursor,
      s.body_length - s.body_cursor
    ).get_if<NetBytes>()) as NetBytes;
  }

  let output: NetMutableBytes = (NetMutableBytes.FromRaw(
    &mut s.scratch[0],
    16384ip
  ).get_if<NetMutableBytes>()) as NetMutableBytes;
  let fed: Result<HttpBodyProgress, HttpError> = s.writer.Push(bytes, output);
  if fed.IsErr() {
    return (s).Fail((fed.get_if<HttpError>()) as HttpError);
  }

  let progress: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
  s.body_cursor = s.body_cursor + progress.consumed;
  if s.streaming && progress.produced == (0ip) && progress.state == HttpBodyState.NeedInput {
    return NetBuffer{};
  }

  if progress.produced == (0ip) {
    return (s).Fail(HttpError{kind: HttpErrorKind.InvalidState});
  }

  let range: NetBytes = (output.AsReadOnly().Slice(
    0ip,
    progress.produced
  ).get_if<NetBytes>()) as NetBytes;
  let copied: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(range);
  if copied.IsErr() {
    return (s).Fail(HttpError{kind: HttpErrorKind.ResourceExhausted});
  }

  s.pending = (copied.get_if<NetBuffer>()) as NetBuffer;
  if s.body_cursor == s.body_length {
    s.body = NetBuffer{};
  }

  return s.pending;
}

/**
 * @brief Acknowledge only actual transport acceptance; invalid counts do not change the cursor.
 * @returns Ok with Unit on success; Err with HttpError on the failure paths described above.
 * @note Report every completed write before admitting/parsing a response. Do not leave
 *   unreported in-flight writes when parsing an early final response. Retire the transport after
 *   completion.
 */
pub method(HttpClientExchange) AcknowledgeOutput(count: intptr) -> Result<Unit, HttpError> {
  if self.cell == nil {
    return HttpError{kind: HttpErrorKind.Closed};
  }

  var s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.failure != nil {
    return s.failure as HttpError;
  }

  if s.stopped {
    return HttpError{kind: HttpErrorKind.InvalidState};
  }

  if count <(0ip) || count > s.pending.Len() - s.pending_cursor {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  s.pending_cursor = s.pending_cursor + count;
  s.stats.request_bytes_sent = s.stats.request_bytes_sent + (count as uint64);

  return Unit{};
}

/**
 * @brief All request framing has been generated and acknowledged, not peer-acknowledged.
 * @returns All request framing has been generated and acknowledged, not peer-acknowledged.
 * @note Streamed producers also finish explicitly. An early-stopped upload never reports
 *   success.
 */
pub method(HttpClientExchange) RequestComplete() -> bool {
  if self.cell == nil {
    return false;
  }

  let s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;

  return s.failure == nil
    && !s.stopped
    && (!s.streaming || s.finish_queued)
    && s.head_cursor == s.head_length
    && s.body_cursor == s.body_length
    && s.writer.IsComplete()
    && s.pending_cursor == s.pending.Len();
}

/**
 * @brief Admit one owned incoming block with visible and backing size at most 16 KiB; never
 *   overwrite unread input.
 * @returns Ok with Unit on success; Err with HttpError on the failure paths described above.
 * @note eof must mean ordinary TCP EOF or authenticated TLS close_notify, never a TLS failure.
 *   Streaming cursors admit responses once the entire head has been acknowledged, while the
 *   producer is still open. Drain received heads before further output; final heads stop upload.
 *   Admission failures leave pending input unchanged. Empty non-EOF input is a no-op.
 */
pub method(HttpClientExchange) Receive(buffer: ref NetBuffer, eof: bool) -> Result<Unit, HttpError> {
  if self.cell == nil {
    return HttpError{kind: HttpErrorKind.Closed};
  }

  var s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.failure != nil {
    return s.failure as HttpError;
  }

  if ((!s.streaming && !self.RequestComplete()) || (s.streaming && !(s).HeadSent()))
    || s.complete
    || s.eof
    || s.input_cursor < s.input.Len() {
    return HttpError{kind: HttpErrorKind.InvalidState};
  }

  if buffer.Len() >(16384ip) || buffer.RetainedBytes() >(16384ip) {
    return HttpError{kind: HttpErrorKind.LimitExceeded};
  }

  // Bound aggregate counters even for a hostile transport driving invalid wire indefinitely.
  if (buffer.Len() as uint64) > 18446744073709551615u64 - s.stats.response_bytes_received {
    return HttpError{kind: HttpErrorKind.LimitExceeded};
  }

  s.input = buffer;
  s.input_cursor = 0ip;
  s.eof = eof;
  s.stats.response_bytes_received = s.stats.response_bytes_received + (buffer.Len() as uint64);

  return Unit{};
}

method(HttpExchangeData) Event(
  kind: HttpClientEventKind,
  head: HttpHead,
  buffer: NetBuffer
) -> HttpClientEvent {
  return HttpClientEvent{kind: kind, head: head, buffer: buffer, complete: self.complete, stats: self.stats};
}

/**
 * @brief Pull one informational/head/body/completion event or NeedInput.
 * @returns Ok with HttpClientEvent on success; Err with HttpError on the failure paths described
 *   above.
 * @note Immutable requests require completed upload; streamed requests permit early responses
 *   after head acknowledgement. Only 100 releases Expect; drain buffered heads before writing
 *   again.
 * @note Protocol failures are sticky. Upgrade/tunnel responses are Unsupported. This exchange is
 *   never reusable: extra received bytes remain quarantined until drop. No pool/request queue is
 *   implemented.
 */
pub method(HttpClientExchange) NextResponse() -> Result<HttpClientEvent, HttpError> {
  if self.cell == nil {
    return HttpError{kind: HttpErrorKind.Closed};
  }

  var s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.failure != nil {
    return s.failure as HttpError;
  }

  if (!s.streaming && !self.RequestComplete()) || (s.streaming && !(s).HeadSent()) {
    return HttpError{kind: HttpErrorKind.InvalidState};
  }

  if s.complete {
    return (s).Event(HttpClientEventKind.Complete, HttpHead{}, NetBuffer{});
  }

  while s.input_cursor < s.input.Len() {
    let input: NetBytes = (s.input.Bytes().Slice(
      s.input_cursor,
      s.input.Len() - s.input_cursor
    ).get_if<NetBytes>()) as NetBytes;
    if !s.has_head {
      if s.streaming {
        s.partial_head = true;
      }

      let fed: Result<HttpResponseProgress, HttpError> = s.response.Push(input);
      if fed.IsErr() {
        return (s).Fail((fed.get_if<HttpError>()) as HttpError);
      }

      let progress: HttpResponseProgress = (fed.get_if<HttpResponseProgress>()) as HttpResponseProgress;
      s.input_cursor = s.input_cursor + progress.consumed;
      if s.streaming {
        s.partial_head = progress.state == HttpResponseState.NeedInput;
      }

      if progress.state != HttpResponseState.NeedInput {
        let head: HttpHead = (s.response.Head().get_if<HttpHead>()) as HttpHead;
        if progress.state == HttpResponseState.Informational {
          if head.Status() == 100 {
            s.await_continue = false;
          }

          return (s).Event(HttpClientEventKind.Informational, head, NetBuffer{});
        }

        if s.streaming && !self.RequestComplete() {
          s.stopped = true;
          s.await_continue = false;
          s.body = NetBuffer{};
          s.pending = NetBuffer{};
          s.pending_cursor = 0ip;
          s.writer = HttpBodyWriter{};
          s.body_cursor = 0ip;
          s.body_length = 0ip;
        }

        var made: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(head, s.limits.body);
        if made.IsErr() {
          return (s).Fail((made.get_if<HttpError>()) as HttpError);
        }

        s.decoder = move((made.get_if<HttpBodyDecoder>()) as HttpBodyDecoder);
        s.has_head = true;
        s.complete = s.decoder.IsComplete();

        return (s).Event(HttpClientEventKind.Head, head, NetBuffer{});
      }
    } else {
      let output: NetMutableBytes = (NetMutableBytes.FromRaw(
        &mut s.scratch[0],
        16384ip
      ).get_if<NetMutableBytes>()) as NetMutableBytes;
      let fed: Result<HttpBodyProgress, HttpError> = s.decoder.Push(input, output);
      if fed.IsErr() {
        return (s).Fail((fed.get_if<HttpError>()) as HttpError);
      }

      let progress: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
      s.input_cursor = s.input_cursor + progress.consumed;
      s.complete = s.decoder.IsComplete();
      if progress.produced >(0ip) {
        let bytes: NetBytes = (output.AsReadOnly().Slice(
          0ip,
          progress.produced
        ).get_if<NetBytes>()) as NetBytes;
        let copied: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(bytes);
        if copied.IsErr() {
          return (s).Fail(HttpError{kind: HttpErrorKind.ResourceExhausted});
        }

        return (s).Event(HttpClientEventKind.Body,
          HttpHead{},
          (copied.get_if<NetBuffer>()) as NetBuffer);
      }

      if s.complete {
        return (s).Event(HttpClientEventKind.Complete, HttpHead{}, NetBuffer{});
      }
    }
  }

  s.input = NetBuffer{};
  s.input_cursor = 0ip;
  if s.eof {
    if !s.has_head {
      let end: Result<HttpHead, HttpError> = s.response.EndInput();
      if end.IsErr() {
        return (s).Fail((end.get_if<HttpError>()) as HttpError);
      }
    } else {
      let end: Result<bool, HttpError> = s.decoder.EndInput();
      if end.IsErr() {
        return (s).Fail((end.get_if<HttpError>()) as HttpError);
      }
    }

    s.complete = true;

    return (s).Event(HttpClientEventKind.Complete, HttpHead{}, NetBuffer{});
  }

  return (s).Event(HttpClientEventKind.NeedInput, HttpHead{}, NetBuffer{});
}

/**
 * @brief Immutable validated request head, or Closed for a default cursor.
 * @returns Ok with HttpHead on success; Err with HttpError on the failure paths described above.
 */
pub method(HttpClientExchange) RequestHead() -> Result<HttpHead, HttpError> {
  if self.cell == nil {
    return HttpError{kind: HttpErrorKind.Closed};
  }

  return (self.cell as arc<HttpExchangeData>).request;
}

/**
 * @brief Owned unbracketed request Host without port, or validation/closed failure.
 * @returns Ok with string on success; Err with HttpError on the failure paths described above.
 */
pub method(HttpClientExchange) AuthorityHost() -> Result<string, HttpError> {
  let request: Result<HttpHead, HttpError> = self.RequestHead();
  if request.IsErr() {
    return (request.get_if<HttpError>()) as HttpError;
  }

  let head: HttpHead = (request.get_if<HttpHead>()) as HttpHead;
  var i: int32 = 0;
  while i < head.FieldCount() {
    let field: HttpField = (head.FieldAt(i).get_if<HttpField>()) as HttpField;
    if (field.name).EqualAsciiIgnoreCase("Host") {
      if field.value[0] == '[' {
        let end: int32 = field.value.Find("]");

        return field.value.Substring(1, end - 1);
      }

      let colon: int32 = field.value.Find(":");
      if colon >= 0 {
        return field.value.Substring(0, colon);
      }

      return field.value;
    }

    i = i + 1;
  }

  return HttpError{kind: HttpErrorKind.InvalidState};
}

/**
 * @brief Current framing stage; default is Request.
 * @returns The HttpClientStage value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpClientExchange) Stage() -> HttpClientStage {
  if self.cell == nil {
    return HttpClientStage.Request;
  }

  let s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.has_head {
    return HttpClientStage.ResponseBody;
  }

  if s.streaming && (s).HeadSent() && (s).IsReading() {
    return HttpClientStage.ResponseHead;
  }

  if s.head_cursor == s.head_length
    && s.body_cursor == s.body_length
    && s.writer.IsComplete()
    && s.pending_cursor == s.pending.Len() {
    return HttpClientStage.ResponseHead;
  }

  return HttpClientStage.Request;
}

/**
 * @brief Committed transport counts, including progress before failure.
 * @returns The HttpClientStats value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpClientExchange) Stats() -> HttpClientStats {
  if self.cell == nil {
    return HttpClientStats{};
  }

  return (self.cell as arc<HttpExchangeData>).stats;
}

/**
 * @brief Whether the response framing completed successfully.
 * @returns Whether the response framing completed successfully.
 */
pub method(HttpClientExchange) IsComplete() -> bool {
  if self.cell == nil {
    return false;
  }

  let s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;

  return s.complete && s.failure == nil;
}

/**
 * @brief Completed response trailer count, pending InvalidState or terminal error.
 * @returns Ok with int32 on success; Err with HttpError on the failure paths described above.
 */
pub method(HttpClientExchange) TrailerCount() -> Result<int32, HttpError> {
  if self.cell == nil {
    return HttpError{kind: HttpErrorKind.Closed};
  }

  let s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.failure != nil {
    return s.failure as HttpError;
  }

  if !s.complete {
    return HttpError{kind: HttpErrorKind.InvalidState};
  }

  return s.decoder.TrailerCount();
}

/**
 * @brief Owned response trailer after completion; no header merging.
 * @returns Ok with HttpField on success; Err with HttpError on the failure paths described
 *   above.
 */
pub method(HttpClientExchange) TrailerAt(index: int32) -> Result<HttpField, HttpError> {
  if self.cell == nil {
    return HttpError{kind: HttpErrorKind.Closed};
  }

  let s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.failure != nil {
    return s.failure as HttpError;
  }

  if !s.complete {
    return HttpError{kind: HttpErrorKind.InvalidState};
  }

  return s.decoder.TrailerAt(index);
}
