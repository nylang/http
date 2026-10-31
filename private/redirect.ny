// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

module HttpRedirectPolicy;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/client.ni";
import "interface/url.ni";
import "interface/redirect.ni";
import "private/grammar.ny";
import "private/url.ny";
import "private/url_reference.ny";

struct RedirectRequestData {
  url: HttpUrl;
  verb: string;
  fields: owned <HttpField>[];
  body: NetBuffer;
  head: NetBuffer;
  parsed: HttpHead;
  limits: HttpClientLimits;
  options: NetOperationOptions;
  streaming: bool;
  plan: HttpBodyPlan;
}

/** @brief Copyable immutable request metadata; retained snapshots outlive chain changes/drop. */
pub struct HttpRedirectRequest {
  cell: arc<RedirectRequestData>?;
}

struct RedirectChainData {
  request: HttpRedirectRequest;
  policy: HttpRedirectPolicy;
  count: int32;
  finished: bool;
  replay: HttpBodyReplayPolicy;
  failure: HttpClientError?;
}

/**
 * @brief Move-only single-caller decision cursor; no automatic network I/O, cookie jar or socket
 *   reuse.
 */
pub struct HttpRedirectChain {
  cell: arc<RedirectChainData>?;
}

static method(HttpClientError) FromRedirectKind(kind: HttpErrorKind) -> HttpClientError {
  return HttpClientError{protocol_error: HttpError{kind: kind}, stage: HttpClientStage.ResponseHead};
}

method(RedirectChainData) Fail(error: HttpClientError) -> HttpClientError {
  if self.failure != nil {
    return self.failure as HttpClientError;
  }

  var failure: HttpClientError = error;
  let control: Result<Unit, NetError> = self.request.Options().CheckNow();
  if control.IsErr() {
    failure = HttpClientError{
      transport_error:(control.get_if<NetError>()) as NetError,
      stage: HttpClientStage.ResponseHead
    };
  }

  self.failure = failure;
  self.request = HttpRedirectRequest{};

  return failure;
}

method(RedirectChainData) Finish() -> Result<bool, HttpClientError> {
  let control: Result<Unit, NetError> = self.request.Options().CheckNow();
  if control.IsErr() {
    return self.Fail(HttpClientError{
        transport_error:(control.get_if<NetError>()) as NetError,
        stage: HttpClientStage.ResponseHead
      });
  }

  self.finished = true;

  return false;
}

static method(HttpRedirectRequest) NewWithMode(
  url: ref HttpUrl,
  verb: ref string,
  fields: ref <HttpField>[],
  body: ref NetBuffer,
  limits: ref HttpClientLimits,
  options: ref NetOperationOptions,
  streaming: bool,
  plan: ref HttpBodyPlan
) -> Result<HttpRedirectRequest, HttpClientError> {
  var wire: Result<NetBuffer, HttpError> = HttpError{kind: HttpErrorKind.Closed};
  if streaming {
    wire = url.StreamingRequestHead(verb, fields, plan);
  } else {
    wire = url.RequestHead(verb, fields, body.Len() as uint64);
  }

  if wire.IsErr() {
    return HttpClientError{protocol_error:(wire.get_if<HttpError>()) as HttpError};
  }

  let head: NetBuffer = (wire.get_if<NetBuffer>()) as NetBuffer;
  var checked: Result<HttpClientExchange, HttpError> = HttpError{kind: HttpErrorKind.Closed};
  if streaming {
    checked = HttpClientExchange.NewStreaming(head, limits);
  } else {
    checked = HttpClientExchange.New(head, body, limits);
  }

  if checked.IsErr() {
    return HttpClientError{protocol_error:(checked.get_if<HttpError>()) as HttpError};
  }

  var exchange: HttpClientExchange = move((checked.get_if<HttpClientExchange>()) as HttpClientExchange);
  let parsed: HttpHead = (exchange.RequestHead().get_if<HttpHead>()) as HttpHead;
  var owned_fields: owned <HttpField>[] = new <HttpField>[fields.length];
  var i: int32 = 0;
  while i < fields.length {
    owned_fields[i] = HttpField{name: (fields[i].name).Substring(0, (fields[i].name).length),
      value: (fields[i].value).Substring(0, (fields[i].value).length)};
    i = i + 1;
  }

  return HttpRedirectRequest{cell: new arc<RedirectRequestData>{
    url: url,
    verb: (verb).Substring(0, (verb).length),
    fields: move(owned_fields),
    body: body,
    head: head,
    parsed: parsed,
    limits: limits,
    options: options,
    streaming: streaming,
    plan: plan
  }};
}

/**
 * @brief Validate and own one request plus policy before any network operation.
 * @returns Ok with HttpRedirectChain on success; Err with HttpClientError on the failure paths
 *   described above.
 * @note Copies borrowed method/field strings; retains immutable body owners under request
 *   backing limits. Fixed metadata is bounded by head limits. Caller-retained snapshots are
 *   outside chain budgets. One original absolute control budget applies to every hop; no deadline
 *   refresh.
 */
pub static method(HttpRedirectChain) New(
  url: ref HttpUrl,
  verb: ref string,
  fields: ref <HttpField>[],
  body: ref NetBuffer,
  limits: ref HttpClientLimits,
  policy: ref HttpRedirectPolicy,
  options: ref NetOperationOptions
) -> Result<HttpRedirectChain, HttpClientError> {
  let control: Result<Unit, NetError> = options.CheckNow();
  if control.IsErr() {
    return HttpClientError{transport_error:(control.get_if<NetError>()) as NetError};
  }

  var caps: HttpRedirectPolicy = policy;
  if caps.max_redirects == 0 {
    caps.max_redirects = 5;
  }

  if caps.max_redirects < 1 || caps.max_redirects > 32 {
    return HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}};
  }

  let request: Result<HttpRedirectRequest, HttpClientError> = HttpRedirectRequest.NewWithMode(
    url,
    verb,
    fields,
    body,
    limits,
    options,
    false,
    HttpBodyPlan{}
  );
  if request.IsErr() {
    return (request.get_if<HttpClientError>()) as HttpClientError;
  }

  let final_control: Result<Unit, NetError> = options.CheckNow();
  if final_control.IsErr() {
    return HttpClientError{transport_error:(final_control.get_if<NetError>()) as NetError};
  }

  return HttpRedirectChain{cell: new arc<RedirectChainData>{
    request:(request.get_if<HttpRedirectRequest>()) as HttpRedirectRequest,
    policy: caps
  }};
}

/**
 * @brief Own a streamed URL request's metadata and bounded redirect/replay policy without I/O.
 * @returns Ok with HttpRedirectChain on success; Err with HttpClientError on the failure paths
 *   described above.
 * @note Framing/limits match HttpUrl.StreamingRequestHead and the streamed exchange. Original
 *   controls apply to every decision/hop. Follow rejects preserved nonempty/chunked bodies under
 *   Never, even if no body bytes were sent. Explicit is an application promise to reproduce the
 *   same payload; manual callers must rewind before opening each accepted preserved-body snapshot.
 *   GET rewrites clear producer framing, Expect, Trailer and Content-* metadata without replay.
 *   Same-origin preserved streams retain Trailer. A Connection-nominated Trailer or cross-origin
 *   stream declaring trailers is ReplayRejected instead of silently losing their declaration.
 *   Other filtering, unsafe-method, downgrade and hop policies match immutable New.
 */
pub static method(HttpRedirectChain) NewStreaming(
  url: ref HttpUrl,
  verb: ref string,
  fields: ref <HttpField>[],
  plan: ref HttpBodyPlan,
  limits: ref HttpClientLimits,
  policy: ref HttpRedirectPolicy,
  replay: HttpBodyReplayPolicy,
  options: ref NetOperationOptions
) -> Result<HttpRedirectChain, HttpClientError> {
  let control: Result<Unit, NetError> = options.CheckNow();
  if control.IsErr() {
    return HttpClientError{transport_error:(control.get_if<NetError>()) as NetError};
  }

  var caps: HttpRedirectPolicy = policy;
  if caps.max_redirects == 0 {
    caps.max_redirects = 5;
  }

  if caps.max_redirects < 1
    || caps.max_redirects > 32
    || (replay != HttpBodyReplayPolicy.Never && replay != HttpBodyReplayPolicy.Explicit) {
    return HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}};
  }

  let request: Result<HttpRedirectRequest, HttpClientError> = HttpRedirectRequest.NewWithMode(
    url,
    verb,
    fields,
    NetBuffer{},
    limits,
    options,
    true,
    plan
  );
  if request.IsErr() {
    return (request.get_if<HttpClientError>()) as HttpClientError;
  }

  let final_control: Result<Unit, NetError> = options.CheckNow();
  if final_control.IsErr() {
    return HttpClientError{transport_error:(final_control.get_if<NetError>()) as NetError};
  }

  return HttpRedirectChain{cell: new arc<RedirectChainData>{
    request:(request.get_if<HttpRedirectRequest>()) as HttpRedirectRequest,
    policy: caps,
    replay: replay
  }};
}

/**
 * @brief Transfer current request, controls and decision state.
 * @returns The HttpRedirectChain value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpRedirectChain) operator move() -> HttpRedirectChain {
  let cell: arc<RedirectChainData>? = self.cell;
  self.cell = nil;

  return HttpRedirectChain{cell: cell};
}

/** @brief Release the current request and decision state. */
pub method(HttpRedirectChain) operator drop() -> void {
  self.cell = nil;
}

/**
 * @brief Retain current request, or original failure/InvalidState after a terminal response.
 * @returns Ok with HttpRedirectRequest on success; Err with HttpClientError on the failure paths
 *   described above.
 * @note A snapshot may be explicitly replayed by its owner; the chain does not authorize I/O
 *   itself.
 */
pub method(HttpRedirectChain) Request() -> Result<HttpRedirectRequest, HttpClientError> {
  if self.cell == nil {
    return HttpClientError.FromRedirectKind(HttpErrorKind.Closed);
  }

  let s: arc<RedirectChainData> = self.cell as arc<RedirectChainData>;
  if s.failure != nil {
    return s.failure as HttpClientError;
  }

  if s.finished {
    return HttpClientError.FromRedirectKind(HttpErrorKind.InvalidState);
  }

  let control: Result<Unit, NetError> = s.request.Options().CheckNow();
  if control.IsErr() {
    return (s).Fail(HttpClientError{
        transport_error:(control.get_if<NetError>()) as NetError,
        stage: HttpClientStage.ResponseHead
      });
  }

  return s.request;
}

method(RedirectRequestData) HasHeader(name: ref string) -> bool {
  if (name).EqualAsciiIgnoreCase("Connection")
    || (name).EqualAsciiIgnoreCase("Keep-Alive")
    || (name).EqualAsciiIgnoreCase("Proxy-Connection")
    || (name).EqualAsciiIgnoreCase("Proxy-Authorization")
    || (name).EqualAsciiIgnoreCase("TE")
    || ((name).EqualAsciiIgnoreCase("Trailer") && !self.streaming)
    || (name).EqualAsciiIgnoreCase("Upgrade") {
    return true;
  }

  var i: int32 = 0;
  while i < self.parsed.FieldCount() {
    let field: HttpField = (self.parsed.FieldAt(i).get_if<HttpField>()) as HttpField;
    if (field.name).EqualAsciiIgnoreCase("Connection") {
      var start: int32 = 0;
      var end: int32 = 0;
      while end <= field.value.length {
        if end == field.value.length || field.value[end] == ',' {
          var a: int32 = start;
          var b: int32 = end;
          while a < b && (field.value[a] == ' ' || field.value[a] == '\t') {
            a = a + 1;
          }

          while b > a && (field.value[b - 1] == ' ' || field.value[b - 1] == '\t') {
            b = b - 1;
          }

          if (field.value.Substring(a, b - a)).EqualAsciiIgnoreCase(name) {
            return true;
          }

          start = end + 1;
        }

        end = end + 1;
      }
    }

    i = i + 1;
  }

  return false;
}

method(HttpLexeme) IsContentHeader() -> bool {
  return (self.raw).ToLowerAscii().StartsWith("content-") || (self.raw).EqualAsciiIgnoreCase("Digest")
    || (self.raw).EqualAsciiIgnoreCase("Want-Digest");
}

method(HttpLexeme) CrossOriginAllowed(preserved: bool) -> bool {
  return (self.raw).EqualAsciiIgnoreCase("Accept") || (self.raw).EqualAsciiIgnoreCase("Accept-Encoding")
    || (self.raw).EqualAsciiIgnoreCase("Accept-Language") || (self.raw).EqualAsciiIgnoreCase("User-Agent")
    || (preserved && ((self.raw).EqualAsciiIgnoreCase("Content-Type")
    || (self.raw).EqualAsciiIgnoreCase("Content-Encoding")));
}

/**
 * @brief Decide from the current request's validated final response head, before any new I/O.
 * @returns True commits a new request; false finishes on nonredirect or missing Location; errors
 *   stick.
 * @note Follow only 301/302/303/307/308. 301/302 rewrite POST to GET; 303 rewrites except HEAD.
 *   Rewrites remove body and Content-* metadata. Preserved unsafe method/body requires opt-in.
 *   Duplicate Location is InvalidFraming; malformed Location never falls back to another field.
 *   HTTPS downgrade, disallowed cross-origin and unsafe replay use distinct protocol categories.
 *   Check original controls before decision/publication. Caller must associate the response with
 *   this hop, Close its old client on true/error, then open the new snapshot; do not drain or
 *   reuse its body/connection. On false, keep reading the terminal response normally. This API
 *   accepts heads, not body-completion attestation; transport errors are never interpreted as
 *   redirects.
 */
pub method(HttpRedirectChain) Follow(response: ref HttpHead) -> Result<bool, HttpClientError> {
  if self.cell == nil {
    return HttpClientError.FromRedirectKind(HttpErrorKind.Closed);
  }

  var s: arc<RedirectChainData> = self.cell as arc<RedirectChainData>;
  if s.failure != nil {
    return s.failure as HttpClientError;
  }

  if s.finished {
    return HttpClientError.FromRedirectKind(HttpErrorKind.InvalidState);
  }

  let control: Result<Unit, NetError> = s.request.Options().CheckNow();
  if control.IsErr() {
    return (s).Fail(HttpClientError{
        transport_error:(control.get_if<NetError>()) as NetError,
        stage: HttpClientStage.ResponseHead
      });
  }

  let status: int32 = response.Status();
  if status < 200 {
    return (s).Fail(HttpClientError.FromRedirectKind(HttpErrorKind.InvalidArgument));
  }

  if status != 301 && status != 302 && status != 303 && status != 307 && status != 308 {
    return (s).Finish();
  }

  var location: string = "";
  var found: int32 = 0;
  var i: int32 = 0;
  while i < response.FieldCount() {
    let field: HttpField = (response.FieldAt(i).get_if<HttpField>()) as HttpField;
    if (field.name).EqualAsciiIgnoreCase("Location") {
      found = found + 1;
      location = field.value;
    }

    i = i + 1;
  }

  if found == 0 {
    return (s).Finish();
  }

  if found != 1 {
    return (s).Fail(HttpClientError.FromRedirectKind(HttpErrorKind.InvalidFraming));
  }

  if s.count >= s.policy.max_redirects {
    return (s).Fail(HttpClientError.FromRedirectKind(HttpErrorKind.RedirectLimit));
  }

  let old: arc<RedirectRequestData> = s.request.cell as arc<RedirectRequestData>;
  let resolved: Result<HttpUrl, HttpError> = old.url.Resolve(location);
  if resolved.IsErr() {
    return (s).Fail(HttpClientError{
        protocol_error:(resolved.get_if<HttpError>()) as HttpError,
        stage: HttpClientStage.ResponseHead
      });
  }

  let url: HttpUrl = (resolved.get_if<HttpUrl>()) as HttpUrl;
  if old.url.IsSecure() && !url.IsSecure() {
    return (s).Fail(HttpClientError.FromRedirectKind(HttpErrorKind.InsecureRedirect));
  }

  let cross: bool = !old.url.SameOrigin(url);
  if cross && !s.policy.allow_cross_origin {
    return (s).Fail(HttpClientError.FromRedirectKind(HttpErrorKind.CrossOriginRedirect));
  }

  var verb: string = old.verb;
  var body: NetBuffer = old.body;
  let rewrite: bool = ((status == 301 || status == 302) && verb.Equal("POST"))
    || (status == 303 && !verb.Equal("HEAD"));
  let streamed_body: bool = old.streaming
    && (
      old.plan.kind == HttpBodyKind.Chunked || (
        old.plan.kind == HttpBodyKind.ContentLength && old.plan.length != 0u64
      )
    );
  var plan: HttpBodyPlan = old.plan;
  if rewrite {
    verb = "GET";
    body = NetBuffer{};
    plan = HttpBodyPlan{};
  } else if !s.policy.allow_unsafe_replay
    && (
      streamed_body || body.Len() != (0ip) || (
        !verb.Equal("GET") && !verb.Equal("HEAD") && !verb.Equal("OPTIONS")
      )
    ) {
    return (s).Fail(HttpClientError.FromRedirectKind(HttpErrorKind.ReplayRejected));
  }

  if !rewrite && streamed_body && s.replay != HttpBodyReplayPolicy.Explicit {
    return (s).Fail(HttpClientError.FromRedirectKind(HttpErrorKind.ReplayRejected));
  }

  // Cross-origin filtering must not silently erase promised producer trailers.
  if !rewrite && old.streaming {
    i = 0;
    while i < old.fields.length {
      if (old.fields[i].name).EqualAsciiIgnoreCase("Trailer") && (cross || (old).HasHeader("Trailer")) {
        return (s).Fail(HttpClientError.FromRedirectKind(HttpErrorKind.ReplayRejected));
      }

      i = i + 1;
    }
  }

  var count: int32 = 0;
  i = 0;
  while i < old.fields.length {
    let name: string = old.fields[i].name;
    if !(old).HasHeader(name)
      && ! (
        rewrite && (
          HttpLexeme.New(name).IsContentHeader() || (name).EqualAsciiIgnoreCase("Expect")
            || (name).EqualAsciiIgnoreCase("Trailer")
        )
      )
      && (!cross || HttpLexeme.New(name).CrossOriginAllowed(!rewrite)) {
      count = count + 1;
    }

    i = i + 1;
  }

  var fields: owned <HttpField>[] = new <HttpField>[count];
  count = 0;
  i = 0;
  while i < old.fields.length {
    let field: HttpField = old.fields[i];
    if !(old).HasHeader(field.name)
      && ! (
        rewrite && (
          HttpLexeme.New(field.name).IsContentHeader() || (field.name).EqualAsciiIgnoreCase("Expect")
            || (field.name).EqualAsciiIgnoreCase("Trailer")
        )
      )
      && (!cross || HttpLexeme.New(field.name).CrossOriginAllowed(!rewrite)) {
      fields[count] = field;
      count = count + 1;
    }

    i = i + 1;
  }

  let made: Result<HttpRedirectRequest, HttpClientError> = HttpRedirectRequest.NewWithMode(
    url,
    verb,
    fields,
    body,
    old.limits,
    old.options,
    old.streaming,
    plan
  );
  if made.IsErr() {
    return (s).Fail((made.get_if<HttpClientError>()) as HttpClientError);
  }

  let final_control: Result<Unit, NetError> = old.options.CheckNow();
  if final_control.IsErr() {
    return (s).Fail(HttpClientError{
        transport_error:(final_control.get_if<NetError>()) as NetError,
        stage: HttpClientStage.ResponseHead
      });
  }

  s.request = (made.get_if<HttpRedirectRequest>()) as HttpRedirectRequest;
  s.count = s.count + 1;

  return true;
}

/**
 * @brief Number of committed redirects, excluding the initial request and rejected decisions.
 * @returns Number of committed redirects, excluding the initial request and rejected decisions.
 */
pub method(HttpRedirectChain) Count() -> int32 {
  if self.cell == nil {
    return 0;
  }

  return (self.cell as arc<RedirectChainData>).count;
}

/**
 * @brief Validated URL for routing and certificate/SNI identity; invalid default returns an
 *   invalid URL.
 * @returns The HttpUrl value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpRedirectRequest) Url() -> HttpUrl {
  if self.cell == nil {
    return HttpUrl{};
  }

  return (self.cell as arc<RedirectRequestData>).url;
}

/**
 * @brief Owned case-sensitive method, or empty for a default snapshot.
 * @returns Owned case-sensitive method, or empty for a default snapshot.
 */
pub method(HttpRedirectRequest) Verb() -> string {
  if self.cell == nil {
    return "";
  }

  return (self.cell as arc<RedirectRequestData>).verb;
}

/**
 * @brief Owned validated HTTP/1.1 head including generated URL routing/framing; default is
 *   empty.
 * @returns The NetBuffer value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpRedirectRequest) Head() -> NetBuffer {
  if self.cell == nil {
    return NetBuffer{};
  }

  return (self.cell as arc<RedirectRequestData>).head;
}

/**
 * @brief Retain immutable buffered body storage; empty for streamed/default/GET-rewritten
 *   snapshots.
 * @returns The NetBuffer value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpRedirectRequest) Body() -> NetBuffer {
  if self.cell == nil {
    return NetBuffer{};
  }

  return (self.cell as arc<RedirectRequestData>).body;
}

/**
 * @brief Additional field count excluding generated Host/framing.
 * @returns Additional field count excluding generated Host/framing.
 */
pub method(HttpRedirectRequest) FieldCount() -> int32 {
  if self.cell == nil {
    return 0;
  }

  return (self.cell as arc<RedirectRequestData>).fields.length;
}

/**
 * @brief Owned additional field, or InvalidArgument for a bad index/default snapshot.
 * @returns Ok with HttpField on success; Err with HttpError on the failure paths described
 *   above.
 */
pub method(HttpRedirectRequest) FieldAt(index: int32) -> Result<HttpField, HttpError> {
  if self.cell == nil || index < 0 || index >= self.FieldCount() {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  return (self.cell as arc<RedirectRequestData>).fields[index];
}

/**
 * @brief Copied original message/retention limits; default selects ordinary defaults.
 * @returns The HttpClientLimits value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpRedirectRequest) Limits() -> HttpClientLimits {
  if self.cell == nil {
    return HttpClientLimits{};
  }

  return (self.cell as arc<RedirectRequestData>).limits;
}

/**
 * @brief Copied original absolute deadline/shared token; modifying the copy never resets this
 *   snapshot.
 * @returns The NetOperationOptions value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpRedirectRequest) Options() -> NetOperationOptions {
  if self.cell == nil {
    return NetOperationOptions{};
  }

  return (self.cell as arc<RedirectRequestData>).options;
}

/**
 * @brief Open an http snapshot using its original controls; reject https and streamed snapshots
 *   without network I/O.
 * @returns Ok with HttpTcpClient on success; Err with HttpClientError on the failure paths
 *   described above.
 */
pub method(HttpRedirectRequest) OpenTcp(
  resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions
) -> Result<HttpTcpClient, HttpClientError> {
  if self.cell == nil {
    return HttpClientError.FromRedirectKind(HttpErrorKind.InvalidArgument);
  }

  let s: arc<RedirectRequestData> = self.cell as arc<RedirectRequestData>;
  if s.streaming {
    return HttpClientError.FromRedirectKind(HttpErrorKind.InvalidState);
  }

  return HttpTcpClient.Open(s.url, s.verb, s.fields, s.body, s.limits, resolver, dial, s.options);
}

/**
 * @brief Whether this snapshot requires a producer; Body is empty even for a nonempty stream.
 * @returns Whether this snapshot requires a producer; Body is empty even for a nonempty stream.
 */
pub method(HttpRedirectRequest) IsStreaming() -> bool {
  return self.cell != nil && (self.cell as arc<RedirectRequestData>).streaming;
}

/**
 * @brief Streamed producer plan, or an empty plan for immutable/default snapshots.
 * @returns The HttpBodyPlan value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpRedirectRequest) UploadPlan() -> HttpBodyPlan {
  if self.cell == nil {
    return HttpBodyPlan{};
  }

  return (self.cell as arc<RedirectRequestData>).plan;
}

/**
 * @brief Open only a streamed http snapshot with its retained original controls.
 * @returns Ok with HttpTcpClient on success; Err with HttpClientError on the failure paths
 *   described above.
 * @note Caller prepares a fresh producer before every preserved-body replay. No implicit rewind.
 */
pub method(HttpRedirectRequest) OpenStreamingTcp(
  resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions,
  continue_wait_ms: int32
) -> Result<HttpTcpClient, HttpClientError> {
  if !self.IsStreaming() {
    return HttpClientError.FromRedirectKind(HttpErrorKind.InvalidState);
  }

  let s: arc<RedirectRequestData> = self.cell as arc<RedirectRequestData>;

  return HttpTcpClient.OpenStreaming(
    s.url,
    s.verb,
    s.fields,
    s.plan,
    s.limits,
    resolver,
    dial,
    s.options,
    continue_wait_ms
  );
}
