/** @brief Bounded request upload and response pull events shared across transports. */
part of HttpClientCore;
struct HttpExchangeData {
  request: HttpHead; head_wire: NetBuffer; body: NetBuffer; head_length: intptr; body_length: intptr;
  head_cursor: intptr; body_cursor: intptr; writer: HttpBodyWriter; response: HttpResponseParser; decoder: HttpBodyDecoder;
  limits: HttpClientLimits; pending: NetBuffer; pending_cursor: intptr; input: NetBuffer; input_cursor: intptr;
  eof: bool; finish_queued: bool; has_head: bool; complete: bool; failure: HttpError?; stats: HttpClientStats;
  streaming: bool; await_continue: bool; stopped: bool; partial_head: bool; supplied: uint64;
  scratch: <uint8>[16384];
}
pub struct HttpClientExchange { cell: arc<HttpExchangeData>?; }
func http_client_error(kind: HttpErrorKind) -> HttpError { return HttpError{kind: kind}; }
func http_exchange_fail(state: arc<HttpExchangeData>, error: HttpError) -> HttpError { var cell: arc<HttpExchangeData> = state; cell.failure = error; return error; }
func http_client_equal(a: ref string, b: ref string) -> bool {
  if a.length != b.length { return false; } var i: int32 = 0;
  while i < a.length { var x: int32 = (a[i] as uint8) as int32; var y: int32 = (b[i] as uint8) as int32; if x >= 65 && x <= 90 { x = x+32; } if y >= 65 && y <= 90 { y = y+32; } if x != y { return false; } i = i+1; } return true;
}
// Validate shared head/framing limits before either upload mode is admitted.
func http_exchange_new(head: ref NetBuffer, body: ref NetBuffer, limits: ref HttpClientLimits, streaming: bool) -> Result<HttpClientExchange, HttpError> {
  var caps: HttpClientLimits = limits;
  if caps.max_retained_request_bytes == 0 { caps.max_retained_request_bytes = 16777216; }
  if caps.max_retained_request_bytes < 1 || caps.max_retained_request_bytes > 1073741824 { return http_client_error(HttpErrorKind.InvalidArgument); }
  let budget: intptr = caps.max_retained_request_bytes as intptr;
  if head.RetainedBytes() > budget || body.RetainedBytes() > budget-head.RetainedBytes() { return http_client_error(HttpErrorKind.LimitExceeded); }
  var parsed: Result<HttpHeadParser, HttpError> = HttpHeadParser.NewRequest(caps.request_head);
  if parsed.IsErr() { return (parsed.get_if<HttpError>()) as HttpError; }
  var parser: HttpHeadParser = move((parsed.get_if<HttpHeadParser>()) as HttpHeadParser);
  let fed: Result<intptr, HttpError> = parser.Push(head.Bytes());
  if fed.IsErr() { return (fed.get_if<HttpError>()) as HttpError; }
  if !parser.IsComplete() { return http_client_error(HttpErrorKind.UnexpectedEof); }
  if ((fed.get_if<intptr>()) as intptr) != head.Len() { return http_client_error(HttpErrorKind.InvalidFraming); }
  let request: HttpHead = (parser.Head().get_if<HttpHead>()) as HttpHead;
  if request.MinorVersion() != 1 || request.Method().Equal("CONNECT") { return http_client_error(HttpErrorKind.Unsupported); }
  var expect: bool = false; var i: int32 = 0;
  while i < request.FieldCount() {
    let field: HttpField = (request.FieldAt(i).get_if<HttpField>()) as HttpField;
    if http_client_equal(field.name, "Upgrade") { return http_client_error(HttpErrorKind.Unsupported); }
    if http_client_equal(field.name, "Expect") {
      if !streaming || expect || !http_client_equal(field.value, "100-continue") { return http_client_error(HttpErrorKind.Unsupported); }
      expect = true;
    } i = i+1;
  }
  let plan: HttpBodyPlan = (request.BodyPlan().get_if<HttpBodyPlan>()) as HttpBodyPlan;
  if expect && (plan.kind == HttpBodyKind.None || (plan.kind == HttpBodyKind.ContentLength && plan.length == 0u64)) { return http_client_error(HttpErrorKind.InvalidFraming); }
  if !streaming && ((plan.kind == HttpBodyKind.None && body.Len() != (0 as intptr)) || (plan.kind == HttpBodyKind.ContentLength && plan.length != body.Len() as uint64)) { return http_client_error(HttpErrorKind.InvalidFraming); }
  var max_body: uint64 = caps.body.max_body_bytes; if max_body == 0u64 { max_body = 16777216u64; }
  if (body.Len() as uint64) > max_body { return http_client_error(HttpErrorKind.LimitExceeded); }
  var writer: Result<HttpBodyWriter, HttpError> = HttpBodyWriter.New(request, caps.body);
  if writer.IsErr() { return (writer.get_if<HttpError>()) as HttpError; }
  var response: Result<HttpResponseParser, HttpError> = HttpResponseParser.New(request.Method(), caps.response);
  if response.IsErr() { return (response.get_if<HttpError>()) as HttpError; }
  return HttpClientExchange{cell: new arc<HttpExchangeData>{request: request, head_wire: head, body: body,
    head_length: head.Len(), body_length: body.Len(), limits: caps, streaming: streaming, await_continue: expect,
    finish_queued: streaming && (plan.kind == HttpBodyKind.None || (plan.kind == HttpBodyKind.ContentLength && plan.length == 0u64)),
    writer: move((writer.get_if<HttpBodyWriter>()) as HttpBodyWriter), response: move((response.get_if<HttpResponseParser>()) as HttpResponseParser)}};
}
/** @brief Validate an immutable single-request exchange. */
pub static method(HttpClientExchange) New(head: ref NetBuffer, body: ref NetBuffer, limits: ref HttpClientLimits) -> Result<HttpClientExchange, HttpError> { return http_exchange_new(head, body, limits, false); }
/** @brief Validate a request head and create an empty bounded producer slot. */
pub static method(HttpClientExchange) NewStreaming(head: ref NetBuffer, limits: ref HttpClientLimits) -> Result<HttpClientExchange, HttpError> { return http_exchange_new(head, NetBuffer{}, limits, true); }
func http_exchange_head_sent(s: arc<HttpExchangeData>) -> bool { return s.stats.request_bytes_sent >= s.head_length as uint64; }
func http_exchange_reading(s: arc<HttpExchangeData>) -> bool { return s.input_cursor < s.input.Len() || s.partial_head || s.eof; }
/** @brief Transfer the sole incremental exchange owner. */
pub method(HttpClientExchange) operator move() -> HttpClientExchange { let cell: arc<HttpExchangeData>? = self.cell; self.cell = nil; return HttpClientExchange{cell: cell}; }
/** @brief Release retained request and cursor storage. */
pub method(HttpClientExchange) operator drop() -> void { self.cell = nil; }
/** @brief Produce stable output until transport acknowledgement advances it. */
pub method(HttpClientExchange) Output() -> Result<NetBuffer, HttpError> {
  if self.cell == nil { return http_client_error(HttpErrorKind.Closed); }
  var s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.failure != nil { return s.failure as HttpError; }
  if s.streaming && (s.stopped || http_exchange_reading(s) || (s.await_continue && http_exchange_head_sent(s))) { return NetBuffer{}; }
  if s.pending_cursor < s.pending.Len() { return (s.pending.Slice(s.pending_cursor, s.pending.Len()-s.pending_cursor).get_if<NetBuffer>()) as NetBuffer; }
  s.pending = NetBuffer{}; s.pending_cursor = 0 as intptr;
  if s.head_cursor < s.head_length {
    var size: intptr = s.head_length-s.head_cursor; if size > (16384 as intptr) { size = 16384 as intptr; }
    let bytes: NetBytes = (s.head_wire.Bytes().Slice(s.head_cursor, size).get_if<NetBytes>()) as NetBytes;
    let copied: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(bytes);
    if copied.IsErr() { return http_exchange_fail(s, http_client_error(HttpErrorKind.ResourceExhausted)); }
    s.pending = (copied.get_if<NetBuffer>()) as NetBuffer; s.head_cursor = s.head_cursor+size;
    if s.head_cursor == s.head_length { s.head_wire = NetBuffer{}; }
    return s.pending;
  }
  if !s.streaming && s.body_cursor == s.body_length && !s.finish_queued {
    let finish: Result<bool, HttpError> = s.writer.Finish(new <HttpField>[0]);
    if finish.IsErr() { return http_exchange_fail(s, (finish.get_if<HttpError>()) as HttpError); }
    s.finish_queued = true; s.body = NetBuffer{};
  }
  if s.writer.IsComplete() { return NetBuffer{}; }
  var bytes: NetBytes = NetBytes{};
  if s.body_cursor < s.body_length { bytes = (s.body.Bytes().Slice(s.body_cursor, s.body_length-s.body_cursor).get_if<NetBytes>()) as NetBytes; }
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut s.scratch[0], 16384 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  let fed: Result<HttpBodyProgress, HttpError> = s.writer.Push(bytes, output);
  if fed.IsErr() { return http_exchange_fail(s, (fed.get_if<HttpError>()) as HttpError); }
  let progress: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
  s.body_cursor = s.body_cursor+progress.consumed;
  if s.streaming && progress.produced == (0 as intptr) && progress.state == HttpBodyState.NeedInput { return NetBuffer{}; }
  if progress.produced == (0 as intptr) { return http_exchange_fail(s, http_client_error(HttpErrorKind.InvalidState)); }
  let range: NetBytes = (output.AsReadOnly().Slice(0 as intptr, progress.produced).get_if<NetBytes>()) as NetBytes;
  let copied: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(range);
  if copied.IsErr() { return http_exchange_fail(s, http_client_error(HttpErrorKind.ResourceExhausted)); }
  s.pending = (copied.get_if<NetBuffer>()) as NetBuffer;
  if s.body_cursor == s.body_length { s.body = NetBuffer{}; }
  return s.pending;
}
/** @brief Record committed acceptance without mutating invalid acknowledgements. */
pub method(HttpClientExchange) AcknowledgeOutput(count: intptr) -> Result<Unit, HttpError> {
  if self.cell == nil { return http_client_error(HttpErrorKind.Closed); }
  var s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.failure != nil { return s.failure as HttpError; }
  if s.stopped { return http_client_error(HttpErrorKind.InvalidState); }
  if count < (0 as intptr) || count > s.pending.Len()-s.pending_cursor { return http_client_error(HttpErrorKind.InvalidArgument); }
  s.pending_cursor = s.pending_cursor+count; s.stats.request_bytes_sent = s.stats.request_bytes_sent+(count as uint64); return Unit{};
}
/** @brief The upload includes acknowledgement of the final wire block. */
pub method(HttpClientExchange) RequestComplete() -> bool {
  if self.cell == nil { return false; } let s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  return s.failure == nil && !s.stopped && (!s.streaming || s.finish_queued) && s.head_cursor == s.head_length && s.body_cursor == s.body_length && s.writer.IsComplete() && s.pending_cursor == s.pending.Len();
}
/** @brief Admit one bounded immutable input owner, preserving pending input on failure. */
pub method(HttpClientExchange) Receive(buffer: ref NetBuffer, eof: bool) -> Result<Unit, HttpError> {
  if self.cell == nil { return http_client_error(HttpErrorKind.Closed); }
  var s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.failure != nil { return s.failure as HttpError; }
  if ((!s.streaming && !self.RequestComplete()) || (s.streaming && !http_exchange_head_sent(s))) || s.complete || s.eof || s.input_cursor < s.input.Len() { return http_client_error(HttpErrorKind.InvalidState); }
  if buffer.Len() > (16384 as intptr) || buffer.RetainedBytes() > (16384 as intptr) { return http_client_error(HttpErrorKind.LimitExceeded); }
  // Bound aggregate counters even for a hostile transport driving invalid wire indefinitely.
  if (buffer.Len() as uint64) > 18446744073709551615u64-s.stats.response_bytes_received { return http_client_error(HttpErrorKind.LimitExceeded); }
  s.input = buffer; s.input_cursor = 0 as intptr; s.eof = eof;
  s.stats.response_bytes_received = s.stats.response_bytes_received+(buffer.Len() as uint64); return Unit{};
}
func http_exchange_event(s: arc<HttpExchangeData>, kind: HttpClientEventKind, head: HttpHead, buffer: NetBuffer) -> HttpClientEvent { return HttpClientEvent{kind: kind, head: head, buffer: buffer, complete: s.complete, stats: s.stats}; }
/** @brief Pull exactly one event, retaining unread wire for the next call. */
pub method(HttpClientExchange) NextResponse() -> Result<HttpClientEvent, HttpError> {
  if self.cell == nil { return http_client_error(HttpErrorKind.Closed); }
  var s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.failure != nil { return s.failure as HttpError; }
  if (!s.streaming && !self.RequestComplete()) || (s.streaming && !http_exchange_head_sent(s)) { return http_client_error(HttpErrorKind.InvalidState); }
  if s.complete { return http_exchange_event(s, HttpClientEventKind.Complete, HttpHead{}, NetBuffer{}); }
  while s.input_cursor < s.input.Len() {
    let input: NetBytes = (s.input.Bytes().Slice(s.input_cursor, s.input.Len()-s.input_cursor).get_if<NetBytes>()) as NetBytes;
    if !s.has_head {
      if s.streaming { s.partial_head = true; }
      let fed: Result<HttpResponseProgress, HttpError> = s.response.Push(input);
      if fed.IsErr() { return http_exchange_fail(s, (fed.get_if<HttpError>()) as HttpError); }
      let progress: HttpResponseProgress = (fed.get_if<HttpResponseProgress>()) as HttpResponseProgress;
      s.input_cursor = s.input_cursor+progress.consumed;
      if s.streaming { s.partial_head = progress.state == HttpResponseState.NeedInput; }
      if progress.state != HttpResponseState.NeedInput {
        let head: HttpHead = (s.response.Head().get_if<HttpHead>()) as HttpHead;
        if progress.state == HttpResponseState.Informational { if head.Status() == 100 { s.await_continue = false; } return http_exchange_event(s, HttpClientEventKind.Informational, head, NetBuffer{}); }
        if s.streaming && !self.RequestComplete() {
          s.stopped = true; s.await_continue = false; s.body = NetBuffer{}; s.pending = NetBuffer{}; s.pending_cursor = 0 as intptr;
          s.writer = HttpBodyWriter{}; s.body_cursor = 0 as intptr; s.body_length = 0 as intptr;
        }
        var made: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(head, s.limits.body);
        if made.IsErr() { return http_exchange_fail(s, (made.get_if<HttpError>()) as HttpError); }
        s.decoder = move((made.get_if<HttpBodyDecoder>()) as HttpBodyDecoder); s.has_head = true; s.complete = s.decoder.IsComplete();
        return http_exchange_event(s, HttpClientEventKind.Head, head, NetBuffer{});
      }
    } else {
      let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut s.scratch[0], 16384 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
      let fed: Result<HttpBodyProgress, HttpError> = s.decoder.Push(input, output);
      if fed.IsErr() { return http_exchange_fail(s, (fed.get_if<HttpError>()) as HttpError); }
      let progress: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
      s.input_cursor = s.input_cursor+progress.consumed; s.complete = s.decoder.IsComplete();
      if progress.produced > (0 as intptr) {
        let bytes: NetBytes = (output.AsReadOnly().Slice(0 as intptr, progress.produced).get_if<NetBytes>()) as NetBytes;
        let copied: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(bytes);
        if copied.IsErr() { return http_exchange_fail(s, http_client_error(HttpErrorKind.ResourceExhausted)); }
        return http_exchange_event(s, HttpClientEventKind.Body, HttpHead{}, (copied.get_if<NetBuffer>()) as NetBuffer);
      }
      if s.complete { return http_exchange_event(s, HttpClientEventKind.Complete, HttpHead{}, NetBuffer{}); }
    }
  }
  s.input = NetBuffer{}; s.input_cursor = 0 as intptr;
  if s.eof {
    if !s.has_head {
      let end: Result<HttpHead, HttpError> = s.response.EndInput();
      if end.IsErr() { return http_exchange_fail(s, (end.get_if<HttpError>()) as HttpError); }
    } else {
      let end: Result<bool, HttpError> = s.decoder.EndInput();
      if end.IsErr() { return http_exchange_fail(s, (end.get_if<HttpError>()) as HttpError); }
    }
    s.complete = true; return http_exchange_event(s, HttpClientEventKind.Complete, HttpHead{}, NetBuffer{});
  }
  return http_exchange_event(s, HttpClientEventKind.NeedInput, HttpHead{}, NetBuffer{});
}
/** @brief Return the validated originating request metadata. */
pub method(HttpClientExchange) RequestHead() -> Result<HttpHead, HttpError> { if self.cell == nil { return http_client_error(HttpErrorKind.Closed); } return (self.cell as arc<HttpExchangeData>).request; }
/** @brief Copy the Host identity without bracket or port syntax. */
pub method(HttpClientExchange) AuthorityHost() -> Result<string, HttpError> {
  let request: Result<HttpHead, HttpError> = self.RequestHead(); if request.IsErr() { return (request.get_if<HttpError>()) as HttpError; }
  let head: HttpHead = (request.get_if<HttpHead>()) as HttpHead; var i: int32 = 0;
  while i < head.FieldCount() {
    let field: HttpField = (head.FieldAt(i).get_if<HttpField>()) as HttpField;
    if http_client_equal(field.name, "Host") {
      if field.value[0] == '[' { let end: int32 = field.value.Find("]"); return field.value.Substring(1, end-1); }
      let colon: int32 = field.value.Find(":"); if colon >= 0 { return field.value.Substring(0, colon); } return field.value;
    } i = i+1;
  }
  return http_client_error(HttpErrorKind.InvalidState);
}
/** @brief Identify which protocol cursor owns an error offset. */
pub method(HttpClientExchange) Stage() -> HttpClientStage {
  if self.cell == nil { return HttpClientStage.Request; } let s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.has_head { return HttpClientStage.ResponseBody; }
  if s.streaming && http_exchange_head_sent(s) && http_exchange_reading(s) { return HttpClientStage.ResponseHead; }
  if s.head_cursor == s.head_length && s.body_cursor == s.body_length && s.writer.IsComplete() && s.pending_cursor == s.pending.Len() { return HttpClientStage.ResponseHead; }
  return HttpClientStage.Request;
}
/** @brief Preserve actual accepted HTTP wire counts. */
pub method(HttpClientExchange) Stats() -> HttpClientStats { if self.cell == nil { return HttpClientStats{}; } return (self.cell as arc<HttpExchangeData>).stats; }
/** @brief Completion excludes terminal protocol failure. */
pub method(HttpClientExchange) IsComplete() -> bool { if self.cell == nil { return false; } let s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>; return s.complete && s.failure == nil; }
/** @brief Publish separate trailers after complete response framing. */
pub method(HttpClientExchange) TrailerCount() -> Result<int32, HttpError> { if self.cell == nil { return http_client_error(HttpErrorKind.Closed); } let s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>; if s.failure != nil { return s.failure as HttpError; } if !s.complete { return http_client_error(HttpErrorKind.InvalidState); } return s.decoder.TrailerCount(); }
/** @brief Retain trailer strings independently of exchange lifetime. */
pub method(HttpClientExchange) TrailerAt(index: int32) -> Result<HttpField, HttpError> { if self.cell == nil { return http_client_error(HttpErrorKind.Closed); } let s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>; if s.failure != nil { return s.failure as HttpError; } if !s.complete { return http_client_error(HttpErrorKind.InvalidState); } return s.decoder.TrailerAt(index); }
