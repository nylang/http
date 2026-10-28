/** @brief Bounded incremental HTTP/1.x payload and chunk framing. */
part of HttpProtocol;
enum HttpBodyPhase { Fixed, Eof, Size, Data, DataCr, DataLf, Trailers, Done }
struct HttpBodyData {
  head: HttpHead; limits: HttpBodyLimits; phase: HttpBodyPhase; remaining: uint64;
  decoded: uint64; total: int64; framing: int32; line: owned <uint8>[]; used: int32; cr: bool;
  trailers: <HttpField>[128]; trailer_count: int32; failure: HttpError?;
}
pub struct HttpBodyDecoder { cell: arc<HttpBodyData>?; }
func http_body_fail(state: arc<HttpBodyData>, kind: HttpErrorKind) -> HttpError {
  var cell: arc<HttpBodyData> = state;
  let error: HttpError = HttpError{kind: kind, offset: cell.total}; cell.failure = error; return error;
}
func http_body_limits(limits: ref HttpBodyLimits) -> Result<HttpBodyLimits, HttpError> {
  var caps: HttpBodyLimits = limits;
  if caps.max_body_bytes == 0u64 { caps.max_body_bytes = 16777216u64; }
  if caps.max_framing_bytes == 0 { caps.max_framing_bytes = 1048576; }
  if caps.max_line_bytes == 0 { caps.max_line_bytes = 8192; }
  if caps.max_trailers == 0 { caps.max_trailers = 100; }
  if caps.max_body_bytes > 9223372036837998591u64 || caps.max_framing_bytes < 1 || caps.max_framing_bytes > 16777216 || caps.max_line_bytes < 1 || caps.max_line_bytes > 65536 || caps.max_trailers < 1 || caps.max_trailers > 128 {
    return http_error(HttpErrorKind.InvalidArgument);
  }
  return caps;
}
/** @brief Validate limits and retain only bounded framing state. */
pub static method(HttpBodyDecoder) New(head: ref HttpHead, limits: ref HttpBodyLimits) -> Result<HttpBodyDecoder, HttpError> {
  let planned: Result<HttpBodyPlan, HttpError> = head.BodyPlan();
  if planned.IsErr() { return (planned.get_if<HttpError>()) as HttpError; }
  let plan: HttpBodyPlan = (planned.get_if<HttpBodyPlan>()) as HttpBodyPlan;
  let checked: Result<HttpBodyLimits, HttpError> = http_body_limits(limits);
  if checked.IsErr() { return (checked.get_if<HttpError>()) as HttpError; }
  let caps: HttpBodyLimits = (checked.get_if<HttpBodyLimits>()) as HttpBodyLimits;
  var phase: HttpBodyPhase = HttpBodyPhase.Done;
  if plan.kind == HttpBodyKind.Upgrade || plan.kind == HttpBodyKind.Tunnel { return http_error(HttpErrorKind.Unsupported); }
  if plan.kind == HttpBodyKind.ContentLength {
    if plan.length > caps.max_body_bytes { return http_error(HttpErrorKind.LimitExceeded); }
    if plan.length != 0u64 { phase = HttpBodyPhase.Fixed; }
  } else if plan.kind == HttpBodyKind.Chunked { phase = HttpBodyPhase.Size; }
  else if plan.kind == HttpBodyKind.UntilEof { phase = HttpBodyPhase.Eof; }
  let state: arc<HttpBodyData> = new arc<HttpBodyData>{head: head, limits: caps, phase: phase,
    remaining: plan.length, line: new <uint8>[caps.max_line_bytes]};
  return HttpBodyDecoder{cell: state};
}
/** @brief Transfer ownership of the framing cursor. */
pub method(HttpBodyDecoder) operator move() -> HttpBodyDecoder { let cell: arc<HttpBodyData>? = self.cell; self.cell = nil; return HttpBodyDecoder{cell: cell}; }
/** @brief Drop bounded scratch and retained fields. */
pub method(HttpBodyDecoder) operator drop() -> void { self.cell = nil; }
func http_body_ows(text: ref string, start: int32) -> int32 {
  var i: int32 = start;
  while i < text.length && (http_char(text, i) == 32 || http_char(text, i) == 9) { i = i+1; }
  return i;
}
func http_chunk_size(state: arc<HttpBodyData>, text: ref string) -> HttpErrorKind? {
  var cell: arc<HttpBodyData> = state; var i: int32 = 0; var size: uint64 = 0u64;
  while i < text.length && http_hex(http_char(text, i)) {
    let ch: int32 = http_char(text, i); var digit: uint64 = (ch-48) as uint64;
    if ch >= 97 { digit = (ch-87) as uint64; } else if ch >= 65 { digit = (ch-55) as uint64; }
    if size > (18446744073709551615u64-digit)/16u64 { return HttpErrorKind.InvalidFraming; }
    size = size*16u64+digit; i = i+1;
  }
  if i == 0 { return HttpErrorKind.Malformed; }
  // RFC 9112 chunk-ext: BWS ';' BWS token [BWS '=' BWS (token / quoted-string)].
  while i < text.length {
    i = http_body_ows(text, i);
    if i >= text.length || http_char(text, i) != 59 { return HttpErrorKind.Malformed; }
    i = http_body_ows(text, i+1); let start: int32 = i;
    while i < text.length && http_tchar(http_char(text, i)) { i = i+1; }
    if i == start { return HttpErrorKind.Malformed; }
    let end: int32 = i; i = http_body_ows(text, i);
    if i < text.length && http_char(text, i) == 61 {
      i = http_body_ows(text, i+1);
      if i >= text.length { return HttpErrorKind.Malformed; }
      if http_char(text, i) == 34 {
        i = i+1; var closed: bool = false;
        while i < text.length {
          let ch: int32 = http_char(text, i); i = i+1;
          if ch == 34 { closed = true; break; }
          if ch == 92 {
            if i >= text.length { return HttpErrorKind.Malformed; }
            let escaped: int32 = http_char(text, i); i = i+1;
            if escaped != 9 && (escaped < 32 || escaped == 127) { return HttpErrorKind.Malformed; }
          } else if ch != 9 && (ch < 32 || ch == 127) { return HttpErrorKind.Malformed; }
        }
        if !closed { return HttpErrorKind.Malformed; }
      } else {
        let value_start: int32 = i;
        while i < text.length && http_tchar(http_char(text, i)) { i = i+1; }
        if i == value_start { return HttpErrorKind.Malformed; }
      }
    } else { i = end; }
  }
  if size > cell.limits.max_body_bytes-cell.decoded { return HttpErrorKind.LimitExceeded; }
  cell.remaining = size;
  if size == 0u64 { cell.phase = HttpBodyPhase.Trailers; } else { cell.phase = HttpBodyPhase.Data; }
  return nil;
}
func http_trailer_forbidden(head: ref HttpHead, name: ref string) -> bool {
  if http_equal(name, "Content-Length") || http_equal(name, "Transfer-Encoding") || http_equal(name, "Host") || http_equal(name, "Connection") || http_equal(name, "Trailer") || http_equal(name, "TE") || http_equal(name, "Upgrade") || http_equal(name, "Keep-Alive") || http_equal(name, "Proxy-Connection") || http_equal(name, "Authorization") || http_equal(name, "Proxy-Authorization") || http_equal(name, "WWW-Authenticate") || http_equal(name, "Proxy-Authenticate") || http_equal(name, "Authentication-Info") || http_equal(name, "Proxy-Authentication-Info") || http_equal(name, "Content-Type") || http_equal(name, "Content-Encoding") || http_equal(name, "Content-Range") || http_equal(name, "Content-Language") || http_equal(name, "Content-Location") || http_equal(name, "Content-Disposition") || http_equal(name, "Cache-Control") || http_equal(name, "Location") || http_equal(name, "Set-Cookie") || http_equal(name, "Cookie") || http_equal(name, "Range") || http_equal(name, "Expect") || http_equal(name, "Max-Forwards") { return true; }
  var f: int32 = 0;
  while f < head.FieldCount() {
    let field: HttpField = (head.FieldAt(f).get_if<HttpField>()) as HttpField;
    if http_equal(field.name, "Connection") {
      var i: int32 = 0;
      while i < field.value.length {
        let start: int32 = i;
        while i < field.value.length && http_char(field.value, i) != 44 { i = i+1; }
        let token: string = http_trim(field.value.Substring(start, i-start));
        if http_equal(token, name) { return true; }
        i = i+1;
      }
    }
    f = f+1;
  }
  return false;
}
func http_body_line(state: arc<HttpBodyData>, text: ref string) -> HttpErrorKind? {
  var cell: arc<HttpBodyData> = state;
  if cell.phase == HttpBodyPhase.Size { return http_chunk_size(cell, text); }
  if text.length == 0 { cell.phase = HttpBodyPhase.Done; return nil; }
  var colon: int32 = 0;
  while colon < text.length && http_char(text, colon) != 58 { colon = colon+1; }
  if colon == text.length { return HttpErrorKind.Malformed; }
  let name: string = text.Substring(0, colon); let value: string = http_trim(text.Substring(colon+1, text.length-colon-1));
  if !http_token(name) || !http_value(value) { return HttpErrorKind.Malformed; }
  if http_trailer_forbidden(cell.head, name) { return HttpErrorKind.InvalidFraming; }
  if cell.trailer_count >= cell.limits.max_trailers { return HttpErrorKind.LimitExceeded; }
  cell.trailers[cell.trailer_count] = HttpField{name: name, value: value}; cell.trailer_count = cell.trailer_count+1;
  return nil;
}
/** @brief Advance metadata, or copy one payload span without retaining caller storage. */
pub method(HttpBodyDecoder) Push(bytes: ref NetBytes, output: ref NetMutableBytes) -> Result<HttpBodyProgress, HttpError> {
  if self.cell == nil { return http_error(HttpErrorKind.Closed); }
  var state: arc<HttpBodyData> = self.cell as arc<HttpBodyData>;
  if state.failure != nil { return state.failure as HttpError; }
  if state.phase == HttpBodyPhase.Done { return HttpBodyProgress{state: HttpBodyState.Complete}; }
  var i: intptr = 0 as intptr;
  while i < bytes.Len() {
    if state.phase == HttpBodyPhase.Fixed || state.phase == HttpBodyPhase.Data || state.phase == HttpBodyPhase.Eof {
      let budget: uint64 = state.limits.max_body_bytes-state.decoded;
      if budget == 0u64 { return http_body_fail(state, HttpErrorKind.LimitExceeded); }
      if output.Len() == (0 as intptr) { return HttpBodyProgress{consumed: i, state: HttpBodyState.NeedOutput}; }
      var count: intptr = bytes.Len()-i;
      if count > output.Len() { count = output.Len(); }
      if count > (2147483647 as intptr) { count = 2147483647 as intptr; }
      if (count as uint64) > budget { count = budget as intptr; }
      if state.phase != HttpBodyPhase.Eof && (count as uint64) > state.remaining { count = state.remaining as intptr; }
      let payload: NetBytes = (bytes.Slice(i, count).get_if<NetBytes>()) as NetBytes;
      unsafe { memcpy(output.Data(), payload.Data(), count as uintptr); }
      state.decoded = state.decoded+(count as uint64); state.total = state.total+(count as int64);
      if state.phase != HttpBodyPhase.Eof {
        state.remaining = state.remaining-(count as uint64);
        if state.remaining == 0u64 {
          if state.phase == HttpBodyPhase.Fixed { state.phase = HttpBodyPhase.Done; } else { state.phase = HttpBodyPhase.DataCr; }
        }
      }
      var next: HttpBodyState = HttpBodyState.Progress;
      if state.phase == HttpBodyPhase.Done { next = HttpBodyState.Complete; }
      else if i+count == bytes.Len() { next = HttpBodyState.NeedInput; }
      else if count == output.Len() && state.decoded < state.limits.max_body_bytes && (state.phase == HttpBodyPhase.Fixed || state.phase == HttpBodyPhase.Data || state.phase == HttpBodyPhase.Eof) { next = HttpBodyState.NeedOutput; }
      return HttpBodyProgress{consumed: i+count, produced: count, state: next};
    }
    if state.framing >= state.limits.max_framing_bytes { return http_body_fail(state, HttpErrorKind.LimitExceeded); }
    var ch: uint8 = 0u8; unsafe { ch = bytes.Data()[i as int32]; }
    i = i+(1 as intptr); state.total = state.total+(1 as int64); state.framing = state.framing+1;
    if state.phase == HttpBodyPhase.DataCr {
      if ch != 13u8 { return http_body_fail(state, HttpErrorKind.Malformed); }
      state.phase = HttpBodyPhase.DataLf;
    } else if state.phase == HttpBodyPhase.DataLf {
      if ch != 10u8 { return http_body_fail(state, HttpErrorKind.Malformed); }
      state.phase = HttpBodyPhase.Size;
    } else if state.cr {
      state.cr = false;
      if ch != 10u8 { return http_body_fail(state, HttpErrorKind.Malformed); }
      let line: string = string.ViewFrom(&state.line[0] as *const int8, state.used);
      let failure: HttpErrorKind? = http_body_line(state, line); state.used = 0;
      if failure != nil { return http_body_fail(state, failure as HttpErrorKind); }
      if state.phase == HttpBodyPhase.Done { return HttpBodyProgress{consumed: i, state: HttpBodyState.Complete}; }
    } else if ch == 13u8 { state.cr = true; }
    else {
      if ch == 10u8 { return http_body_fail(state, HttpErrorKind.Malformed); }
      if state.used >= state.limits.max_line_bytes { return http_body_fail(state, HttpErrorKind.LimitExceeded); }
      state.line[state.used] = ch; state.used = state.used+1;
    }
  }
  return HttpBodyProgress{consumed: i, state: HttpBodyState.NeedInput};
}
/** @brief Only close-delimited framing can complete solely from transport EOF. */
pub method(HttpBodyDecoder) EndInput() -> Result<bool, HttpError> {
  if self.cell == nil { return http_error(HttpErrorKind.Closed); }
  var state: arc<HttpBodyData> = self.cell as arc<HttpBodyData>;
  if state.failure != nil { return state.failure as HttpError; }
  if state.phase == HttpBodyPhase.Eof { state.phase = HttpBodyPhase.Done; }
  if state.phase != HttpBodyPhase.Done { return http_body_fail(state, HttpErrorKind.UnexpectedEof); }
  return true;
}
/** @brief Completion excludes sticky protocol errors. */
pub method(HttpBodyDecoder) IsComplete() -> bool { if self.cell == nil { return false; } return (self.cell as arc<HttpBodyData>).phase == HttpBodyPhase.Done; }
/** @brief Expose trailers only after the terminating empty line. */
pub method(HttpBodyDecoder) TrailerCount() -> Result<int32, HttpError> {
  if self.cell == nil { return http_error(HttpErrorKind.Closed); }
  let state: arc<HttpBodyData> = self.cell as arc<HttpBodyData>;
  if state.failure != nil { return state.failure as HttpError; }
  if state.phase != HttpBodyPhase.Done { return http_error(HttpErrorKind.InvalidState); }
  return state.trailer_count;
}
/** @brief Retain trailer strings independently of decoder lifetime. */
pub method(HttpBodyDecoder) TrailerAt(index: int32) -> Result<HttpField, HttpError> {
  let count: Result<int32, HttpError> = self.TrailerCount();
  if count.IsErr() { return (count.get_if<HttpError>()) as HttpError; }
  if index < 0 || index >= ((count.get_if<int32>()) as int32) { return http_error(HttpErrorKind.InvalidArgument); }
  return (self.cell as arc<HttpBodyData>).trailers[index];
}
