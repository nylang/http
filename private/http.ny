/** @brief Strict byte-oriented HTTP head parsing without socket or TLS ownership. */
module HttpProtocol;
part "scan.ny";
part "writer.ny";
part "body.ny";
part "body_writer.ny";
part "response.ny";
part "../tests/head_selftest.ny";
part "../tests/body_selftest.ny";
part "../tests/framing_selftest.ny";
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";

struct HttpHeadData {
  response: bool; minor: int32; verb: string; target: string; status: int32; reason: string;
  fields: <HttpField>[128]; field_count: int32; plan: HttpBodyPlan;
}
struct HttpParserData {
  head: arc<HttpHeadData>; limits: HttpHeadLimits; request_method: string;
  line: owned <uint8>[]; used: int32; total: int64; cr: bool; started: bool; complete: bool;
  failure: HttpError?; has_length: bool; length: uint64; transfer: string; has_transfer: bool;
  hosts: int32; close: bool; keep_alive: bool;
}
pub struct HttpHead { cell: arc<HttpHeadData>?; }
pub struct HttpHeadParser { cell: arc<HttpParserData>?; }
func http_error(kind: HttpErrorKind) -> HttpError { return HttpError{kind: kind}; }
func http_fail(state: arc<HttpParserData>, kind: HttpErrorKind) -> HttpError {
  var cell: arc<HttpParserData> = state;
  let error: HttpError = HttpError{kind: kind, offset: cell.total}; cell.failure = error; return error;
}
func http_new(response: bool, request_method: ref string, limits: ref HttpHeadLimits) -> Result<HttpHeadParser, HttpError> {
  var caps: HttpHeadLimits = limits;
  if caps.max_head_bytes == 0 { caps.max_head_bytes = 32768; }
  if caps.max_line_bytes == 0 { caps.max_line_bytes = 8192; }
  if caps.max_fields == 0 { caps.max_fields = 100; }
  if caps.max_head_bytes < 4 || caps.max_head_bytes > 1048576 || caps.max_line_bytes < 1 || caps.max_line_bytes > 65536 || caps.max_fields < 1 || caps.max_fields > 128 {
    return http_error(HttpErrorKind.InvalidArgument);
  }
  if response && !http_token(request_method) { return http_error(HttpErrorKind.InvalidArgument); }
  let head: arc<HttpHeadData> = new arc<HttpHeadData>{response: response, minor: -1};
  let state: arc<HttpParserData> = new arc<HttpParserData>{head: head, limits: caps,
    request_method: request_method.Substring(0, request_method.length), line: new <uint8>[caps.max_line_bytes]};
  return HttpHeadParser{cell: state};
}
/** @brief Create bounded request state. */
pub static method(HttpHeadParser) NewRequest(limits: ref HttpHeadLimits) -> Result<HttpHeadParser, HttpError> { return http_new(false, "", limits); }
/** @brief Retain request context for response body selection. */
pub static method(HttpHeadParser) NewResponse(request_method: ref string, limits: ref HttpHeadLimits) -> Result<HttpHeadParser, HttpError> { return http_new(true, request_method, limits); }
/** @brief Move the state owner without duplicating an incremental cursor. */
pub method(HttpHeadParser) operator move() -> HttpHeadParser { let cell: arc<HttpParserData>? = self.cell; self.cell = nil; return HttpHeadParser{cell: cell}; }
/** @brief Release all parser-owned storage. */
pub method(HttpHeadParser) operator drop() -> void { self.cell = nil; }
/** @brief Consume a byte prefix, preserving every byte after the head boundary. */
pub method(HttpHeadParser) Push(bytes: ref NetBytes) -> Result<intptr, HttpError> {
  let optional: arc<HttpParserData>? = self.cell;
  if optional == nil { return http_error(HttpErrorKind.Closed); }
  var state: arc<HttpParserData> = optional as arc<HttpParserData>;
  if state.failure != nil { return state.failure as HttpError; }
  if state.complete { return 0 as intptr; }
  var i: intptr = 0 as intptr;
  while i < bytes.Len() {
    var ch: uint8 = 0u8; unsafe { ch = bytes.Data()[i as int32]; }
    state.total = state.total + (1 as int64);
    if state.total > state.limits.max_head_bytes as int64 { return http_fail(state, HttpErrorKind.LimitExceeded); }
    i = i + (1 as intptr);
    if state.cr {
      state.cr = false;
      if ch != 10u8 { return http_fail(state, HttpErrorKind.Malformed); }
      let line: string = string.ViewFrom(&state.line[0] as *const int8, state.used);
      let failure: HttpErrorKind? = http_line(state, line);
      if failure != nil { return http_fail(state, failure as HttpErrorKind); }
      state.used = 0;
      if state.complete { return i; }
    } else if ch == 13u8 { state.cr = true; }
    else {
      if ch == 10u8 { return http_fail(state, HttpErrorKind.Malformed); }
      if state.used >= state.limits.max_line_bytes { return http_fail(state, HttpErrorKind.LimitExceeded); }
      state.line[state.used] = ch; state.used = state.used + 1;
    }
  }
  return i;
}
/** @brief Query completion without exposing partial metadata. */
pub method(HttpHeadParser) IsComplete() -> bool {
  let optional: arc<HttpParserData>? = self.cell; if optional == nil { return false; }
  let state: arc<HttpParserData> = optional as arc<HttpParserData>; return state.complete;
}
/** @brief Retain immutable validated data independently of parser lifetime. */
pub method(HttpHeadParser) Head() -> Result<HttpHead, HttpError> {
  let optional: arc<HttpParserData>? = self.cell; if optional == nil { return http_error(HttpErrorKind.Closed); }
  let state: arc<HttpParserData> = optional as arc<HttpParserData>;
  if state.failure != nil { return state.failure as HttpError; }
  if !state.complete { return http_error(HttpErrorKind.InvalidState); }
  return HttpHead{cell: state.head};
}
/** @brief Make incomplete transport EOF a sticky protocol error. */
pub method(HttpHeadParser) EndInput() -> Result<HttpHead, HttpError> {
  let optional: arc<HttpParserData>? = self.cell; if optional == nil { return http_error(HttpErrorKind.Closed); }
  let state: arc<HttpParserData> = optional as arc<HttpParserData>;
  if state.failure != nil { return state.failure as HttpError; }
  if !state.complete { return http_fail(state, HttpErrorKind.UnexpectedEof); }
  return HttpHead{cell: state.head};
}
/** @brief Read immutable response classification. */
pub method(HttpHead) IsResponse() -> bool { if self.cell == nil { return false; } return (self.cell as arc<HttpHeadData>).response; }
/** @brief Read validated minor version. */
pub method(HttpHead) MinorVersion() -> int32 { if self.cell == nil { return -1; } return (self.cell as arc<HttpHeadData>).minor; }
/** @brief Retain request method text. */
pub method(HttpHead) Method() -> string { if self.cell == nil { return ""; } return (self.cell as arc<HttpHeadData>).verb; }
/** @brief Retain request target text. */
pub method(HttpHead) Target() -> string { if self.cell == nil { return ""; } return (self.cell as arc<HttpHeadData>).target; }
/** @brief Read response status. */
pub method(HttpHead) Status() -> int32 { if self.cell == nil { return 0; } return (self.cell as arc<HttpHeadData>).status; }
/** @brief Retain response reason bytes. */
pub method(HttpHead) Reason() -> string { if self.cell == nil { return ""; } return (self.cell as arc<HttpHeadData>).reason; }
/** @brief Count fields without combining repeated values. */
pub method(HttpHead) FieldCount() -> int32 { if self.cell == nil { return 0; } return (self.cell as arc<HttpHeadData>).field_count; }
/** @brief Return independently retained name/value strings. */
pub method(HttpHead) FieldAt(index: int32) -> Result<HttpField, HttpError> {
  if self.cell == nil { return http_error(HttpErrorKind.InvalidArgument); }
  let state: arc<HttpHeadData> = self.cell as arc<HttpHeadData>;
  if index < 0 || index >= state.field_count { return http_error(HttpErrorKind.InvalidArgument); }
  return state.fields[index];
}
/** @brief Return framing only after validated head publication. */
pub method(HttpHead) BodyPlan() -> Result<HttpBodyPlan, HttpError> {
  if self.cell == nil { return http_error(HttpErrorKind.InvalidState); }
  return (self.cell as arc<HttpHeadData>).plan;
}
