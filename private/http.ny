// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

module HttpHeadCodec;
part "scan.ny";
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/client.ni";
import "interface/url.ni";
import "interface/redirect.ni";
import "private/grammar.ny";

/** @brief Strict byte-oriented HTTP head parsing without socket or TLS ownership. */

struct HttpHeadData {
  response: bool;
  minor: int32;
  verb: string;
  target: string;
  status: int32;
  reason: string;
  fields: <HttpField>[128];
  field_count: int32;
  plan: HttpBodyPlan;
}

struct HttpParserData {
  head: arc<HttpHeadData>;
  limits: HttpHeadLimits;
  request_method: string;
  line: owned <uint8>[];
  used: int32;
  total: int64;
  cr: bool;
  started: bool;
  complete: bool;
  failure: HttpError?;
  has_length: bool;
  length: uint64;
  transfer: string;
  has_transfer: bool;
  hosts: int32;
  close: bool;
  keep_alive: bool;
}

/** @brief Immutable, copyable head owning every returned string through shared storage. */
pub struct HttpHead {
  cell: arc<HttpHeadData>?;
}

/** @brief Move-only, single-caller incremental head parser; input is borrowed only during Push. */
pub struct HttpHeadParser {
  cell: arc<HttpParserData>?;
}

method(HttpParserData) Fail(kind: HttpErrorKind) -> HttpError {
  let error: HttpError = HttpError{kind: kind, offset: self.total};
  self.failure = error;

  return error;
}

/**
 * @brief Construct an incremental head parser for the selected request/response mode.
 * @returns A parser with validated limits, or InvalidArgument before allocating parser state.
 */
pub static method(HttpHeadParser) NewParser(
  response: bool,
  request_method: ref string,
  limits: ref HttpHeadLimits
) -> Result<HttpHeadParser, HttpError> {
  var caps: HttpHeadLimits = limits;
  if caps.max_head_bytes == 0 {
    caps.max_head_bytes = 32768;
  }

  if caps.max_line_bytes == 0 {
    caps.max_line_bytes = 8192;
  }

  if caps.max_fields == 0 {
    caps.max_fields = 100;
  }

  if caps.max_head_bytes < 4
    || caps.max_head_bytes > 1048576
    || caps.max_line_bytes < 1
    || caps.max_line_bytes > 65536
    || caps.max_fields < 1
    || caps.max_fields > 128 {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  if response && !HttpLexeme.New(request_method).IsToken() {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  let head: arc<HttpHeadData> = new arc<HttpHeadData>{response: response, minor: -1};
  let state: arc<HttpParserData> = new arc<HttpParserData>{
    head: head,
    limits: caps,
    request_method: request_method.Substring(0, request_method.length),
    line: new <uint8>[caps.max_line_bytes]
  };

  return HttpHeadParser{cell: state};
}

/**
 * @brief Construct a strict origin-form/OPTIONS-* request parser; caps: 1 MiB/64 KiB/128 fields.
 * @returns Ok with HttpHeadParser on success; Err with HttpError on the failure paths described
 *   above.
 */
pub static method(HttpHeadParser) NewRequest(limits: ref HttpHeadLimits) -> Result<HttpHeadParser, HttpError> {
  return HttpHeadParser.NewParser(false, "", limits);
}

/**
 * @brief Construct a response parser with case-sensitive originating method (HEAD/CONNECT
 *   semantics).
 * @returns Ok with HttpHeadParser on success; Err with HttpError on the failure paths described
 *   above.
 */
pub static method(HttpHeadParser) NewResponse(
  request_method: ref string,
  limits: ref HttpHeadLimits
) -> Result<HttpHeadParser, HttpError> {
  return HttpHeadParser.NewParser(true, request_method, limits);
}

/**
 * @brief Transfer parser ownership and invalidate the source.
 * @returns The HttpHeadParser value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpHeadParser) operator move() -> HttpHeadParser {
  let cell: arc<HttpParserData>? = self.cell;
  self.cell = nil;

  return HttpHeadParser{cell: cell};
}

/** @brief Release all parser-owned storage. */
pub method(HttpHeadParser) operator drop() -> void {
  self.cell = nil;
}

/**
 * @brief Consume through CRLFCRLF only; success returns the exact consumed input prefix.
 * @returns Ok with intptr on success; Err with HttpError on the failure paths described above.
 * @note Stops before body/pipeline/tunnel bytes. Complete parsers consume zero. Errors are
 *   sticky; discard the connection on error, not just this input span. Limits include head CRLF
 *   bytes.
 */
pub method(HttpHeadParser) Push(bytes: ref NetBytes) -> Result<intptr, HttpError> {
  let optional: arc<HttpParserData>? = self.cell;
  if optional == nil {
    return HttpError{kind: HttpErrorKind.Closed};
  }

  var state: arc<HttpParserData> = optional as arc<HttpParserData>;
  if state.failure != nil {
    return state.failure as HttpError;
  }

  if state.complete {
    return 0ip;
  }

  var i: intptr = 0;
  while i < bytes.Len() {
    var ch: uint8 = 0;
    unsafe {
      ch = bytes.Data()[i as int32];
    }

    state.total = state.total + (1i64);
    if state.total > state.limits.max_head_bytes as int64 {
      return (state).Fail(HttpErrorKind.LimitExceeded);
    }

    i = i + (1ip);
    if state.cr {
      state.cr = false;
      if ch != 10u8 {
        return (state).Fail(HttpErrorKind.Malformed);
      }

      let line: string = string.ViewFrom(&state.line[0] as *const int8, state.used);
      let failure: HttpErrorKind? = (state).ParseLine(line);
      if failure != nil {
        return (state).Fail(failure as HttpErrorKind);
      }

      state.used = 0;
      if state.complete {
        return i;
      }
    } else if ch == 13u8 {
      state.cr = true;
    } else {
      if ch == 10u8 {
        return (state).Fail(HttpErrorKind.Malformed);
      }

      if state.used >= state.limits.max_line_bytes {
        return (state).Fail(HttpErrorKind.LimitExceeded);
      }

      state.line[state.used] = ch;
      state.used = state.used + 1;
    }
  }

  return i;
}

/**
 * @brief Whether a complete, validated head is available.
 * @returns Whether a complete, validated head is available.
 */
pub method(HttpHeadParser) IsComplete() -> bool {
  let optional: arc<HttpParserData>? = self.cell;
  if optional == nil {
    return false;
  }

  let state: arc<HttpParserData> = optional as arc<HttpParserData>;

  return state.complete;
}

/**
 * @brief Owned immutable head, pending InvalidState, or the sticky terminal error.
 * @returns Ok with HttpHead on success; Err with HttpError on the failure paths described above.
 */
pub method(HttpHeadParser) Head() -> Result<HttpHead, HttpError> {
  let optional: arc<HttpParserData>? = self.cell;
  if optional == nil {
    return HttpError{kind: HttpErrorKind.Closed};
  }

  let state: arc<HttpParserData> = optional as arc<HttpParserData>;
  if state.failure != nil {
    return state.failure as HttpError;
  }

  if !state.complete {
    return HttpError{kind: HttpErrorKind.InvalidState};
  }

  return HttpHead{cell: state.head};
}

/**
 * @brief Return a complete head or mark incomplete transport EOF as terminal UnexpectedEof.
 * @returns Ok with HttpHead on success; Err with HttpError on the failure paths described above.
 */
pub method(HttpHeadParser) EndInput() -> Result<HttpHead, HttpError> {
  let optional: arc<HttpParserData>? = self.cell;
  if optional == nil {
    return HttpError{kind: HttpErrorKind.Closed};
  }

  let state: arc<HttpParserData> = optional as arc<HttpParserData>;
  if state.failure != nil {
    return state.failure as HttpError;
  }

  if !state.complete {
    return (state).Fail(HttpErrorKind.UnexpectedEof);
  }

  return HttpHead{cell: state.head};
}

/**
 * @brief Whether this is a response; a default head is invalid.
 * @returns Whether this is a response; a default head is invalid.
 */
pub method(HttpHead) IsResponse() -> bool {
  if self.cell == nil {
    return false;
  }

  return (self.cell as arc<HttpHeadData>).response;
}

/**
 * @brief HTTP minor version (0/1), or -1 for a default head.
 * @returns HTTP minor version (0/1), or -1 for a default head.
 */
pub method(HttpHead) MinorVersion() -> int32 {
  if self.cell == nil {
    return -1;
  }

  return (self.cell as arc<HttpHeadData>).minor;
}

/**
 * @brief Request method, or empty for a response/default head; owned result.
 * @returns Request method, or empty for a response/default head; owned result.
 */
pub method(HttpHead) Method() -> string {
  if self.cell == nil {
    return "";
  }

  return (self.cell as arc<HttpHeadData>).verb;
}

/**
 * @brief Request target, or empty for a response/default head; owned result.
 * @returns Request target, or empty for a response/default head; owned result.
 */
pub method(HttpHead) Target() -> string {
  if self.cell == nil {
    return "";
  }

  return (self.cell as arc<HttpHeadData>).target;
}

/**
 * @brief Response status (100..599), or zero for a request/default head.
 * @returns Response status (100..599), or zero for a request/default head.
 */
pub method(HttpHead) Status() -> int32 {
  if self.cell == nil {
    return 0;
  }

  return (self.cell as arc<HttpHeadData>).status;
}

/**
 * @brief Response reason bytes, possibly empty; owned result.
 * @returns Response reason bytes, possibly empty; owned result.
 */
pub method(HttpHead) Reason() -> string {
  if self.cell == nil {
    return "";
  }

  return (self.cell as arc<HttpHeadData>).reason;
}

/**
 * @brief Number of ordered header fields; zero for a default head.
 * @returns Number of ordered header fields; zero for a default head.
 */
pub method(HttpHead) FieldCount() -> int32 {
  if self.cell == nil {
    return 0;
  }

  return (self.cell as arc<HttpHeadData>).field_count;
}

/**
 * @brief Return an owned field or InvalidArgument for an out-of-range index.
 * @returns Ok with HttpField on success; Err with HttpError on the failure paths described
 *   above.
 */
pub method(HttpHead) FieldAt(index: int32) -> Result<HttpField, HttpError> {
  if self.cell == nil {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  let state: arc<HttpHeadData> = self.cell as arc<HttpHeadData>;
  if index < 0 || index >= state.field_count {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  return state.fields[index];
}

/**
 * @brief Validated body framing, or InvalidState for a default head.
 * @returns Ok with HttpBodyPlan on success; Err with HttpError on the failure paths described
 *   above.
 */
pub method(HttpHead) BodyPlan() -> Result<HttpBodyPlan, HttpError> {
  if self.cell == nil {
    return HttpError{kind: HttpErrorKind.InvalidState};
  }

  return (self.cell as arc<HttpHeadData>).plan;
}
