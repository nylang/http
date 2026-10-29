// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

module HttpResponseSequence;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/client.ni";
import "interface/url.ni";
import "interface/redirect.ni";
import "private/grammar.ny";
import "private/http.ny";

/** @brief One-request informational/final response sequencing with bounded cumulative heads. */

struct HttpResponseData {
  parser: HttpHeadParser;
  request_method: string;
  limits: HttpResponseLimits;
  head: HttpHead;
  total: int64;
  head_start: int64;
  informationals: int32;
  next_head: bool;
  complete: bool;
  failure: HttpError?;
}

/**
 * @brief Move-only parser for one request's informational heads and final response, without body
 *   decoding.
 */
pub struct HttpResponseParser {
  cell: arc<HttpResponseData>?;
}

func http_response_fail(state: arc<HttpResponseData>, kind: HttpErrorKind, offset: int64) -> HttpError {
  var cell: arc<HttpResponseData> = state;
  let error: HttpError = HttpError{kind: kind, offset: offset};
  cell.failure = error;

  return error;
}

/**
 * @brief Retain the case-sensitive originating method for every informational/final head.
 * @returns Ok with HttpResponseParser on success; Err with HttpError on the failure paths
 *   described above.
 */
pub static method(HttpResponseParser) New(
  request_method: ref string,
  limits: ref HttpResponseLimits
) -> Result<HttpResponseParser, HttpError> {
  var caps: HttpResponseLimits = limits;
  if caps.max_informational == 0 {
    caps.max_informational = 16;
  }

  if caps.max_total_head_bytes == 0 {
    caps.max_total_head_bytes = 1048576;
  }

  if caps.max_informational < 1
    || caps.max_informational > 64
    || caps.max_total_head_bytes < 1
    || caps.max_total_head_bytes > 16777216 {
    return HttpMakeError(HttpErrorKind.InvalidArgument);
  }

  var made: Result<HttpHeadParser, HttpError> = HttpHeadParser.NewResponse(request_method, caps.head);
  if made.IsErr() {
    return (made.get_if<HttpError>()) as HttpError;
  }

  let state: arc<HttpResponseData> = new arc<HttpResponseData>{
    parser: move((made.get_if<HttpHeadParser>()) as HttpHeadParser),
    request_method: request_method.Substring(0, request_method.length),
    limits: caps
  };

  return HttpResponseParser{cell: state};
}

/**
 * @brief Transfer the originating request context and incremental head cursor.
 * @returns The HttpResponseParser value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpResponseParser) operator move() -> HttpResponseParser {
  let cell: arc<HttpResponseData>? = self.cell;
  self.cell = nil;

  return HttpResponseParser{cell: cell};
}

/** @brief Drop owned head cursors and metadata. */
pub method(HttpResponseParser) operator drop() -> void {
  self.cell = nil;
}

/**
 * @brief Stop at each response head; 100..199 except 101 are informational, 101 is a terminal
 *   handoff.
 * @returns Ok with HttpResponseProgress on success; Err with HttpError on the failure paths
 *   described above.
 * @note After Informational, retain Head() before feeding the next nonempty input. Final
 *   consumes no body/pipeline/tunnel bytes, and later Push calls consume zero. Errors are sticky
 *   with aggregate sequence offsets; discard the connection. No upgrade negotiation or request
 *   queue is implemented.
 */
pub method(HttpResponseParser) Push(bytes: ref NetBytes) -> Result<HttpResponseProgress, HttpError> {
  if self.cell == nil {
    return HttpMakeError(HttpErrorKind.Closed);
  }

  var state: arc<HttpResponseData> = self.cell as arc<HttpResponseData>;
  if state.failure != nil {
    return state.failure as HttpError;
  }

  if state.complete {
    return HttpResponseProgress{state: HttpResponseState.Final};
  }

  if bytes.Len() == (0 as intptr) {
    return HttpResponseProgress{state: HttpResponseState.NeedInput};
  }

  if state.next_head {
    var made: Result<HttpHeadParser, HttpError> = HttpHeadParser.NewResponse(
      state.request_method,
      state.limits.head
    );
    if made.IsErr() {
      return http_response_fail(state,((made.get_if<HttpError>()) as HttpError).kind, state.total);
    }

    state.parser = move((made.get_if<HttpHeadParser>()) as HttpHeadParser);
    state.head = HttpHead{};
    state.head_start = state.total;
    state.next_head = false;
  }

  let budget: int64 = (state.limits.max_total_head_bytes as int64) - state.total;
  if budget == (0 as int64) {
    return http_response_fail(state, HttpErrorKind.LimitExceeded, state.total);
  }

  var count: intptr = bytes.Len();
  if (count as int64) > budget {
    count = budget as intptr;
  }

  let range: NetBytes = (bytes.Slice(0 as intptr, count).get_if<NetBytes>()) as NetBytes;
  let fed: Result<intptr, HttpError> = state.parser.Push(range);
  if fed.IsErr() {
    let error: HttpError = (fed.get_if<HttpError>()) as HttpError;

    return http_response_fail(state, error.kind, state.head_start + error.offset);
  }

  let consumed: intptr = (fed.get_if<intptr>()) as intptr;
  state.total = state.total + (consumed as int64);
  if !state.parser.IsComplete() {
    if count < bytes.Len() {
      return http_response_fail(state, HttpErrorKind.LimitExceeded, state.total);
    }

    return HttpResponseProgress{consumed: consumed, state: HttpResponseState.NeedInput};
  }

  let head: HttpHead = (state.parser.Head().get_if<HttpHead>()) as HttpHead;
  if head.Status() < 200 && head.Status() != 101 {
    if state.informationals >= state.limits.max_informational {
      return http_response_fail(state, HttpErrorKind.LimitExceeded, state.total);
    }

    state.head = head;
    state.informationals = state.informationals + 1;
    state.next_head = true;

    return HttpResponseProgress{consumed: consumed, state: HttpResponseState.Informational};
  }

  state.head = head;
  state.complete = true;

  return HttpResponseProgress{consumed: consumed, state: HttpResponseState.Final};
}

/**
 * @brief Last completed event head; pending InvalidState, closed cursor or terminal error
 *   otherwise.
 * @returns Ok with HttpHead on success; Err with HttpError on the failure paths described above.
 */
pub method(HttpResponseParser) Head() -> Result<HttpHead, HttpError> {
  if self.cell == nil {
    return HttpMakeError(HttpErrorKind.Closed);
  }

  let state: arc<HttpResponseData> = self.cell as arc<HttpResponseData>;
  if state.failure != nil {
    return state.failure as HttpError;
  }

  if state.head.MinorVersion() < 0 {
    return HttpMakeError(HttpErrorKind.InvalidState);
  }

  return state.head;
}

/**
 * @brief Whether a final response or 101 handoff head has completed successfully.
 * @returns Whether a final response or 101 handoff head has completed successfully.
 */
pub method(HttpResponseParser) IsComplete() -> bool {
  if self.cell == nil {
    return false;
  }

  let state: arc<HttpResponseData> = self.cell as arc<HttpResponseData>;

  return state.complete && state.failure == nil;
}

/**
 * @brief Accepted informational head count, excluding 101; zero for a default cursor.
 * @returns Accepted informational head count, excluding 101; zero for a default cursor.
 */
pub method(HttpResponseParser) InformationalCount() -> int32 {
  if self.cell == nil {
    return 0;
  }

  return (self.cell as arc<HttpResponseData>).informationals;
}

/**
 * @brief Return the terminal head, or make EOF before a final/101 head a sticky UnexpectedEof.
 * @returns Ok with HttpHead on success; Err with HttpError on the failure paths described above.
 */
pub method(HttpResponseParser) EndInput() -> Result<HttpHead, HttpError> {
  if self.cell == nil {
    return HttpMakeError(HttpErrorKind.Closed);
  }

  let state: arc<HttpResponseData> = self.cell as arc<HttpResponseData>;
  if state.failure != nil {
    return state.failure as HttpError;
  }

  if !state.complete {
    return http_response_fail(state, HttpErrorKind.UnexpectedEof, state.total);
  }

  return state.head;
}
