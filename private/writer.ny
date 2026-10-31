// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

module HttpHeadWriter;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/client.ni";
import "interface/url.ni";
import "interface/redirect.ni";
import "private/grammar.ny";
import "private/http.ny";

/** @brief Head serialization validates both individual fields and the resulting framing. */

// Validate the complete head before publishing wire bytes so malformed metadata cannot leak as a partial request.
// Own the immutable serialization context; fields are borrowed only by Encode.
struct HttpHeadEncoding {
  readonly start: string;
  readonly response: bool;
  readonly request_method: string;
}

method(HttpHeadEncoding) Encode(fields: ref <HttpField>[]) -> Result<NetBuffer, HttpError> {
  let start: string = self.start;
  let response: bool = self.response;
  let request_method: string = self.request_method;
  if start.length > 8192 || fields.length > 100 {
    return HttpError{kind: HttpErrorKind.LimitExceeded};
  }

  var size: int32 = start.length + 4;
  var i: int32 = 0;
  while i < fields.length {
    let field: HttpField = fields[i];
    if !HttpLexeme.New(field.name).IsToken() || !HttpLexeme.New(field.value).IsFieldValue() {
      return HttpError{kind: HttpErrorKind.Malformed};
    }

    if field.name.length > 8192 || field.value.length > 8192 - field.name.length - 2 {
      return HttpError{kind: HttpErrorKind.LimitExceeded};
    }

    let line_size: int32 = field.name.length + field.value.length + 4;
    if line_size > 32768 - size {
      return HttpError{kind: HttpErrorKind.LimitExceeded};
    }

    size = size + line_size;
    i = i + 1;
  }

  var buffer: StringBuffer = StringBuffer.NewWithCapacity(size);
  buffer.Append(start);
  buffer.Append("\r\n");
  i = 0;
  while i < fields.length {
    buffer.Append(fields[i].name);
    buffer.Append(": ");
    buffer.Append(fields[i].value);
    buffer.Append("\r\n");
    i = i + 1;
  }

  buffer.Append("\r\n");
  let wire: string = buffer.Take();
  var made: Result<HttpHeadParser, HttpError> = HttpHeadParser.NewParser(response, request_method, HttpHeadLimits{});
  if made.IsErr() {
    return (made.get_if<HttpError>()) as HttpError;
  }

  var parser: HttpHeadParser = move((made.get_if<HttpHeadParser>()) as HttpHeadParser);
  let parsed: Result<intptr, HttpError> = parser.Push(NetBytes.FromString(wire));
  if parsed.IsErr() {
    return (parsed.get_if<HttpError>()) as HttpError;
  }

  if !parser.IsComplete() || ((parsed.get_if<intptr>()) as intptr) != wire.length as intptr {
    return HttpError{kind: HttpErrorKind.Malformed};
  }

  let copied: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(NetBytes.FromString(wire));
  if copied.IsErr() {
    return HttpError{kind: HttpErrorKind.ResourceExhausted};
  }

  return (copied.get_if<NetBuffer>()) as NetBuffer;
}

/**
 * @brief Validate method, origin-form/OPTIONS-* target and fields; mandatory single Host. No
 *   body emitted.
 * @returns Ok with NetBuffer on success; Err with HttpError on the failure paths described
 *   above.
 */
pub static method(HttpHead) EncodeRequest(
  verb: ref string,
  target: ref string,
  fields: ref <HttpField>[]
) -> Result<NetBuffer, HttpError> {
  if !HttpLexeme.New(verb).IsToken() || !HttpLexeme.New(verb).AcceptsTarget(target) {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  if verb.length > 8192 || target.length > 8192 - verb.length - 10 {
    return HttpError{kind: HttpErrorKind.LimitExceeded};
  }

  let start: string = verb.Concat(" ").Concat(target).Concat(" HTTP/1.1");

  return HttpHeadEncoding{start: start, response: false, request_method: ""}.Encode(fields);
}

/**
 * @brief Validate status/reason/fields with originating-method framing; no body emitted.
 * @returns Ok with NetBuffer on success; Err with HttpError on the failure paths described
 *   above.
 */
pub static method(HttpHead) EncodeResponse(
  status: int32,
  reason: ref string,
  fields: ref <HttpField>[],
  request_method: ref string
) -> Result<NetBuffer, HttpError> {
  if status < 100 || status > 599 || !HttpLexeme.New(reason).IsFieldValue()
    || !HttpLexeme.New(request_method).IsToken() {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  if reason.length > 8192 - 13 {
    return HttpError{kind: HttpErrorKind.LimitExceeded};
  }

  var digits: <int8>[3] = <int8>[3] {
  };
  digits[0] = (48 + status / 100) as int8;
  digits[1] = (48 + (status / 10) % 10) as int8;
  digits[2] = (48 + status % 10) as int8;
  let code: string = string.ViewFrom(&digits[0], 3);
  let start: string = "HTTP/1.1 ".Concat(code).Concat(" ").Concat(reason);

  return HttpHeadEncoding{start: start, response: true, request_method: request_method}.Encode(fields);
}
