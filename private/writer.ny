/** @brief Head serialization validates both individual fields and the resulting framing. */
part of HttpProtocol;

func http_serialize(start: ref string, fields: ref <HttpField>[], response: bool, request_method: ref string) -> Result<NetBuffer, HttpError> {
  if start.length > 8192 || fields.length > 100 { return http_error(HttpErrorKind.LimitExceeded); }
  var size: int32 = start.length+4;
  var i: int32 = 0;
  while i < fields.length {
    let field: HttpField = fields[i];
    if !http_token(field.name) || !http_value(field.value) { return http_error(HttpErrorKind.Malformed); }
    if field.name.length > 8192 || field.value.length > 8192-field.name.length-2 { return http_error(HttpErrorKind.LimitExceeded); }
    let line_size: int32 = field.name.length+field.value.length+4;
    if line_size > 32768-size { return http_error(HttpErrorKind.LimitExceeded); } size = size+line_size; i = i+1;
  }
  var buffer: StringBuffer = StringBuffer.NewWithCapacity(size);
  buffer.Append(start); buffer.Append("\r\n"); i = 0;
  while i < fields.length { buffer.Append(fields[i].name); buffer.Append(": "); buffer.Append(fields[i].value); buffer.Append("\r\n"); i = i+1; }
  buffer.Append("\r\n"); let wire: string = buffer.Take();
  var made: Result<HttpHeadParser, HttpError> = http_new(response, request_method, HttpHeadLimits{});
  if made.IsErr() { return (made.get_if<HttpError>()) as HttpError; }
  var parser: HttpHeadParser = move((made.get_if<HttpHeadParser>()) as HttpHeadParser);
  let parsed: Result<intptr, HttpError> = parser.Push(NetBytes.FromString(wire));
  if parsed.IsErr() { return (parsed.get_if<HttpError>()) as HttpError; }
  if !parser.IsComplete() || ((parsed.get_if<intptr>()) as intptr) != wire.length as intptr { return http_error(HttpErrorKind.Malformed); }
  let copied: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(NetBytes.FromString(wire));
  if copied.IsErr() { return http_error(HttpErrorKind.ResourceExhausted); }
  return (copied.get_if<NetBuffer>()) as NetBuffer;
}
/** @brief Emit a validated HTTP/1.1 request head without borrowing caller backing. */
pub static method(HttpWriter) Request(verb: ref string, target: ref string, fields: ref <HttpField>[]) -> Result<NetBuffer, HttpError> {
  if !http_token(verb) || !http_target(verb, target) { return http_error(HttpErrorKind.InvalidArgument); }
  if verb.length > 8192 || target.length > 8192-verb.length-10 { return http_error(HttpErrorKind.LimitExceeded); }
  let start: string = verb.Concat(" ").Concat(target).Concat(" HTTP/1.1");
  return http_serialize(start, fields, false, "");
}
/** @brief Emit a validated HTTP/1.1 response head under the originating request context. */
pub static method(HttpWriter) Response(status: int32, reason: ref string, fields: ref <HttpField>[], request_method: ref string) -> Result<NetBuffer, HttpError> {
  if status < 100 || status > 599 || !http_value(reason) || !http_token(request_method) { return http_error(HttpErrorKind.InvalidArgument); }
  if reason.length > 8192-13 { return http_error(HttpErrorKind.LimitExceeded); }
  var digits: <int8>[3] = <int8>[3]{};
  digits[0] = (48+status/100) as int8; digits[1] = (48+(status/10)%10) as int8; digits[2] = (48+status%10) as int8;
  let code: string = string.ViewFrom(&digits[0], 3);
  let start: string = "HTTP/1.1 ".Concat(code).Concat(" ").Concat(reason);
  return http_serialize(start, fields, true, request_method);
}
