/** @brief Owned strict URL parsing without decoding or transport side effects. */
part of HttpClientCore;
struct HttpUrlData { scheme: string; host: string; port: int32; authority: string; target: string; }
pub struct HttpUrl { cell: arc<HttpUrlData>?; }
func url_error(kind: HttpErrorKind, offset: int32) -> HttpError { return HttpError{kind: kind, offset: offset as int64}; }
func url_hex(c: int32) -> bool { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
func url_lower(text: ref string) -> string {
  var out: StringBuffer = StringBuffer.New(); var i: int32 = 0;
  while i < text.length { var c: int32 = (text[i] as uint8) as int32; if c >= 65 && c <= 90 { c = c+32; } var byte: int8 = c as int8; out.Append(string.ViewFrom(&byte, 1)); i = i+1; } return out.Take();
}
func url_decimal(n: uint64) -> string {
  if n == 0u64 { return "0"; } var value: uint64 = n; var out: string = "";
  while value != 0u64 { var digit: StringBuffer = StringBuffer.New(); var byte: int8 = (((value%10u64) as int32)+48) as int8; digit.Append(string.ViewFrom(&byte, 1)); out = digit.Take().Concat(out); value = value/10u64; } return out;
}
func url_unreserved(c: int32) -> bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~'; }
func url_subdelim(c: int32) -> bool { return c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' || c == '*' || c == '+' || c == ',' || c == ';' || c == '='; }
func url_component(text: ref string, start: int32, end: int32, query: bool) -> int32 {
  var i: int32 = start;
  while i < end {
    let c: int32 = text[i];
    if c == '%' { if i+2 >= end || !url_hex(text[i+1]) || !url_hex(text[i+2]) { return i; } i = i+3; continue; }
    if !url_unreserved(c) && !url_subdelim(c) && c != ':' && c != '@' && c != '/' && !(query && c == '?') { return i; } i = i+1;
  } return -1;
}
// OS getaddrinfo may interpret shortened, octal, hex or integer forms as IPv4.
func url_numeric_host(host: ref string) -> bool {
  var start: int32 = 0; var i: int32 = 0;
  while i <= host.length {
    if i == host.length || host[i] == '.' {
      var j: int32 = start; var hex: bool = false;
      if i-start > 2 && host[start] == '0' && host[start+1] == 'x' { hex = true; j = j+2; }
      if j == i { return false; }
      while j < i { if hex { if !url_hex(host[j]) { return false; } } else { if host[j] < '0' || host[j] > '9' { return false; } } j = j+1; }
      start = i+1;
    } i = i+1;
  } return true;
}
/** @brief Parse and copy a bounded absolute URL, preserving escaped target semantics. */
pub static method(HttpUrl) Parse(text: ref string) -> Result<HttpUrl, HttpError> {
  if text.length > 8192 { return url_error(HttpErrorKind.LimitExceeded, 8192); }
  var i: int32 = 0;
  while i < text.length { let c: int32 = (text[i] as uint8) as int32; if c <= 32 || c >= 127 || c == 92 { return url_error(HttpErrorKind.Malformed, i); } i = i+1; }
  let sep: int32 = text.Find("://"); if sep < 0 { return url_error(HttpErrorKind.Malformed, 0); }
  let scheme: string = url_lower(text.Substring(0, sep));
  if !scheme.Equal("http") && !scheme.Equal("https") { return url_error(HttpErrorKind.Unsupported, 0); }
  let start: int32 = sep+3; var end: int32 = start;
  while end < text.length && text[end] != '/' && text[end] != '?' && text[end] != '#' { if text[end] == '@' { return url_error(HttpErrorKind.Unsupported, end); } end = end+1; }
  if start == end { return url_error(HttpErrorKind.Malformed, start); }
  var host: string = ""; var port_start: int32 = -1; var bracket: bool = false;
  if text[start] == '[' {
    bracket = true; var close: int32 = start+1; while close < end && text[close] != ']' { if text[close] == '%' { return url_error(HttpErrorKind.Unsupported, close); } close = close+1; }
    if close == end { return url_error(HttpErrorKind.Malformed, start); }
    let literal: string = text.Substring(start+1, close-start-1); let parsed: Result<IpAddress, NetError> = IpAddress.Parse(literal);
    if parsed.IsErr() || ((parsed.get_if<IpAddress>()) as IpAddress).Family() != IpFamily.V6 { return url_error(HttpErrorKind.Malformed, start); }
    host = ((parsed.get_if<IpAddress>()) as IpAddress).ToString();
    if close+1 < end { if text[close+1] != ':' { return url_error(HttpErrorKind.Malformed, close+1); } port_start = close+2; }
  } else {
    var stop: int32 = start; while stop < end && text[stop] != ':' { stop = stop+1; }
    host = url_lower(text.Substring(start, stop-start)); if stop < end { port_start = stop+1; }
    if host.length == 0 || host.length > 253 { return url_error(HttpErrorKind.Malformed, start); }
    let ip: Result<IpAddress, NetError> = IpAddress.Parse(host);
    if ip.IsOk() { if ((ip.get_if<IpAddress>()) as IpAddress).Family() != IpFamily.V4 { return url_error(HttpErrorKind.Malformed, start); } host = ((ip.get_if<IpAddress>()) as IpAddress).ToString(); }
    else {
      if url_numeric_host(host) { return url_error(HttpErrorKind.Unsupported, start); }
      var label: int32 = 0; i = 0;
      while i <= host.length {
        if i == host.length || host[i] == '.' {
          if i == label || i-label > 63 || host[label] == '-' || host[i-1] == '-' { return url_error(HttpErrorKind.Malformed, start+label); } label = i+1;
        } else { let c: int32 = host[i]; if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') { return url_error(HttpErrorKind.Unsupported, start+i); } } i = i+1;
      }
    }
  }
  var port: int32 = 80; if scheme.Equal("https") { port = 443; }
  let default_port: int32 = port;
  if port_start >= 0 {
    if port_start == end { return url_error(HttpErrorKind.Malformed, port_start); } port = 0; i = port_start;
    while i < end { if text[i] < '0' || text[i] > '9' { return url_error(HttpErrorKind.Malformed, i); } let digit: int32 = (text[i] as int32)-48; if port > (65535-digit)/10 { return url_error(HttpErrorKind.Malformed, i); } port = port*10+digit; i = i+1; }
    if port == 0 { return url_error(HttpErrorKind.Unsupported, port_start); }
  }
  var authority: string = host; if bracket { authority = "[".Concat(host).Concat("]"); } if port != default_port { authority = authority.Concat(":").Concat(url_decimal(port as uint64)); }
  var fragment: int32 = end; while fragment < text.length && text[fragment] != '#' { fragment = fragment+1; }
  var query: int32 = end; while query < fragment && text[query] != '?' { query = query+1; }
  let bad_path: int32 = url_component(text, end, query, false); if bad_path >= 0 { return url_error(HttpErrorKind.Malformed, bad_path); }
  if query < fragment { let bad: int32 = url_component(text, query+1, fragment, true); if bad >= 0 { return url_error(HttpErrorKind.Malformed, bad); } }
  if fragment < text.length { let bad: int32 = url_component(text, fragment+1, text.length, true); if bad >= 0 { return url_error(HttpErrorKind.Malformed, bad); } }
  var target: string = text.Substring(end, fragment-end); if end == query { target = "/".Concat(target); }
  return HttpUrl{cell: new arc<HttpUrlData>{scheme: scheme, host: host, port: port, authority: authority, target: target}};
}
/** @brief Successful Parse values retain immutable URL storage. */
pub method(HttpUrl) IsValid() -> bool { return self.cell != nil; }
/** @brief Lowercase scheme or empty. */
pub method(HttpUrl) Scheme() -> string { if self.cell == nil { return ""; } return (self.cell as arc<HttpUrlData>).scheme; }
/** @brief Canonical unbracketed resolution/verification host or empty. */
pub method(HttpUrl) Host() -> string { if self.cell == nil { return ""; } return (self.cell as arc<HttpUrlData>).host; }
/** @brief Effective nonzero port or zero. */
pub method(HttpUrl) Port() -> int32 { if self.cell == nil { return 0; } return (self.cell as arc<HttpUrlData>).port; }
/** @brief Whether the validated scheme is https. */
pub method(HttpUrl) IsSecure() -> bool { return self.Scheme().Equal("https"); }
/** @brief Canonical request Host or empty. */
pub method(HttpUrl) HostField() -> string { if self.cell == nil { return ""; } return (self.cell as arc<HttpUrlData>).authority; }
/** @brief Escaped origin-form path/query or empty. */
pub method(HttpUrl) Target() -> string { if self.cell == nil { return ""; } return (self.cell as arc<HttpUrlData>).target; }
/** @brief Owned canonical absolute URL without fragment. */
pub method(HttpUrl) ToString() -> string { if self.cell == nil { return ""; } return self.Scheme().Concat("://").Concat(self.HostField()).Concat(self.Target()); }
// Generate routing fields in one place for buffered and streamed URL requests.
func url_request_head(url: ref HttpUrl, verb: ref string, fields: ref <HttpField>[], body_length: uint64, chunked: bool, streaming: bool) -> Result<NetBuffer, HttpError> {
  if !url.IsValid() { return http_client_error(HttpErrorKind.InvalidArgument); }
  if fields.length > 126 { return http_client_error(HttpErrorKind.LimitExceeded); }
  var all: owned <HttpField>[] = new <HttpField>[fields.length+2]; all[0] = HttpField{name: "Host", value: url.HostField()};
  all[1] = HttpField{name: "Content-Length", value: url_decimal(body_length)};
  if chunked { all[1] = HttpField{name: "Transfer-Encoding", value: "chunked"}; }
  var i: int32 = 0; while i < fields.length {
    let name: string = fields[i].name;
    if http_client_equal(name, "Host") || http_client_equal(name, "Content-Length") || http_client_equal(name, "Transfer-Encoding") { return http_client_error(HttpErrorKind.InvalidArgument); }
    if (!streaming && http_client_equal(name, "Expect")) || http_client_equal(name, "Upgrade") { return http_client_error(HttpErrorKind.Unsupported); }
    all[i+2] = fields[i]; i = i+1;
  }
  if verb.Equal("CONNECT") { return http_client_error(HttpErrorKind.Unsupported); }
  return HttpWriter.Request(verb, url.Target(), all);
}
/** @brief Generate authority/framing once; caller cannot override routing fields. */
pub method(HttpUrl) RequestHead(verb: ref string, fields: ref <HttpField>[], body_length: uint64) -> Result<NetBuffer, HttpError> {
  return url_request_head(self, verb, fields, body_length, false, false);
}
/** @brief Serialize a URL-associated streamed request and validate the shared producer profile. */
pub method(HttpUrl) StreamingRequestHead(verb: ref string, fields: ref <HttpField>[], plan: ref HttpBodyPlan) -> Result<NetBuffer, HttpError> {
  if plan.close_connection || (plan.kind != HttpBodyKind.None && plan.kind != HttpBodyKind.ContentLength && plan.kind != HttpBodyKind.Chunked) || (plan.kind != HttpBodyKind.ContentLength && plan.length != 0u64) { return http_client_error(HttpErrorKind.InvalidArgument); }
  let made: Result<NetBuffer, HttpError> = url_request_head(self, verb, fields, plan.length, plan.kind == HttpBodyKind.Chunked, true);
  if made.IsErr() { return (made.get_if<HttpError>()) as HttpError; }
  let wire: NetBuffer = (made.get_if<NetBuffer>()) as NetBuffer;
  // Share Expect/upgrade/framing validation without imposing a caller's body budget.
  var checked: Result<HttpClientExchange, HttpError> = HttpClientExchange.NewStreaming(wire, HttpClientLimits{max_retained_request_bytes: 1073741824, body: HttpBodyLimits{max_body_bytes: 9223372036837998591u64}});
  if checked.IsErr() { return (checked.get_if<HttpError>()) as HttpError; }
  return wire;
}
