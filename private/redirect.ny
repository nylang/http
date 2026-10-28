/** @brief Shared URI-reference resolution and explicit redirect/replay policy. */
part of HttpClientCore;
func redirect_last_slash(text: ref string) -> int32 { var i: int32 = text.length-1; while i >= 0 { if text[i] == '/' { return i; } i = i-1; } return -1; }
func redirect_remove_last(text: ref string) -> string { let slash: int32 = redirect_last_slash(text); if slash < 0 { return ""; } return text.Substring(0, slash); }
func redirect_dot_segments(path: ref string) -> string {
  var input: string = path; var output: string = "";
  while input.length != 0 {
    if input.StartsWith("../") { input = input.Substring(3, input.length-3); }
    else if input.StartsWith("./") { input = input.Substring(2, input.length-2); }
    else if input.StartsWith("/./") { input = input.Substring(2, input.length-2); }
    else if input.Equal("/.") { input = "/"; }
    else if input.StartsWith("/../") { input = input.Substring(3, input.length-3); output = redirect_remove_last(output); }
    else if input.Equal("/..") { input = "/"; output = redirect_remove_last(output); }
    else if input.Equal(".") || input.Equal("..") { input = ""; }
    else {
      var end: int32 = 0; if input[0] == '/' { end = 1; }
      while end < input.length && input[end] != '/' { end = end+1; }
      output = output.Concat(input.Substring(0, end)); input = input.Substring(end, input.length-end);
    }
  } return output;
}
/** @brief Resolve strict HTTP references, validating escaped bytes before removing literal dot segments. */
pub method(HttpUrl) Resolve(reference: ref string) -> Result<HttpUrl, HttpError> {
  if !self.IsValid() { return http_client_error(HttpErrorKind.InvalidArgument); }
  if reference.length > 8192 { return http_client_error(HttpErrorKind.LimitExceeded); }
  let origin: string = self.Scheme().Concat("://").Concat(self.HostField());
  var target: string = self.Target(); let query: int32 = target.Find("?"); if query >= 0 { target = target.Substring(0, query); }
  var colon: int32 = 0; while colon < reference.length && reference[colon] != ':' && reference[colon] != '/' && reference[colon] != '?' && reference[colon] != '#' { colon = colon+1; }
  var absolute: string = "";
  if colon < reference.length && reference[colon] == ':' { absolute = reference; }
  else if reference.StartsWith("//") { absolute = self.Scheme().Concat(":").Concat(reference); }
  else if reference.StartsWith("/") { absolute = origin.Concat(reference); }
  else if reference.StartsWith("?") { absolute = origin.Concat(target).Concat(reference); }
  else if reference.length == 0 || reference.StartsWith("#") { absolute = self.ToString().Concat(reference); }
  else { let slash: int32 = redirect_last_slash(target); absolute = origin.Concat(target.Substring(0, slash+1)).Concat(reference); }
  let checked: Result<HttpUrl, HttpError> = HttpUrl.Parse(absolute); if checked.IsErr() { return (checked.get_if<HttpError>()) as HttpError; }
  let raw: HttpUrl = (checked.get_if<HttpUrl>()) as HttpUrl;
  if reference.length == 0 || reference.StartsWith("?") || reference.StartsWith("#") { return raw; }
  var path: string = raw.Target(); var suffix: string = "";
  let mark: int32 = path.Find("?"); if mark >= 0 { suffix = path.Substring(mark, path.length-mark); path = path.Substring(0, mark); }
  return HttpUrl.Parse(raw.Scheme().Concat("://").Concat(raw.HostField()).Concat(redirect_dot_segments(path)).Concat(suffix));
}
/** @brief Exact canonical scheme/host/effective-port origin comparison. */
pub method(HttpUrl) SameOrigin(other: ref HttpUrl) -> bool { return self.IsValid() && other.IsValid() && self.Scheme().Equal(other.Scheme()) && self.Host().Equal(other.Host()) && self.Port() == other.Port(); }
struct RedirectRequestData { url: HttpUrl; verb: string; fields: owned <HttpField>[]; body: NetBuffer; head: NetBuffer; parsed: HttpHead; limits: HttpClientLimits; options: NetOperationOptions; }
pub struct HttpRedirectRequest { cell: arc<RedirectRequestData>?; }
struct RedirectChainData { request: HttpRedirectRequest; policy: HttpRedirectPolicy; count: int32; finished: bool; failure: HttpClientError?; }
pub struct HttpRedirectChain { cell: arc<RedirectChainData>?; }
func redirect_copy(text: ref string) -> string { var buffer: StringBuffer = StringBuffer.New(); buffer.Append(text); return buffer.Take(); }
func redirect_error(kind: HttpErrorKind) -> HttpClientError { return HttpClientError{protocol_error: HttpError{kind: kind}, stage: HttpClientStage.ResponseHead}; }
func redirect_fail(state: arc<RedirectChainData>, error: HttpClientError) -> HttpClientError {
  var s: arc<RedirectChainData> = state; if s.failure != nil { return s.failure as HttpClientError; }
  var failure: HttpClientError = error;
  let control: Result<Unit, NetError> = s.request.Options().Check(NetClock.NowNanoseconds());
  if control.IsErr() { failure = HttpClientError{transport_error: (control.get_if<NetError>()) as NetError, stage: HttpClientStage.ResponseHead}; }
  s.failure = failure; s.request = HttpRedirectRequest{}; return failure;
}
func redirect_finish(state: arc<RedirectChainData>) -> Result<bool, HttpClientError> {
  var s: arc<RedirectChainData> = state; let control: Result<Unit, NetError> = s.request.Options().Check(NetClock.NowNanoseconds());
  if control.IsErr() { return redirect_fail(s, HttpClientError{transport_error: (control.get_if<NetError>()) as NetError, stage: HttpClientStage.ResponseHead}); }
  s.finished = true; return false;
}
func redirect_request(url: ref HttpUrl, verb: ref string, fields: ref <HttpField>[], body: ref NetBuffer, limits: ref HttpClientLimits, options: ref NetOperationOptions) -> Result<HttpRedirectRequest, HttpClientError> {
  let wire: Result<NetBuffer, HttpError> = url.RequestHead(verb, fields, body.Len() as uint64);
  if wire.IsErr() { return HttpClientError{protocol_error: (wire.get_if<HttpError>()) as HttpError}; }
  let head: NetBuffer = (wire.get_if<NetBuffer>()) as NetBuffer;
  var checked: Result<HttpClientExchange, HttpError> = HttpClientExchange.New(head, body, limits);
  if checked.IsErr() { return HttpClientError{protocol_error: (checked.get_if<HttpError>()) as HttpError}; }
  var exchange: HttpClientExchange = move((checked.get_if<HttpClientExchange>()) as HttpClientExchange);
  let parsed: HttpHead = (exchange.RequestHead().get_if<HttpHead>()) as HttpHead;
  var owned_fields: owned <HttpField>[] = new <HttpField>[fields.length]; var i: int32 = 0;
  while i < fields.length { owned_fields[i] = HttpField{name: redirect_copy(fields[i].name), value: redirect_copy(fields[i].value)}; i = i+1; }
  return HttpRedirectRequest{cell: new arc<RedirectRequestData>{url: url, verb: redirect_copy(verb), fields: move(owned_fields), body: body, head: head, parsed: parsed, limits: limits, options: options}};
}
/** @brief Own a validated initial request and a bounded redirect policy. */
pub static method(HttpRedirectChain) New(url: ref HttpUrl, verb: ref string, fields: ref <HttpField>[], body: ref NetBuffer, limits: ref HttpClientLimits, policy: ref HttpRedirectPolicy, options: ref NetOperationOptions) -> Result<HttpRedirectChain, HttpClientError> {
  let control: Result<Unit, NetError> = options.Check(NetClock.NowNanoseconds()); if control.IsErr() { return HttpClientError{transport_error: (control.get_if<NetError>()) as NetError}; }
  var caps: HttpRedirectPolicy = policy; if caps.max_redirects == 0 { caps.max_redirects = 5; }
  if caps.max_redirects < 1 || caps.max_redirects > 32 { return HttpClientError{protocol_error: http_client_error(HttpErrorKind.InvalidArgument)}; }
  let request: Result<HttpRedirectRequest, HttpClientError> = redirect_request(url, verb, fields, body, limits, options);
  if request.IsErr() { return (request.get_if<HttpClientError>()) as HttpClientError; }
  let final_control: Result<Unit, NetError> = options.Check(NetClock.NowNanoseconds()); if final_control.IsErr() { return HttpClientError{transport_error: (final_control.get_if<NetError>()) as NetError}; }
  return HttpRedirectChain{cell: new arc<RedirectChainData>{request: (request.get_if<HttpRedirectRequest>()) as HttpRedirectRequest, policy: caps}};
}
/** @brief Transfer the sole decision cursor. */
pub method(HttpRedirectChain) operator move() -> HttpRedirectChain { let cell: arc<RedirectChainData>? = self.cell; self.cell = nil; return HttpRedirectChain{cell: cell}; }
/** @brief Release the current request and decision state. */
pub method(HttpRedirectChain) operator drop() -> void { self.cell = nil; }
/** @brief Retain a request snapshot under the chain's original controls. */
pub method(HttpRedirectChain) Request() -> Result<HttpRedirectRequest, HttpClientError> {
  if self.cell == nil { return redirect_error(HttpErrorKind.Closed); } let s: arc<RedirectChainData> = self.cell as arc<RedirectChainData>;
  if s.failure != nil { return s.failure as HttpClientError; } if s.finished { return redirect_error(HttpErrorKind.InvalidState); }
  let control: Result<Unit, NetError> = s.request.Options().Check(NetClock.NowNanoseconds()); if control.IsErr() { return redirect_fail(s, HttpClientError{transport_error: (control.get_if<NetError>()) as NetError, stage: HttpClientStage.ResponseHead}); }
  return s.request;
}
func redirect_hop_field(request: arc<RedirectRequestData>, name: ref string) -> bool {
  if http_client_equal(name, "Connection") || http_client_equal(name, "Keep-Alive") || http_client_equal(name, "Proxy-Connection") || http_client_equal(name, "Proxy-Authorization") || http_client_equal(name, "TE") || http_client_equal(name, "Trailer") || http_client_equal(name, "Upgrade") { return true; }
  var i: int32 = 0;
  while i < request.parsed.FieldCount() {
    let field: HttpField = (request.parsed.FieldAt(i).get_if<HttpField>()) as HttpField;
    if http_client_equal(field.name, "Connection") {
      var start: int32 = 0; var end: int32 = 0;
      while end <= field.value.length {
        if end == field.value.length || field.value[end] == ',' {
          var a: int32 = start; var b: int32 = end; while a < b && (field.value[a] == ' ' || field.value[a] == '\t') { a = a+1; } while b > a && (field.value[b-1] == ' ' || field.value[b-1] == '\t') { b = b-1; }
          if http_client_equal(field.value.Substring(a, b-a), name) { return true; } start = end+1;
        } end = end+1;
      }
    } i = i+1;
  } return false;
}
func redirect_content(name: ref string) -> bool { return url_lower(name).StartsWith("content-") || http_client_equal(name, "Digest") || http_client_equal(name, "Want-Digest"); }
func redirect_cross_field(name: ref string, preserved: bool) -> bool {
  return http_client_equal(name, "Accept") || http_client_equal(name, "Accept-Encoding") || http_client_equal(name, "Accept-Language") || http_client_equal(name, "User-Agent") || (preserved && (http_client_equal(name, "Content-Type") || http_client_equal(name, "Content-Encoding")));
}
/** @brief Atomically advance one accepted redirect, without opening another connection. */
pub method(HttpRedirectChain) Follow(response: ref HttpHead) -> Result<bool, HttpClientError> {
  if self.cell == nil { return redirect_error(HttpErrorKind.Closed); } var s: arc<RedirectChainData> = self.cell as arc<RedirectChainData>;
  if s.failure != nil { return s.failure as HttpClientError; } if s.finished { return redirect_error(HttpErrorKind.InvalidState); }
  let control: Result<Unit, NetError> = s.request.Options().Check(NetClock.NowNanoseconds()); if control.IsErr() { return redirect_fail(s, HttpClientError{transport_error: (control.get_if<NetError>()) as NetError, stage: HttpClientStage.ResponseHead}); }
  let status: int32 = response.Status(); if status < 200 { return redirect_fail(s, redirect_error(HttpErrorKind.InvalidArgument)); }
  if status != 301 && status != 302 && status != 303 && status != 307 && status != 308 { return redirect_finish(s); }
  var location: string = ""; var found: int32 = 0; var i: int32 = 0;
  while i < response.FieldCount() { let field: HttpField = (response.FieldAt(i).get_if<HttpField>()) as HttpField; if http_client_equal(field.name, "Location") { found = found+1; location = field.value; } i = i+1; }
  if found == 0 { return redirect_finish(s); }
  if found != 1 { return redirect_fail(s, redirect_error(HttpErrorKind.InvalidFraming)); }
  if s.count >= s.policy.max_redirects { return redirect_fail(s, redirect_error(HttpErrorKind.RedirectLimit)); }
  let old: arc<RedirectRequestData> = s.request.cell as arc<RedirectRequestData>;
  let resolved: Result<HttpUrl, HttpError> = old.url.Resolve(location);
  if resolved.IsErr() { return redirect_fail(s, HttpClientError{protocol_error: (resolved.get_if<HttpError>()) as HttpError, stage: HttpClientStage.ResponseHead}); }
  let url: HttpUrl = (resolved.get_if<HttpUrl>()) as HttpUrl;
  if old.url.IsSecure() && !url.IsSecure() { return redirect_fail(s, redirect_error(HttpErrorKind.InsecureRedirect)); }
  let cross: bool = !old.url.SameOrigin(url);
  if cross && !s.policy.allow_cross_origin { return redirect_fail(s, redirect_error(HttpErrorKind.CrossOriginRedirect)); }
  var verb: string = old.verb; var body: NetBuffer = old.body;
  let rewrite: bool = ((status == 301 || status == 302) && verb.Equal("POST")) || (status == 303 && !verb.Equal("HEAD"));
  if rewrite { verb = "GET"; body = NetBuffer{}; }
  else if !s.policy.allow_unsafe_replay && (body.Len() != (0 as intptr) || (!verb.Equal("GET") && !verb.Equal("HEAD") && !verb.Equal("OPTIONS"))) { return redirect_fail(s, redirect_error(HttpErrorKind.ReplayRejected)); }
  var count: int32 = 0; i = 0;
  while i < old.fields.length { let name: string = old.fields[i].name; if !redirect_hop_field(old, name) && !(rewrite && redirect_content(name)) && (!cross || redirect_cross_field(name, !rewrite)) { count = count+1; } i = i+1; }
  var fields: owned <HttpField>[] = new <HttpField>[count]; count = 0; i = 0;
  while i < old.fields.length { let field: HttpField = old.fields[i]; if !redirect_hop_field(old, field.name) && !(rewrite && redirect_content(field.name)) && (!cross || redirect_cross_field(field.name, !rewrite)) { fields[count] = field; count = count+1; } i = i+1; }
  let made: Result<HttpRedirectRequest, HttpClientError> = redirect_request(url, verb, fields, body, old.limits, old.options);
  if made.IsErr() { return redirect_fail(s, (made.get_if<HttpClientError>()) as HttpClientError); }
  let final_control: Result<Unit, NetError> = old.options.Check(NetClock.NowNanoseconds()); if final_control.IsErr() { return redirect_fail(s, HttpClientError{transport_error: (final_control.get_if<NetError>()) as NetError, stage: HttpClientStage.ResponseHead}); }
  s.request = (made.get_if<HttpRedirectRequest>()) as HttpRedirectRequest; s.count = s.count+1; return true;
}
/** @brief Committed hop count survives failure and completion. */
pub method(HttpRedirectChain) Count() -> int32 { if self.cell == nil { return 0; } return (self.cell as arc<RedirectChainData>).count; }
/** @brief Owned current URL, or invalid default. */
pub method(HttpRedirectRequest) Url() -> HttpUrl { if self.cell == nil { return HttpUrl{}; } return (self.cell as arc<RedirectRequestData>).url; }
/** @brief Owned request method. */
pub method(HttpRedirectRequest) Verb() -> string { if self.cell == nil { return ""; } return (self.cell as arc<RedirectRequestData>).verb; }
/** @brief Retain the validated generated head owner. */
pub method(HttpRedirectRequest) Head() -> NetBuffer { if self.cell == nil { return NetBuffer{}; } return (self.cell as arc<RedirectRequestData>).head; }
/** @brief Retain the immutable payload owner. */
pub method(HttpRedirectRequest) Body() -> NetBuffer { if self.cell == nil { return NetBuffer{}; } return (self.cell as arc<RedirectRequestData>).body; }
/** @brief Additional field count. */
pub method(HttpRedirectRequest) FieldCount() -> int32 { if self.cell == nil { return 0; } return (self.cell as arc<RedirectRequestData>).fields.length; }
/** @brief Retain one owned field without exposing mutable storage. */
pub method(HttpRedirectRequest) FieldAt(index: int32) -> Result<HttpField, HttpError> { if self.cell == nil || index < 0 || index >= self.FieldCount() { return http_client_error(HttpErrorKind.InvalidArgument); } return (self.cell as arc<RedirectRequestData>).fields[index]; }
/** @brief Copied original limits. */
pub method(HttpRedirectRequest) Limits() -> HttpClientLimits { if self.cell == nil { return HttpClientLimits{}; } return (self.cell as arc<RedirectRequestData>).limits; }
/** @brief Copied original absolute controls; shared cancellation remains shared. */
pub method(HttpRedirectRequest) Options() -> NetOperationOptions { if self.cell == nil { return NetOperationOptions{}; } return (self.cell as arc<RedirectRequestData>).options; }
/** @brief Connect a plain snapshot without refreshing controls. */
pub method(HttpRedirectRequest) OpenTcp(resolver: ref mut AsyncResolver, dial: ref HttpDialOptions) -> Result<HttpTcpClient, HttpClientError> {
  if self.cell == nil { return redirect_error(HttpErrorKind.InvalidArgument); } let s: arc<RedirectRequestData> = self.cell as arc<RedirectRequestData>;
  return HttpTcpClient.Open(s.url, s.verb, s.fields, s.body, s.limits, resolver, dial, s.options);
}
