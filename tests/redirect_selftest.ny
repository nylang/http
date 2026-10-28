/** @brief Redirect resolution and replay policy acceptance. */
part of HttpClientCore;
func redirect_test_head(status: int32, location: ref string) -> HttpHead {
  let wire: string = "HTTP/1.1 ".Concat(url_decimal(status as uint64)).Concat(" Test\r\nContent-Length: 0\r\n").Concat(location).Concat("\r\n");
  var made: Result<HttpHeadParser, HttpError> = HttpHeadParser.NewResponse("GET", HttpHeadLimits{}); var parser: HttpHeadParser = move((made.get_if<HttpHeadParser>()) as HttpHeadParser);
  client_assert(parser.Push(NetBytes.FromString(wire)).IsOk(), "valid test response head"); return (parser.Head().get_if<HttpHead>()) as HttpHead;
}
func redirect_test_chain(url: ref string, verb: ref string, fields: ref <HttpField>[], body: ref string, policy: ref HttpRedirectPolicy) -> HttpRedirectChain {
  var made: Result<HttpRedirectChain, HttpClientError> = HttpRedirectChain.New(url_test(url), verb, fields, client_buffer(body), HttpClientLimits{}, policy, NetOperationOptions{});
  client_assert(made.IsOk(), "redirect chain validates initial request"); return move((made.get_if<HttpRedirectChain>()) as HttpRedirectChain);
}
func redirect_test_request(chain: ref mut HttpRedirectChain) -> HttpRedirectRequest { let result: Result<HttpRedirectRequest, HttpClientError> = chain.Request(); client_assert(result.IsOk(), "request snapshot available"); return (result.get_if<HttpRedirectRequest>()) as HttpRedirectRequest; }
@test(tag = "http_core")
func test_http_redirect_reference_rfc_examples() {
  let base: HttpUrl = url_test("http://a/b/c/d;p?q");
  var inputs: owned <string>[] = new <string>[]{"g", "./g", "g/", "/g", "//g", "?y", "g?y", "#s", "g#s", "g?y#s", ";x", "g;x", "g;x?y#s", "", ".", "./", "..", "../", "../g", "../..", "../../", "../../g", "../../../g", "/./g", "/../g", "g.", ".g", "g..", "..g", "./../g", "./g/.", "g/./h", "g/../h", "g;x=1/./y", "g;x=1/../y", "g?y/./x", "g?y/../x", "g#s/../x"};
  var outputs: owned <string>[] = new <string>[]{"http://a/b/c/g", "http://a/b/c/g", "http://a/b/c/g/", "http://a/g", "http://g/", "http://a/b/c/d;p?y", "http://a/b/c/g?y", "http://a/b/c/d;p?q", "http://a/b/c/g", "http://a/b/c/g?y", "http://a/b/c/;x", "http://a/b/c/g;x", "http://a/b/c/g;x?y", "http://a/b/c/d;p?q", "http://a/b/c/", "http://a/b/c/", "http://a/b/", "http://a/b/", "http://a/b/g", "http://a/", "http://a/", "http://a/g", "http://a/g", "http://a/g", "http://a/g", "http://a/b/c/g.", "http://a/b/c/.g", "http://a/b/c/g..", "http://a/b/c/..g", "http://a/b/g", "http://a/b/c/g/", "http://a/b/c/g/h", "http://a/b/c/h", "http://a/b/c/g;x=1/y", "http://a/b/c/y", "http://a/b/c/g?y/./x", "http://a/b/c/g?y/../x", "http://a/b/c/g"};
  var i: int32 = 0; while i < inputs.length { let result: Result<HttpUrl,HttpError> = base.Resolve(inputs[i]); client_assert(result.IsOk(), inputs[i]); if result.IsOk() { client_assert(((result.get_if<HttpUrl>()) as HttpUrl).ToString().Equal(outputs[i]), inputs[i]); } i = i+1; }
}
@test(tag = "http_core")
func test_http_redirect_resolution_validation_and_origin() {
  let base: HttpUrl = url_test("https://LOCALHOST:443/a//b?q");
  let dotted: HttpUrl = url_test("https://localhost/x/../y?q");
  client_assert(((dotted.Resolve("#fragment").get_if<HttpUrl>()) as HttpUrl).Target().Equal("/x/../y?q") && ((dotted.Resolve("?z").get_if<HttpUrl>()) as HttpUrl).Target().Equal("/x/../y?z"), "empty-path references preserve the base path verbatim");
  client_assert((base.Resolve("../%2e%2e/%2f?").get_if<HttpUrl>() as HttpUrl).Target().Equal("/a/%2e%2e/%2f?"), "escaped dots/slash stay literal and repeated segments preserved");
  client_assert(base.Resolve("bad%/../ok").IsErr() && base.Resolve("x\\evil/../ok").IsErr() && base.Resolve("javascript:x").IsErr() && base.Resolve("http:g").IsErr() && base.Resolve("//user@host/").IsErr(), "validate components before normalization and reject unsupported schemes/authority");
  client_assert(base.SameOrigin(url_test("https://localhost/x")) && !base.SameOrigin(url_test("http://localhost/x")) && !base.SameOrigin(url_test("https://localhost:444/x")) && !base.SameOrigin(HttpUrl{}), "origin includes scheme/canonical host/effective port");
}
@test(tag = "http_core")
func test_http_redirect_post_rewrite_and_snapshot_lifetime() {
  var fields: owned <HttpField>[] = new <HttpField>[]{HttpField{name: "Content-Type",value: "text/plain"}, HttpField{name: "Content-Encoding",value: "identity"}, HttpField{name: "X-Keep",value: "ok"}};
  var chain: HttpRedirectChain = redirect_test_chain("http://localhost/a", "POST", fields, "payload", HttpRedirectPolicy{});
  let old: HttpRedirectRequest = redirect_test_request(chain);
  let followed: Result<bool,HttpClientError> = chain.Follow(redirect_test_head(302, "Location: ../next\r\n")); client_assert(followed.IsOk() && ((followed.get_if<bool>()) as bool), "POST 302 becomes GET");
  let next: HttpRedirectRequest = redirect_test_request(chain); chain = HttpRedirectChain{};
  client_assert(next.Verb().Equal("GET") && next.Body().Len() == (0 as intptr) && next.FieldCount() == 1 && next.Url().Target().Equal("/next"), "rewrite clears body and representation fields");
  client_assert(old.Verb().Equal("POST") && old.Body().Len() == (7 as intptr) && next.Head().Len() > (0 as intptr), "old and next snapshots independently own data after chain drop");
}
@test(tag = "http_core")
func test_http_redirect_preserved_replay_requires_opt_in() {
  var chain: HttpRedirectChain = redirect_test_chain("http://localhost/", "POST", new <HttpField>[0], "abc", HttpRedirectPolicy{});
  let failed: Result<bool,HttpClientError> = chain.Follow(redirect_test_head(307,"Location: /next\r\n"));
  client_assert(failed.IsErr() && (((failed.get_if<HttpClientError>()) as HttpClientError).protocol_error as HttpError).kind == HttpErrorKind.ReplayRejected && chain.Count() == 0 && chain.Request().IsErr(), "307 POST fails closed without replay permission");
  var allowed: HttpRedirectChain = redirect_test_chain("http://localhost/", "POST", new <HttpField>[0], "abc", HttpRedirectPolicy{allow_unsafe_replay: true});
  client_assert(allowed.Follow(redirect_test_head(308,"Location: /next\r\n")).IsOk(), "308 preserved replay explicitly enabled");
  let request: HttpRedirectRequest = redirect_test_request(allowed); client_assert(request.Verb().Equal("POST") && request.Body().Len() == (3 as intptr), "method and immutable body preserved");
}
@test(tag = "http_core")
func test_http_redirect_cross_origin_filters_and_no_downgrade() {
  var fields: owned <HttpField>[] = new <HttpField>[]{HttpField{name: "Authorization",value: "secret"},HttpField{name: "Cookie",value: "secret"},HttpField{name: "X-Token",value: "secret"},HttpField{name: "Origin",value: "secret"},HttpField{name: "Referer",value: "secret"},HttpField{name: "Accept",value: "text/plain"},HttpField{name: "Connection",value: "User-Agent"},HttpField{name: "User-Agent",value: "nominated"}};
  var chain: HttpRedirectChain = redirect_test_chain("http://localhost/", "GET", fields, "", HttpRedirectPolicy{allow_cross_origin:true});
  client_assert(chain.Follow(redirect_test_head(301,"Location: http://localhost:81/\r\n")).IsOk(), "explicit cross-port follow allowed");
  let next: HttpRedirectRequest = redirect_test_request(chain); client_assert(next.FieldCount() == 1 && ((next.FieldAt(0).get_if<HttpField>()) as HttpField).name.Equal("Accept"), "only safe allowlisted non-nominated fields survive");
  client_assert(chain.Follow(redirect_test_head(302,"Location: http://localhost/\r\n")).IsOk() && redirect_test_request(chain).FieldCount() == 1, "return to original origin never resurrects credentials");
  var denied: HttpRedirectChain = redirect_test_chain("http://localhost/", "GET", new <HttpField>[0], "", HttpRedirectPolicy{});
  client_assert(denied.Follow(redirect_test_head(302,"Location: http://elsewhere/\r\n")).IsErr(), "cross-origin disabled by default");
  var secure: HttpRedirectChain = redirect_test_chain("https://localhost/", "GET", new <HttpField>[0], "", HttpRedirectPolicy{allow_cross_origin:true,allow_unsafe_replay:true});
  let failed: Result<bool,HttpClientError> = secure.Follow(redirect_test_head(302,"Location: http://localhost/\r\n")); client_assert(failed.IsErr() && (((failed.get_if<HttpClientError>()) as HttpClientError).protocol_error as HttpError).kind == HttpErrorKind.InsecureRedirect, "HTTPS downgrade cannot be enabled by another permission");
}
@test(tag = "http_core")
func test_http_redirect_limits_locations_and_terminal_response() {
  var chain: HttpRedirectChain = redirect_test_chain("http://localhost/", "GET", new <HttpField>[0], "", HttpRedirectPolicy{max_redirects:1});
  client_assert(chain.Follow(redirect_test_head(302,"Location: #same\r\n")).IsOk() && chain.Count() == 1, "fragment-only self redirect consumes a hop");
  let failed: Result<bool,HttpClientError> = chain.Follow(redirect_test_head(302,"Location: /\r\n")); client_assert(failed.IsErr() && (((failed.get_if<HttpClientError>()) as HttpClientError).protocol_error as HttpError).kind == HttpErrorKind.RedirectLimit, "cycles bounded by exact hop cap");
  var duplicate: HttpRedirectChain = redirect_test_chain("http://localhost/", "GET", new <HttpField>[0], "", HttpRedirectPolicy{});
  client_assert(duplicate.Follow(redirect_test_head(302,"Location: /one\r\nLocation: /two\r\n")).IsErr() && duplicate.Follow(redirect_test_head(200,"")).IsErr(), "ambiguous location remains terminal");
  var terminal: HttpRedirectChain = redirect_test_chain("http://localhost/", "GET", new <HttpField>[0], "", HttpRedirectPolicy{});
  let done: Result<bool,HttpClientError> = terminal.Follow(redirect_test_head(302,"")); client_assert(done.IsOk() && !((done.get_if<bool>()) as bool) && terminal.Request().IsErr(), "missing location is an observable terminal response");
}
@test(tag = "http_core")
func test_http_redirect_method_status_matrix() {
  var statuses: owned <int32>[] = new <int32>[]{301,302,303,307,308};
  var methods: owned <string>[] = new <string>[]{"GET","HEAD","OPTIONS","POST","PUT","post"};
  var i: int32 = 0; while i < statuses.length { var j: int32 = 0; while j < methods.length {
    var chain: HttpRedirectChain = redirect_test_chain("http://localhost/start", methods[j], new <HttpField>[0], "", HttpRedirectPolicy{});
    let rewrites: bool = ((statuses[i] == 301 || statuses[i] == 302) && methods[j].Equal("POST")) || (statuses[i] == 303 && !methods[j].Equal("HEAD"));
    let allowed: bool = rewrites || methods[j].Equal("GET") || methods[j].Equal("HEAD") || methods[j].Equal("OPTIONS");
    let result: Result<bool,HttpClientError> = chain.Follow(redirect_test_head(statuses[i], "Location: /next\r\n"));
    client_assert(result.IsOk() == allowed, "status/method replay matrix"); if result.IsOk() { let request: HttpRedirectRequest = redirect_test_request(chain); var expected: string = methods[j]; if rewrites { expected = "GET"; } client_assert(request.Verb().Equal(expected), "correct case-sensitive method rewrite"); } j = j+1;
  } i = i+1; }
  var body: HttpRedirectChain = redirect_test_chain("http://localhost/", "GET", new <HttpField>[0], "x", HttpRedirectPolicy{});
  client_assert(body.Follow(redirect_test_head(307,"Location: /next\r\n")).IsErr(), "even GET body replay requires explicit permission");
}
@test(tag = "http_core")
func test_http_redirect_same_origin_hop_fields_and_borrowed_sources() {
  var bytes: <int8>[6] = <int8>[6]{}; bytes[0] = 's'; bytes[1] = 'e'; bytes[2] = 'c'; bytes[3] = 'r'; bytes[4] = 'e'; bytes[5] = 't';
  var fields: owned <HttpField>[] = new <HttpField>[]{HttpField{name:"Authorization",value:string.ViewFrom(&bytes[0],6)},HttpField{name:"Connection",value:"X-Hop"},HttpField{name:"X-Hop",value:"remove"},HttpField{name:"Proxy-Authorization",value:"remove"}};
  var chain: HttpRedirectChain = redirect_test_chain("http://localhost/", "GET", fields, "", HttpRedirectPolicy{}); bytes[0] = 'X'; fields[0].value = "changed";
  client_assert(chain.Follow(redirect_test_head(307,"Location: /next\r\n")).IsOk(), "same-origin GET replay allowed");
  let next: HttpRedirectRequest = redirect_test_request(chain); client_assert(next.FieldCount() == 1 && ((next.FieldAt(0).get_if<HttpField>()) as HttpField).value.Equal("secret"), "same-origin owned credential retained and nominated/proxy fields removed");
}
@test(tag = "http_core")
func test_http_redirect_controls_defaults_and_sticky_invalid_input() {
  var token: NetCancellation = NetCancellation.New(); let options: NetOperationOptions = NetOperationOptions{cancellation: token};
  var made: Result<HttpRedirectChain,HttpClientError> = HttpRedirectChain.New(url_test("http://localhost/"),"GET",new <HttpField>[0],NetBuffer{},HttpClientLimits{},HttpRedirectPolicy{},options);
  client_assert(made.IsOk(), "controlled chain admission"); var chain: HttpRedirectChain = move((made.get_if<HttpRedirectChain>()) as HttpRedirectChain); token.Cancel();
  let failed: Result<bool,HttpClientError> = chain.Follow(redirect_test_head(302,"Location: /next\r\n")); client_assert(failed.IsErr() && (((failed.get_if<HttpClientError>()) as HttpClientError).transport_error as NetError).kind == NetErrorKind.Cancelled && chain.Count() == 0 && chain.Request().IsErr(), "original cancellation prevents decision publication and further request access");
  client_assert(HttpRedirectChain.New(url_test("http://localhost/"),"GET",new <HttpField>[0],NetBuffer{},HttpClientLimits{},HttpRedirectPolicy{max_redirects:33},NetOperationOptions{}).IsErr(), "hard policy cap enforced");
  var invalid: HttpRedirectChain = redirect_test_chain("http://localhost/", "GET", new <HttpField>[0], "", HttpRedirectPolicy{});
  client_assert(invalid.Follow(HttpHead{}).IsErr() && invalid.Request().IsErr(), "invalid/default response head retires chain");
  var capped: HttpRedirectChain = redirect_test_chain("http://localhost/", "GET", new <HttpField>[0], "", HttpRedirectPolicy{}); var i: int32 = 0;
  while i < 5 { client_assert(capped.Follow(redirect_test_head(302,"Location: /\r\n")).IsOk(), "default five redirects accepted"); i = i+1; } client_assert(capped.Follow(redirect_test_head(302,"Location: /\r\n")).IsErr(), "sixth default redirect rejected");
}
