/** @brief Strict URL normalization, injection boundaries and generated request association. */
part of HttpClientCore;
func url_test(text: ref string) -> HttpUrl { let parsed: Result<HttpUrl, HttpError> = HttpUrl.Parse(text); client_assert(parsed.IsOk(), "URL parse succeeds"); return (parsed.get_if<HttpUrl>()) as HttpUrl; }
@test(tag = "http_core")
func test_http_url_authority_and_defaults() {
  let a: HttpUrl = url_test("HtTp://ExAmPle.COM:00080");
  client_assert(a.Scheme().Equal("http") && a.Host().Equal("example.com") && a.Port() == 80 && a.HostField().Equal("example.com") && a.Target().Equal("/") && a.ToString().Equal("http://example.com/"), "case, leading-zero/default port and empty path normalize");
  let b: HttpUrl = url_test("HTTPS://LOCALHOST:8443?q=1#fragment");
  client_assert(b.IsSecure() && b.Port() == 8443 && b.Target().Equal("/?q=1") && b.ToString().Equal("https://localhost:8443/?q=1"), "nondefault port retained and fragment removed");
  client_assert(url_test("https://example.com:443/?").ToString().Equal("https://example.com/?"), "empty query delimiter retained");
}
@test(tag = "http_core")
func test_http_url_ip_identity_and_ports() {
  let a: HttpUrl = url_test("https://[0:0:0:0:0:0:0:1]:443/a");
  client_assert(a.Host().Equal("::1") && a.HostField().Equal("[::1]") && a.ToString().Equal("https://[::1]/a"), "IPv6 host canonical and Host bracketed");
  client_assert(url_test("http://127.0.0.1:65535").Port() == 65535, "largest nonzero port accepted");
  client_assert(HttpUrl.Parse("http://host:0").IsErr() && HttpUrl.Parse("http://host:").IsErr() && HttpUrl.Parse("http://host:65536").IsErr() && HttpUrl.Parse("http://host:999999999999999999999").IsErr(), "empty, zero and overflowing ports rejected");
  client_assert(HttpUrl.Parse("http://[::1]extra/").IsErr() && HttpUrl.Parse("http://[127.0.0.1]/").IsErr() && HttpUrl.Parse("http://::1/").IsErr() && HttpUrl.Parse("http://[fe80::1%25en0]/").IsErr(), "IPv6 bracket and scope boundary enforced");
}
@test(tag = "http_core")
func test_http_url_escaped_target_is_opaque() {
  let a: HttpUrl = url_test("http://example.com/a/../b%2fc?x=%0d%0A&y=/?:@!$'()*+,;=#frag%20ok");
  client_assert(a.Target().Equal("/a/../b%2fc?x=%0d%0A&y=/?:@!$'()*+,;="), "dot segments and escapes preserved without decoding into header syntax");
  client_assert(HttpUrl.Parse("http://host/%").IsErr() && HttpUrl.Parse("http://host/?x=%G0").IsErr() && HttpUrl.Parse("http://host/#%a").IsErr(), "malformed triplets rejected in every component");
  client_assert(HttpUrl.Parse("http://host/a[b]").IsErr() && HttpUrl.Parse("http://host/#x#y").IsErr(), "raw invalid component delimiters rejected");
}
@test(tag = "http_core")
func test_http_url_rejects_ambiguous_authority() {
  var bad: owned <string>[] = new <string>[14]; bad[0] = "http://127.1/"; bad[1] = "http://2130706433/"; bad[2] = "http://0x7f000001/"; bad[3] = "http://0177.0.0.1/"; bad[4] = "http://user:pass@host/"; bad[5] = "http://host./"; bad[6] = "http://-host/"; bad[7] = "http://host-/"; bad[8] = "http://a..b/"; bad[9] = "http://a_b/"; bad[10] = "http://%68ost/"; bad[11] = "ftp://host/"; bad[12] = "//host/"; bad[13] = "http:///path";
  var i: int32 = 0; while i < bad.length { client_assert(HttpUrl.Parse(bad[i]).IsErr(), bad[i]); i = i+1; }
}
@test(tag = "http_core")
func test_http_url_controls_limits_and_default_value() {
  var high: <int8>[13] = <int8>[13]{}; let prefix: string = "http://host/"; var j: int32 = 0; while j < 12 { high[j] = prefix[j] as int8; j = j+1; } high[12] = -1 as int8;
  client_assert(HttpUrl.Parse("http://host/a b").IsErr() && HttpUrl.Parse("http://host/\r\nX: y").IsErr() && HttpUrl.Parse("http://host\\evil/").IsErr() && HttpUrl.Parse(string.ViewFrom(&high[0], 13)).IsErr(), "raw spaces, controls, backslash and high octets rejected");
  var text: StringBuffer = StringBuffer.New(); text.Append("http://host/"); var i: int32 = 12; while i < 8192 { text.Append("a"); i = i+1; }
  let limit: string = text.Take(); client_assert(HttpUrl.Parse(limit).IsOk() && HttpUrl.Parse(limit.Concat("a")).IsErr(), "8192-byte URL cap exact");
  let empty: HttpUrl = HttpUrl{}; client_assert(!empty.IsValid() && empty.Host().length == 0 && empty.Target().length == 0 && empty.Port() == 0 && empty.RequestHead("GET", new <HttpField>[0], 0u64).IsErr(), "invalid default remains harmless");
}
@test(tag = "http_core")
func test_http_url_owned_and_generated_request() {
  var source: <int8>[40] = <int8>[40]{}; let seed: string = "http://EXAMPLE.com:8080/a?q#frag"; var i: int32 = 0;
  while i < seed.length { source[i] = seed[i] as int8; i = i+1; }
  let url: HttpUrl = url_test(string.ViewFrom(&source[0], seed.length)); source[7] = 'Z';
  var fields: owned <HttpField>[] = new <HttpField>[1]; fields[0] = HttpField{name: "X-Test", value: "kept"};
  let made: Result<NetBuffer, HttpError> = url.RequestHead("POST", fields, 18446744073709551615u64);
  client_assert(made.IsOk() && url.Host().Equal("example.com"), "URL owns source bytes and serializes full uint64 without overflow");
  let buffer: NetBuffer = (made.get_if<NetBuffer>()) as NetBuffer;
  client_assert(string.ViewFrom(buffer.Bytes().Data() as *const int8, buffer.Len() as int32).Equal("POST /a?q HTTP/1.1\r\nHost: example.com:8080\r\nContent-Length: 18446744073709551615\r\nX-Test: kept\r\n\r\n"), "request routing/framing derived only from validated URL");
}
@test(tag = "http_core")
func test_http_url_reserved_fields_and_request_injection() {
  let url: HttpUrl = url_test("http://localhost/");
  var names: owned <string>[] = new <string>[5]; names[0] = "hOsT"; names[1] = "content-length"; names[2] = "Transfer-Encoding"; names[3] = "Expect"; names[4] = "Upgrade"; var i: int32 = 0;
  while i < names.length { var fields: owned <HttpField>[] = new <HttpField>[1]; fields[0] = HttpField{name: names[i], value: "x"}; client_assert(url.RequestHead("GET", fields, 0u64).IsErr(), "caller cannot override URL association or unsupported negotiation"); i = i+1; }
  var fields: owned <HttpField>[] = new <HttpField>[1]; fields[0] = HttpField{name: "X", value: "a\r\nHost: evil"};
  client_assert(url.RequestHead("CONNECT", new <HttpField>[0], 0u64).IsErr() && url.RequestHead("GET\r\nInjected", new <HttpField>[0], 0u64).IsErr() && url.RequestHead("GET", fields, 0u64).IsErr(), "method/header injection rejected by shared writer");
}
@test(tag = "http_core")
func test_http_url_dial_and_open_preflight_controls() {
  var resolver: AsyncResolver = AsyncResolver{};
  var token: NetCancellation = NetCancellation.New(); token.Cancel();
  let options: NetOperationOptions = NetOperationOptions{cancellation: token};
  let url: HttpUrl = url_test("http://127.0.0.1:1/");
  var made: Result<TcpConnection, HttpClientError> = url.Dial(resolver, HttpDialOptions{}, options);
  client_assert(made.IsErr(), "cancelled URL dial fails before connection attempt");
  let error: HttpClientError = (made.get_if<HttpClientError>()) as HttpClientError;
  client_assert(error.stage == HttpClientStage.Resolve && error.transport_error != nil && (error.transport_error as NetError).kind == NetErrorKind.Cancelled && error.stats.request_bytes_sent == 0u64, "cancel cause/stage preserved before any request bytes");
  client_assert(HttpTcpClient.Open(url_test("https://localhost/"), "GET", new <HttpField>[0], NetBuffer{}, HttpClientLimits{}, resolver, HttpDialOptions{}, NetOperationOptions{}).IsErr(), "plain factory cannot downgrade https");
  var fields: owned <HttpField>[] = new <HttpField>[1]; fields[0] = HttpField{name: "Host", value: "evil"};
  client_assert(HttpTcpClient.Open(url, "GET", fields, NetBuffer{}, HttpClientLimits{}, resolver, HttpDialOptions{}, NetOperationOptions{}).IsErr(), "routing override rejected before DNS/connect");
  made = url.Dial(resolver, HttpDialOptions{family: IpFamily.V6}, NetOperationOptions{});
  client_assert(made.IsErr() && (((made.get_if<HttpClientError>()) as HttpClientError).transport_error as NetError).kind == NetErrorKind.UnsupportedFamily, "numeric family mismatch rejected without DNS");
}
