/** @brief Streaming body boundaries, bounded framing and caller-owned output. */
part of HttpProtocol;
func http_test_body(wire: ref string, limits: ref HttpBodyLimits) -> HttpBodyDecoder {
  let head: HttpHead = http_test_head(true, "GET", wire);
  var made: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(head, limits);
  http_test_assert(made.IsOk(), "body construction succeeds");
  return move((made.get_if<HttpBodyDecoder>()) as HttpBodyDecoder);
}
@test(tag = "http_core")
func test_http_body_fixed_smoke() {
  var decoder: HttpBodyDecoder = http_test_body("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n", HttpBodyLimits{});
  var storage: <uint8>[8] = <uint8>[8]{};
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut storage[0], 8 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  let fed: Result<HttpBodyProgress, HttpError> = decoder.Push(NetBytes.FromString("abcNEXT"), output);
  http_test_assert(fed.IsOk(), "fixed body decode succeeds");
  if fed.IsOk() {
    let step: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
    http_test_assert(step.consumed == (3 as intptr) && step.produced == (3 as intptr) && step.state == HttpBodyState.Complete && storage[0] == 97u8 && storage[2] == 99u8, "fixed boundary preserves pipeline");
  }
  http_test_assert(decoder.EndInput().IsOk(), "complete fixed body survives EOF");
}
func http_test_body_feed(decoder: ref mut HttpBodyDecoder, wire: ref string) -> string {
  var result: StringBuffer = StringBuffer.New(); var used: intptr = 0 as intptr;
  var storage: <uint8>[3] = <uint8>[3]{};
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut storage[0], 3 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  while used < wire.length as intptr && !decoder.IsComplete() {
    let input: NetBytes = (NetBytes.FromString(wire).Slice(used, wire.length as intptr-used).get_if<NetBytes>()) as NetBytes;
    let fed: Result<HttpBodyProgress, HttpError> = decoder.Push(input, output);
    http_test_assert(fed.IsOk(), "fragment decoding succeeds"); if fed.IsErr() { return result.Take(); }
    let step: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
    http_test_assert(step.consumed > (0 as intptr), "available input and output advance the decoder");
    if step.consumed == (0 as intptr) { return result.Take(); }
    if step.produced > (0 as intptr) { result.Append(string.ViewFrom(&storage[0] as *const int8, step.produced as int32)); }
    used = used+step.consumed;
  }
  return result.Take();
}
func http_test_body_reject(wire: ref string, limits: ref HttpBodyLimits, expected: HttpErrorKind) -> void {
  var decoder: HttpBodyDecoder = http_test_body("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", limits);
  var storage: <uint8>[1] = <uint8>[1]{};
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut storage[0], 1 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  var used: intptr = 0 as intptr; var rejected: bool = false;
  while used < wire.length as intptr && !decoder.IsComplete() {
    storage[0] = 165u8;
    let input: NetBytes = (NetBytes.FromString(wire).Slice(used, wire.length as intptr-used).get_if<NetBytes>()) as NetBytes;
    let fed: Result<HttpBodyProgress, HttpError> = decoder.Push(input, output);
    if fed.IsErr() {
      rejected = true; let error: HttpError = (fed.get_if<HttpError>()) as HttpError;
      http_test_assert(error.kind == expected && storage[0] == 165u8, "error kind matches and error call leaves output untouched");
      let retry: Result<HttpBodyProgress, HttpError> = decoder.Push(NetBytes.FromString("0\r\n\r\n"), output);
      http_test_assert(retry.IsErr() && decoder.EndInput().IsErr() && decoder.TrailerCount().IsErr() && !decoder.IsComplete(), "body failures remain terminal");
      if retry.IsErr() { http_test_assert(((retry.get_if<HttpError>()) as HttpError).offset == error.offset, "terminal body cursor is stable"); }
      break;
    }
    let step: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
    if step.consumed == (0 as intptr) { break; }
    used = used+step.consumed;
  }
  http_test_assert(rejected, "invalid chunk wire is rejected");
}
@test(tag = "http_core")
func test_http_body_chunked_every_split() {
  let wire: string = "3; name = \"a\\\"b\";flag\r\nabc\r\n2\r\nde\r\n0;done\r\nX-Hash: one\r\nX-Hash: two\r\n\r\n";
  var split: int32 = 0;
  while split <= wire.length {
    var decoder: HttpBodyDecoder = http_test_body("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", HttpBodyLimits{});
    let first: string = http_test_body_feed(decoder, wire.Substring(0, split));
    let last: string = http_test_body_feed(decoder, wire.Substring(split, wire.length-split));
    http_test_assert(first.Concat(last).Equal("abcde") && decoder.IsComplete() && decoder.EndInput().IsOk(), "every split decodes the same body");
    let count: Result<int32, HttpError> = decoder.TrailerCount();
    http_test_assert(count.IsOk() && ((count.get_if<int32>()) as int32) == 2, "trailers complete separately from head");
    let field: HttpField = (decoder.TrailerAt(1).get_if<HttpField>()) as HttpField;
    http_test_assert(field.name.Equal("X-Hash") && field.value.Equal("two"), "ordinary duplicate trailer order is preserved");
    split = split+1;
  }
}
@test(tag = "http_core")
func test_http_body_backpressure_and_pipeline() {
  var decoder: HttpBodyDecoder = http_test_body("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", HttpBodyLimits{});
  let empty: NetMutableBytes = NetMutableBytes{};
  let fed: Result<HttpBodyProgress, HttpError> = decoder.Push(NetBytes.FromString("3\r\nabc\r\n0\r\n\r\nNEXT"), empty);
  http_test_assert(fed.IsOk(), "zero output consumes metadata only");
  let step: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
  http_test_assert(step.consumed == (3 as intptr) && step.produced == (0 as intptr) && step.state == HttpBodyState.NeedOutput, "chunk payload waits for caller capacity");
  http_test_assert(decoder.TrailerCount().IsErr(), "pending trailer query does not poison body");
  var storage: <uint8>[8] = <uint8>[8]{};
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut storage[0], 8 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  let copied: HttpBodyProgress = (decoder.Push(NetBytes.FromString("abc\r\n0\r\n\r\nNEXT"), output).get_if<HttpBodyProgress>()) as HttpBodyProgress;
  http_test_assert(copied.consumed == (3 as intptr) && copied.produced == (3 as intptr), "payload call returns before validating following delimiter");
  let final: HttpBodyProgress = (decoder.Push(NetBytes.FromString("\r\n0\r\n\r\nNEXT"), empty).get_if<HttpBodyProgress>()) as HttpBodyProgress;
  http_test_assert(final.consumed == (7 as intptr) && final.produced == (0 as intptr) && final.state == HttpBodyState.Complete, "metadata completes without consuming pipeline suffix");
  let again: HttpBodyProgress = (decoder.Push(NetBytes.FromString("NEXT"), output).get_if<HttpBodyProgress>()) as HttpBodyProgress;
  http_test_assert(again.consumed == (0 as intptr) && again.produced == (0 as intptr), "completed body consumes nothing");
}
@test(tag = "http_core")
func test_http_body_fixed_every_split_and_eof() {
  var split: int32 = 0;
  while split <= 5 {
    var decoder: HttpBodyDecoder = http_test_body("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", HttpBodyLimits{});
    let first: string = http_test_body_feed(decoder, "abcde".Substring(0, split));
    let last: string = http_test_body_feed(decoder, "abcde".Substring(split, 5-split));
    http_test_assert(first.Concat(last).Equal("abcde") && decoder.EndInput().IsOk(), "fixed fragments finish exactly");
    var truncated: HttpBodyDecoder = http_test_body("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n", HttpBodyLimits{});
    http_test_body_feed(truncated, "abcde".Substring(0, split));
    let eof: Result<bool, HttpError> = truncated.EndInput();
    http_test_assert(eof.IsErr() && ((eof.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.UnexpectedEof, "fixed EOF never silently completes short bodies");
    split = split+1;
  }
}
@test(tag = "http_core")
func test_http_body_chunked_eof_every_prefix() {
  let wire: string = "1;x=y\r\na\r\n0\r\nX-End: yes\r\n\r\n"; var i: int32 = 0;
  while i < wire.length {
    var decoder: HttpBodyDecoder = http_test_body("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", HttpBodyLimits{});
    http_test_body_feed(decoder, wire.Substring(0, i));
    let eof: Result<bool, HttpError> = decoder.EndInput();
    http_test_assert(eof.IsErr() && ((eof.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.UnexpectedEof && decoder.TrailerAt(0).IsErr(), "every incomplete chunk/trailer prefix fails at EOF"); i = i+1;
  }
}
@test(tag = "http_core")
func test_http_body_eof_delimited_and_budget() {
  var decoder: HttpBodyDecoder = http_test_body("HTTP/1.0 200 OK\r\n\r\n", HttpBodyLimits{max_body_bytes: 3u64});
  http_test_assert(http_test_body_feed(decoder, "abc").Equal("abc") && !decoder.IsComplete(), "EOF body waits for actual EOF at exact decoded cap");
  http_test_assert(decoder.EndInput().IsOk() && decoder.IsComplete(), "exact body cap can finish at EOF");
  var exceeded: HttpBodyDecoder = http_test_body("HTTP/1.0 200 OK\r\n\r\n", HttpBodyLimits{max_body_bytes: 3u64});
  http_test_body_feed(exceeded, "abc");
  let fed: Result<HttpBodyProgress, HttpError> = exceeded.Push(NetBytes.FromString("d"), NetMutableBytes{});
  http_test_assert(fed.IsErr() && ((fed.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.LimitExceeded, "extra EOF body data fails even without output space");
}
@test(tag = "http_core")
func test_http_body_size_and_extension_rejection() {
  http_test_body_reject("10000000000000000\r\n", HttpBodyLimits{}, HttpErrorKind.InvalidFraming);
  http_test_body_reject("ffffffffffffffff\r\n", HttpBodyLimits{}, HttpErrorKind.LimitExceeded);
  http_test_body_reject("+1\r\n", HttpBodyLimits{}, HttpErrorKind.Malformed);
  http_test_body_reject(" 1\r\n", HttpBodyLimits{}, HttpErrorKind.Malformed);
  http_test_body_reject("1 \r\n", HttpBodyLimits{}, HttpErrorKind.Malformed);
  http_test_body_reject("1;\r\n", HttpBodyLimits{}, HttpErrorKind.Malformed);
  http_test_body_reject("1;x=\r\n", HttpBodyLimits{}, HttpErrorKind.Malformed);
  http_test_body_reject("1;x=\"open\r\n", HttpBodyLimits{}, HttpErrorKind.Malformed);
  http_test_body_reject("1;x=\"a\"oops\r\n", HttpBodyLimits{}, HttpErrorKind.Malformed);
  http_test_body_reject("1;x=\"a\tb\"\r\naX", HttpBodyLimits{}, HttpErrorKind.Malformed);
  http_test_body_reject("1\na", HttpBodyLimits{}, HttpErrorKind.Malformed);
  http_test_body_reject("1\rXa", HttpBodyLimits{}, HttpErrorKind.Malformed);
  http_test_body_reject("1\r\na\rX", HttpBodyLimits{}, HttpErrorKind.Malformed);
}
@test(tag = "http_core")
func test_http_body_cumulative_limits() {
  http_test_body_reject("2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n", HttpBodyLimits{max_body_bytes: 3u64}, HttpErrorKind.LimitExceeded);
  http_test_body_reject("1;x=long\r\na\r\n0\r\n\r\n", HttpBodyLimits{max_line_bytes: 7}, HttpErrorKind.LimitExceeded);
  http_test_body_reject("1\r\na\r\n1\r\nb\r\n0\r\n\r\n", HttpBodyLimits{max_framing_bytes: 14}, HttpErrorKind.LimitExceeded);
  http_test_body_reject("0\r\nX: a\r\nY: b\r\n\r\n", HttpBodyLimits{max_trailers: 1}, HttpErrorKind.LimitExceeded);
  var exact: HttpBodyDecoder = http_test_body("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", HttpBodyLimits{max_body_bytes: 1u64, max_framing_bytes: 10, max_line_bytes: 1});
  http_test_assert(http_test_body_feed(exact, "1\r\na\r\n0\r\n\r\n").Equal("a") && exact.IsComplete(), "exact cumulative framing and body caps succeed");
}
@test(tag = "http_core")
func test_http_body_forbidden_and_malformed_trailers() {
  http_test_body_reject("0\r\nContent-Length: 0\r\n\r\n", HttpBodyLimits{}, HttpErrorKind.InvalidFraming);
  http_test_body_reject("0\r\ntRaNsFeR-EnCoDiNg: chunked\r\n\r\n", HttpBodyLimits{}, HttpErrorKind.InvalidFraming);
  http_test_body_reject("0\r\nHost: x\r\n\r\n", HttpBodyLimits{}, HttpErrorKind.InvalidFraming);
  http_test_body_reject("0\r\nConnection: close\r\n\r\n", HttpBodyLimits{}, HttpErrorKind.InvalidFraming);
  http_test_body_reject("0\r\nAuthorization: secret\r\n\r\n", HttpBodyLimits{}, HttpErrorKind.InvalidFraming);
  http_test_body_reject("0\r\nContent-Type: text/plain\r\n\r\n", HttpBodyLimits{}, HttpErrorKind.InvalidFraming);
  http_test_body_reject("0\r\nSet-Cookie: a=b\r\n\r\n", HttpBodyLimits{}, HttpErrorKind.InvalidFraming);
  http_test_body_reject("0\r\n Bad: value\r\n\r\n", HttpBodyLimits{}, HttpErrorKind.Malformed);
  http_test_body_reject("0\r\nBad : value\r\n\r\n", HttpBodyLimits{}, HttpErrorKind.Malformed);
  http_test_body_reject("0\r\nBad: a\r\n folded\r\n\r\n", HttpBodyLimits{}, HttpErrorKind.Malformed);
  var nominated: HttpBodyDecoder = http_test_body("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: x-private\r\n\r\n", HttpBodyLimits{});
  let fed: Result<HttpBodyProgress, HttpError> = nominated.Push(NetBytes.FromString("0\r\nX-Private: a\r\n\r\n"), NetMutableBytes{});
  http_test_assert(fed.IsErr() && ((fed.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.InvalidFraming, "connection-nominated trailer names cannot cross into application metadata");
}
@test(tag = "http_core")
func test_http_body_construction_and_handoffs() {
  let fixed: HttpHead = http_test_head(true, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n");
  var oversized: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(fixed, HttpBodyLimits{});
  http_test_assert(oversized.IsErr() && ((oversized.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.LimitExceeded, "oversized fixed body rejected before any payload allocation");
  let none: HttpHead = http_test_head(true, "HEAD", "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n");
  var made: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(none, HttpBodyLimits{});
  http_test_assert(made.IsOk(), "HEAD metadata length does not become a body budget");
  var decoder: HttpBodyDecoder = move((made.get_if<HttpBodyDecoder>()) as HttpBodyDecoder);
  http_test_assert(decoder.IsComplete() && decoder.EndInput().IsOk(), "no-body framing is complete immediately");
  let upgrade: HttpHead = http_test_head(true, "GET", "HTTP/1.1 101 Switching\r\n\r\n");
  var unsupported: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(upgrade, HttpBodyLimits{});
  http_test_assert(unsupported.IsErr() && ((unsupported.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.Unsupported, "upgrade requires explicit handoff");
  let tunnel: HttpHead = http_test_head(true, "CONNECT", "HTTP/1.1 200 OK\r\n\r\n");
  var unsupported_tunnel: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(tunnel, HttpBodyLimits{});
  http_test_assert(unsupported_tunnel.IsErr(), "tunnel bytes cannot enter a body decoder");
  var invalid: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(HttpHead{}, HttpBodyLimits{});
  http_test_assert(invalid.IsErr(), "unvalidated default head cannot select body framing");
  var caps: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(none, HttpBodyLimits{max_line_bytes: -1});
  http_test_assert(caps.IsErr(), "negative limits are rejected");
}
@test(tag = "http_core")
func test_http_body_reused_byte_move_and_owned_trailer() {
  var decoder: HttpBodyDecoder = http_test_body("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", HttpBodyLimits{});
  let wire: string = "1\r\nZ\r\n0\r\nX-Owned: kept\r\n\r\n";
  var byte: <uint8>[1] = <uint8>[1]{}; var dest: <uint8>[1] = <uint8>[1]{}; var i: int32 = 0;
  let input: NetBytes = (NetBytes.FromRaw(&byte[0], 1 as intptr).get_if<NetBytes>()) as NetBytes;
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut dest[0], 1 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  var payload: StringBuffer = StringBuffer.New();
  while i < wire.length {
    byte[0] = wire[i] as uint8;
    let fed: Result<HttpBodyProgress, HttpError> = decoder.Push(input, output);
    http_test_assert(fed.IsOk(), "reused one-byte body input accepted");
    if fed.IsErr() { return; }
    let step: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
    http_test_assert(step.consumed == (1 as intptr), "one-byte body fragments always consumed");
    if step.produced != (0 as intptr) { payload.Append(string.ViewFrom(&dest[0] as *const int8, 1)); }
    byte[0] = 0u8; dest[0] = 0u8; i = i+1;
  }
  let field: HttpField = (decoder.TrailerAt(0).get_if<HttpField>()) as HttpField;
  var moved: HttpBodyDecoder = move(decoder);
  http_test_assert(moved.IsComplete() && payload.Take().Equal("Z"), "move preserves completed payload cursor");
  moved = HttpBodyDecoder{};
  http_test_assert(field.value.Equal("kept"), "trailer strings own storage after decoder drop");
  http_test_assert(moved.Push(input, output).IsErr() && moved.EndInput().IsErr(), "default decoder is closed");
}
@test(tag = "http_core")
func test_http_body_binary_octets_and_extension_controls() {
  var decoder: HttpBodyDecoder = http_test_body("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n", HttpBodyLimits{});
  var source: <uint8>[3] = <uint8>[3]{}; source[1] = 255u8; source[2] = 127u8;
  var target: <uint8>[4] = <uint8>[4]{}; target[3] = 165u8;
  let input: NetBytes = (NetBytes.FromRaw(&source[0], 3 as intptr).get_if<NetBytes>()) as NetBytes;
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut target[0], 4 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  http_test_assert(decoder.Push(input, output).IsOk() && target[0] == 0u8 && target[1] == 255u8 && target[2] == 127u8 && target[3] == 165u8, "payload octets remain opaque and output suffix stays untouched");
  let text: string = "0;x=\"a\"\r\n\r\n";
  var bytes: owned <uint8>[] = new <uint8>[text.length]; var i: int32 = 0;
  while i < text.length { bytes[i] = text[i] as uint8; i = i+1; }
  let span: NetBytes = (NetBytes.FromRaw(&bytes[0], text.length as intptr).get_if<NetBytes>()) as NetBytes;
  var control: int32 = 0;
  while control < 2 {
    bytes[5] = 0u8; if control == 1 { bytes[5] = 127u8; }
    var invalid: HttpBodyDecoder = http_test_body("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", HttpBodyLimits{});
    let fed: Result<HttpBodyProgress, HttpError> = invalid.Push(span, output);
    http_test_assert(fed.IsErr() && ((fed.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.Malformed, "quoted chunk extensions reject NUL and DEL"); control = control+1;
  }
  bytes[5] = 255u8;
  var opaque: HttpBodyDecoder = http_test_body("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", HttpBodyLimits{});
  http_test_assert(opaque.Push(span, output).IsOk() && opaque.IsComplete(), "quoted extension obs-text remains valid opaque data");
}
