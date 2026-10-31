// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of HttpProtocolTests;

/** @brief Controlled fragmented HTTP head and serialization contracts. */


static method(HttpHeadParser) TestNew(response: bool, verb: ref string, limits: ref HttpHeadLimits) -> HttpHeadParser {
  var made: Result<HttpHeadParser, HttpError> = HttpHeadParser.NewParser(response, verb, limits);
  AssertTrueMsg(made.IsOk(), "parser construction succeeds");

  return move((made.get_if<HttpHeadParser>()) as HttpHeadParser);
}

static method(HttpHead) TestParse(response: bool, verb: ref string, wire: ref string) -> HttpHead {
  var parser: HttpHeadParser = HttpHeadParser.TestNew(response, verb, HttpHeadLimits{});
  let fed: Result<intptr, HttpError> = parser.Push(NetBytes.FromString(wire));
  AssertTrueMsg(fed.IsOk() && parser.IsComplete(), "complete valid head is accepted");
  let head: Result<HttpHead, HttpError> = parser.Head();
  AssertTrueMsg(head.IsOk(), "head metadata is published");

  return (head.get_if<HttpHead>()) as HttpHead;
}

@test(tag = "http_core")
func test_http_request_smoke() {
  let head: HttpHead = HttpHead.TestParse(false, "", "GET /hello?q=x HTTP/1.1\r\nHost: example.test\r\n\r\n");
  AssertTrueMsg(
    head.Method().Equal("GET") && head.Target().Equal("/hello?q=x") && head.FieldCount() == 1,
    "request metadata survives parser drop"
  );
  let plan: HttpBodyPlan = (head.BodyPlan().get_if<HttpBodyPlan>()) as HttpBodyPlan;
  AssertTrueMsg(
    plan.kind == HttpBodyKind.None && !plan.close_connection,
    "request without framing has no body"
  );
}

// Immutable fixture inputs and expected protocol result.
struct HttpHeadRejectCase {
  readonly response: bool;
  readonly wire: string;
  readonly expected: HttpErrorKind;
}

method(HttpHeadRejectCase) Run() -> void {
  let response: bool = self.response;
  let wire: string = self.wire;
  let expected: HttpErrorKind = self.expected;

  var parser: HttpHeadParser = HttpHeadParser.TestNew(response, "GET", HttpHeadLimits{});
  let fed: Result<intptr, HttpError> = parser.Push(NetBytes.FromString(wire));
  AssertTrueMsg(fed.IsErr(), "invalid wire is rejected before head publication");
  if fed.IsErr() {
    let error: HttpError = (fed.get_if<HttpError>()) as HttpError;
    AssertTrueMsg(
      error.kind == expected && error.offset >(0 as int64),
      "expected named error and detection offset"
    );
    let retry: Result<intptr, HttpError> = parser.Push(
      NetBytes.FromString("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    );
    AssertTrueMsg(
      retry.IsErr() && parser.Head().IsErr() && parser.EndInput().IsErr() && !parser.IsComplete(),
      "failure is sticky and partial head stays unpublished"
    );
    if retry.IsErr() {
      AssertTrueMsg(
        ((retry.get_if<HttpError>()) as HttpError).offset == error.offset,
        "terminal cursor does not advance"
      );
    }
  }
}

// Immutable fixture inputs and expected protocol result.
struct HttpBodyPlanCase {
  readonly verb: string;
  readonly wire: string;
  readonly kind: HttpBodyKind;
  readonly size: uint64;
  readonly close: bool;
}

method(HttpBodyPlanCase) Run() -> void {
  let verb: string = self.verb;
  let wire: string = self.wire;
  let kind: HttpBodyKind = self.kind;
  let size: uint64 = self.size;
  let close: bool = self.close;

  let head: HttpHead = HttpHead.TestParse(true, verb, wire);
  let plan: HttpBodyPlan = (head.BodyPlan().get_if<HttpBodyPlan>()) as HttpBodyPlan;
  AssertTrueMsg(
    plan.kind == kind && plan.length == size && plan.close_connection == close,
    "body selection and connection persistence match request context"
  );
}

@test(tag = "http_core")
func test_http_every_split_preserves_body_suffix() {
  let wire: string = "POST /a%20b?q=1 HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\n";
  var split: int32 = 0;
  while split <= wire.length {
    var parser: HttpHeadParser = HttpHeadParser.TestNew(false, "", HttpHeadLimits{});
    let first: string = wire.Substring(0, split);
    let prefix: Result<intptr, HttpError> = parser.Push(NetBytes.FromString(first));
    AssertTrueMsg(
      prefix.IsOk() && ((prefix.get_if<intptr>()) as intptr) == split as intptr,
      "first fragment is consumed exactly"
    );
    if split < wire.length {
      AssertTrueMsg(parser.Head().IsErr(), "pending head query does not poison the cursor");
    }

    let tail: string = wire.Substring(split, wire.length - split).Concat("abcGET /next");
    let rest: Result<intptr, HttpError> = parser.Push(NetBytes.FromString(tail));
    AssertTrueMsg(
      rest.IsOk() && ((rest.get_if<intptr>()) as intptr) == (wire.length - split) as intptr,
      "body and pipeline bytes remain unconsumed at every split"
    );
    AssertTrueMsg(parser.IsComplete() && parser.EndInput().IsOk(), "split terminator completes once");
    let head: HttpHead = (parser.Head().get_if<HttpHead>()) as HttpHead;
    AssertTrueMsg(
      head.Target().Equal("/a%20b?q=1")
        && ((head.BodyPlan().get_if<HttpBodyPlan>()) as HttpBodyPlan).length == 3u64,
      "split metadata stays correct"
    );
    split = split + 1;
  }
}

@test(tag = "http_core")
func test_http_reused_input_and_owned_head() {
  var parser: HttpHeadParser = HttpHeadParser.TestNew(false, "", HttpHeadLimits{});
  let wire: string = "GET /stable HTTP/1.1\r\nHost: example.test\r\nX-Value: retained\r\n\r\n";
  var byte: <uint8>[1] = <uint8>[1] {
  };
  var i: int32 = 0;
  while i < wire.length {
    byte[0] = wire[i] as uint8;
    let span: NetBytes = (NetBytes.FromRaw(&byte[0], 1 as intptr).get_if<NetBytes>()) as NetBytes;
    AssertTrueMsg(parser.Push(span).IsOk(), "single-byte fragments work with reused caller storage");
    byte[0] = 0u8;
    i = i + 1;
  }

  let head: HttpHead = (parser.Head().get_if<HttpHead>()) as HttpHead;
  var moved: HttpHeadParser = move(parser);
  AssertTrueMsg(moved.Head().IsOk(), "move preserves the completed parser");
  moved = HttpHeadParser{};
  AssertTrueMsg(
    head.Target().Equal("/stable")
      && ((head.FieldAt(1).get_if<HttpField>()) as HttpField).value.Equal("retained"),
    "published head owns strings after parser destruction"
  );
  AssertTrueMsg(head.FieldAt(-1).IsErr() && head.FieldAt(2).IsErr(), "field lookup checks bounds");
}

@test(tag = "http_core")
func test_http_strict_line_and_field_syntax() {
  HttpHeadRejectCase{response: false, wire: "GET / HTTP/1.1\nHost: x\n\n", expected: HttpErrorKind.Malformed}.Run();
  HttpHeadRejectCase{response: false, wire: "GET / HTTP/1.1\rX", expected: HttpErrorKind.Malformed}.Run();
  HttpHeadRejectCase{response: false, wire: "GET / HTTP/1.1\r\n Host: x\r\n\r\n",
    expected: HttpErrorKind.Malformed}.Run();
  HttpHeadRejectCase{response: false, wire: "GET / HTTP/1.1\r\nHost : x\r\n\r\n",
    expected: HttpErrorKind.Malformed}.Run();
  HttpHeadRejectCase{response: false, wire: "GET / HTTP/1.1\r\nHost: x\r\nX: a\r\n folded\r\n\r\n",
    expected: HttpErrorKind.Malformed}.Run();
  HttpHeadRejectCase{response: false, wire: "GET\t/ HTTP/1.1\r\n\r\n", expected: HttpErrorKind.Malformed}.Run();
}

@test(tag = "http_core")
func test_http_duplicate_lengths_and_numeric_overflow() {
  HttpHeadRejectCase{response: false,
    wire: "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\ncontent-length: 1\r\n\r\n",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpHeadRejectCase{response: false,
    wire: "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpHeadRejectCase{response: true, wire: "HTTP/1.1 200 OK\r\nContent-Length: 1, 1\r\n\r\n",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpHeadRejectCase{response: true, wire: "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpHeadRejectCase{response: true, wire: "HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\n",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpHeadRejectCase{response: true, wire: "HTTP/1.1 200 OK\r\nContent-Length: 1 0\r\n\r\n",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpHeadRejectCase{response: true, wire: "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpBodyPlanCase{verb: "GET", wire: "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n",
    kind: HttpBodyKind.ContentLength, size: 18446744073709551615u64, close: false}.Run();
  HttpBodyPlanCase{verb: "GET", wire: "HTTP/1.1 200 OK\r\nContent-Length: 000\r\n\r\n",
    kind: HttpBodyKind.ContentLength, size: 0u64, close: false}.Run();
}

@test(tag = "http_core")
func test_http_transfer_encoding_conflicts() {
  HttpHeadRejectCase{response: true,
    wire: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpHeadRejectCase{response: true,
    wire: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpHeadRejectCase{response: true,
    wire: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpHeadRejectCase{response: true, wire: "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
    expected: HttpErrorKind.Unsupported}.Run();
  HttpHeadRejectCase{response: true, wire: "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpBodyPlanCase{verb: "GET", wire: "HTTP/1.1 200 OK\r\nTransfer-Encoding: ChUnKeD\r\n\r\n",
    kind: HttpBodyKind.Chunked, size: 0u64, close: false}.Run();
}

@test(tag = "http_core")
func test_http_host_validation() {
  HttpHeadRejectCase{response: false, wire: "GET / HTTP/1.1\r\n\r\n", expected: HttpErrorKind.Malformed}.Run();
  HttpHeadRejectCase{response: false, wire: "GET / HTTP/1.1\r\nHost: a\r\nhOsT: a\r\n\r\n",
    expected: HttpErrorKind.Malformed}.Run();
  HttpHeadRejectCase{response: false, wire: "GET / HTTP/1.1\r\nHost: a b\r\n\r\n",
    expected: HttpErrorKind.Malformed}.Run();
  HttpHeadRejectCase{response: false, wire: "GET / HTTP/1.1\r\nHost: a:65536\r\n\r\n",
    expected: HttpErrorKind.Malformed}.Run();
  HttpHeadRejectCase{response: false, wire: "GET / HTTP/1.1\r\nHost: user@a\r\n\r\n",
    expected: HttpErrorKind.Malformed}.Run();
  HttpHeadRejectCase{response: false, wire: "GET / HTTP/1.1\r\nHost: [127.0.0.1]\r\n\r\n",
    expected: HttpErrorKind.Malformed}.Run();
  HttpHeadRejectCase{response: false, wire: "GET / HTTP/1.1\r\nHost: [::1\r\n\r\n",
    expected: HttpErrorKind.Malformed}.Run();
  let head: HttpHead = HttpHead.TestParse(false, "", "GET / HTTP/1.1\r\nHost: [::1]:443\r\n\r\n");
  AssertTrueMsg(head.FieldCount() == 1, "bracketed IPv6 authority is accepted");
}

@test(tag = "http_core")
func test_http_response_context_and_handoffs() {
  HttpBodyPlanCase{verb: "HEAD", wire: "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n", kind: HttpBodyKind.None,
    size: 0u64, close: false}.Run();
  HttpBodyPlanCase{verb: "head", wire: "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n",
    kind: HttpBodyKind.ContentLength, size: 99u64, close: false}.Run();
  HttpBodyPlanCase{verb: "GET", wire: "HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n",
    kind: HttpBodyKind.None, size: 0u64, close: false}.Run();
  HttpBodyPlanCase{verb: "GET", wire: "HTTP/1.1 204 No Content\r\n\r\n", kind: HttpBodyKind.None, size: 0u64,
    close: false}.Run();
  HttpBodyPlanCase{verb: "GET", wire: "HTTP/1.1 100 Continue\r\n\r\n", kind: HttpBodyKind.None, size: 0u64,
    close: false}.Run();
  HttpBodyPlanCase{verb: "GET",
    wire: "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: example\r\n\r\n",
    kind: HttpBodyKind.Upgrade, size: 0u64, close: false}.Run();
  HttpBodyPlanCase{verb: "CONNECT", wire: "HTTP/1.1 200 Connection Established\r\n\r\n", kind: HttpBodyKind.Tunnel,
    size: 0u64, close: false}.Run();
  HttpHeadRejectCase{response: true, wire: "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpHeadRejectCase{response: true, wire: "HTTP/1.1 100 Continue\r\nTransfer-Encoding: chunked\r\n\r\n",
    expected: HttpErrorKind.InvalidFraming}.Run();
}

@test(tag = "http_core")
func test_http_connection_lifecycle() {
  HttpBodyPlanCase{verb: "GET", wire: "HTTP/1.1 200 OK\r\n\r\n", kind: HttpBodyKind.UntilEof, size: 0u64,
    close: true}.Run();
  HttpBodyPlanCase{verb: "GET", wire: "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
    kind: HttpBodyKind.ContentLength, size: 0u64, close: true}.Run();
  HttpBodyPlanCase{verb: "GET", wire: "HTTP/1.0 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
    kind: HttpBodyKind.ContentLength, size: 0u64, close: false}.Run();
  HttpBodyPlanCase{verb: "GET",
    wire: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\nConnection: Close\r\n\r\n",
    kind: HttpBodyKind.ContentLength, size: 0u64, close: true}.Run();
  HttpHeadRejectCase{response: true, wire: "HTTP/1.1 200 OK\r\nConnection: close,\r\n\r\n",
    expected: HttpErrorKind.Malformed}.Run();
}

@test(tag = "http_core")
func test_http_ordinary_duplicates_and_ows() {
  let head: HttpHead = HttpHead.TestParse(
    true,
    "GET",
    "HTTP/1.1 200 \r\nSet-Cookie: a=1\r\nSet-Cookie:\tb=2 \t\r\nContent-Length: 0\r\n\r\n"
  );
  let first: HttpField = (head.FieldAt(0).get_if<HttpField>()) as HttpField;
  let second: HttpField = (head.FieldAt(1).get_if<HttpField>()) as HttpField;
  AssertTrueMsg(
    head.Reason().length == 0 && head.Status() == 200 && head.IsResponse(),
    "empty reason is valid"
  );
  AssertTrueMsg(
    first.name.Equal("Set-Cookie") && first.value.Equal("a=1") && second.value.Equal("b=2"),
    "ordered duplicate fields stay separate and outer OWS trims"
  );
}

@test(tag = "http_core")
func test_http_limits_and_exact_boundaries() {
  let wire: string = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
  var exact: HttpHeadParser = HttpHeadParser.TestNew(
    false,
    "",
    HttpHeadLimits{max_head_bytes: wire.length, max_line_bytes: 14, max_fields: 1}
  );
  AssertTrueMsg(
    exact.Push(NetBytes.FromString(wire)).IsOk() && exact.IsComplete(),
    "exact byte/line/field bounds accept"
  );
  var short: HttpHeadParser = HttpHeadParser.TestNew(false, "", HttpHeadLimits{max_head_bytes: wire.length - 1});
  AssertTrueMsg(short.Push(NetBytes.FromString(wire)).IsErr(), "one byte below complete head fails");
  var line: HttpHeadParser = HttpHeadParser.TestNew(false, "", HttpHeadLimits{max_line_bytes: 13});
  AssertTrueMsg(line.Push(NetBytes.FromString(wire)).IsErr(), "one byte below request line fails");
  var fields: HttpHeadParser = HttpHeadParser.TestNew(false, "", HttpHeadLimits{max_fields: 1});
  AssertTrueMsg(
    fields.Push(NetBytes.FromString("GET / HTTP/1.1\r\nHost: x\r\nX: y\r\n\r\n")).IsErr(),
    "field count is bounded"
  );
  AssertTrueMsg(
    HttpHeadParser.NewRequest(HttpHeadLimits{max_fields: 129}).IsErr()
      && HttpHeadParser.NewRequest(HttpHeadLimits{max_head_bytes: -1}).IsErr(),
    "invalid configuration is rejected"
  );
  AssertTrueMsg(
    HttpHeadParser.NewResponse("GET /", HttpHeadLimits{}).IsErr(),
    "response request context must be a token"
  );
}

@test(tag = "http_core")
func test_http_eof_at_every_prefix() {
  let wire: string = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
  var end: int32 = 0;
  while end < wire.length {
    var parser: HttpHeadParser = HttpHeadParser.TestNew(true, "GET", HttpHeadLimits{});
    AssertTrueMsg(
      parser.Push(NetBytes.FromString(wire.Substring(0, end))).IsOk(),
      "prefix is pending, not malformed"
    );
    let closed: Result<HttpHead, HttpError> = parser.EndInput();
    AssertTrueMsg(
      closed.IsErr() && ((closed.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.UnexpectedEof,
      "EOF before every terminator boundary is terminal"
    );
    AssertTrueMsg(parser.Push(NetBytes.FromString(wire)).IsErr(), "EOF cursor cannot be reused");
    end = end + 1;
  }
}

@test(tag = "http_core")
func test_http_target_and_version_profile() {
  let options: HttpHead = HttpHead.TestParse(false, "", "OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n");
  AssertTrueMsg(
    options.Target().Equal("*") && options.MinorVersion() == 1,
    "OPTIONS asterisk form supported"
  );
  HttpHeadRejectCase{response: false, wire: "GET http://example.test/ HTTP/1.1\r\nHost: x\r\n\r\n",
    expected: HttpErrorKind.Unsupported}.Run();
  HttpHeadRejectCase{response: false, wire: "GET /a#fragment HTTP/1.1\r\nHost: x\r\n\r\n",
    expected: HttpErrorKind.Unsupported}.Run();
  HttpHeadRejectCase{response: false, wire: "GET /bad%xx HTTP/1.1\r\nHost: x\r\n\r\n",
    expected: HttpErrorKind.Unsupported}.Run();
  HttpHeadRejectCase{response: false, wire: "GET / HTTP/2.0\r\nHost: x\r\n\r\n",
    expected: HttpErrorKind.Unsupported}.Run();
  HttpHeadRejectCase{response: true, wire: "HTTP/1.1 600 Nope\r\n\r\n", expected: HttpErrorKind.Malformed}.Run();
  HttpHeadRejectCase{response: true, wire: "HTTP/1.1 20 OK\r\n\r\n", expected: HttpErrorKind.Malformed}.Run();
}

@test(tag = "http_core")
func test_http_writer_request_roundtrip_and_ownership() {
  var fields: owned <HttpField>[] = new <HttpField>[2];
  fields[0] = HttpField{name: "Host", value: "example.test"};
  fields[1] = HttpField{name: "Content-Length", value: "3"};
  let made: Result<NetBuffer, HttpError> = HttpHead.EncodeRequest("POST", "/resource", fields);
  AssertTrueMsg(made.IsOk(), "writer creates a valid request");
  let buffer: NetBuffer = (made.get_if<NetBuffer>()) as NetBuffer;
  fields[0] = HttpField{name: "Bad", value: "changed"};
  let bytes: NetBytes = buffer.Bytes();
  let wire: string = string.ViewFrom(bytes.Data() as *const int8, bytes.Len() as int32);
  AssertTrueMsg(
    wire.Equal("POST /resource HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\n"),
    "writer owns the exact head and appends no body"
  );
  let head: HttpHead = HttpHead.TestParse(false, "", wire);
  AssertTrueMsg(
    head.Method().Equal("POST") && head.Target().Equal("/resource"),
    "serialized request reparses"
  );
}

@test(tag = "http_core")
func test_http_writer_response_roundtrip() {
  var fields: owned <HttpField>[] = new <HttpField>[1];
  fields[0] = HttpField{name: "Content-Length", value: "12"};
  let made: Result<NetBuffer, HttpError> = HttpHead.EncodeResponse(200, "OK", fields, "HEAD");
  AssertTrueMsg(made.IsOk(), "writer creates response metadata");
  let bytes: NetBytes = ((made.get_if<NetBuffer>()) as NetBuffer).Bytes();
  let wire: string = string.ViewFrom(bytes.Data() as *const int8, bytes.Len() as int32);
  HttpBodyPlanCase{verb: "HEAD", wire: wire, kind: HttpBodyKind.None, size: 0u64, close: false}.Run();
  AssertTrueMsg(
    wire.Equal("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n"),
    "status digits and reason are canonical"
  );
  AssertTrueMsg(
    HttpHead.EncodeResponse(204, "No Content", fields, "GET").IsErr(),
    "writer cannot emit framing forbidden for status"
  );
}

@test(tag = "http_core")
func test_http_writer_injection_and_framing_rejection() {
  var fields: owned <HttpField>[] = new <HttpField>[1];
  fields[0] = HttpField{name: "Host", value: "x\r\nInjected: yes"};
  AssertTrueMsg(
    HttpHead.EncodeRequest("GET", "/", fields).IsErr(),
    "writer rejects CRLF in values before emitting"
  );
  fields[0] = HttpField{name: "Host\r\nInjected", value: "x"};
  AssertTrueMsg(HttpHead.EncodeRequest("GET", "/", fields).IsErr(), "writer rejects injected names");
  fields[0] = HttpField{name: "Host", value: "x"};
  AssertTrueMsg(
    HttpHead.EncodeRequest("GE T", "/", fields).IsErr() && HttpHead.EncodeRequest("GET", "/a b", fields).IsErr(),
    "writer rejects unsafe start line inputs"
  );
  AssertTrueMsg(
    HttpHead.EncodeResponse(200, "OK\r\nX: y", fields, "GET").IsErr(),
    "writer rejects reason injection"
  );
  var conflict: owned <HttpField>[] = new <HttpField>[3];
  conflict[0] = HttpField{name: "Host", value: "x"};
  conflict[1] = HttpField{name: "Content-Length", value: "0"};
  conflict[2] = HttpField{name: "Transfer-Encoding", value: "chunked"};
  AssertTrueMsg(
    HttpHead.EncodeRequest("POST", "/", conflict).IsErr(),
    "writer shares parser framing-conflict rules"
  );
}

@test(tag = "http_core")
func test_http_writer_limits_and_defaults() {
  var fields: owned <HttpField>[] = new <HttpField>[101];
  var i: int32 = 0;
  while i < 101 {
    fields[i] = HttpField{name: "X", value: "y"};
    i = i + 1;
  }

  AssertTrueMsg(
    HttpHead.EncodeRequest("GET", "/", fields).IsErr(),
    "writer caps fields before constructing wire"
  );
  var empty: HttpHeadParser = HttpHeadParser{};
  AssertTrueMsg(
    empty.Push(NetBytes{}).IsErr() && empty.Head().IsErr() && empty.EndInput().IsErr(),
    "default parser has no resource"
  );
  let head: HttpHead = HttpHead{};
  AssertTrueMsg(
    head.MinorVersion() == -1 && head.FieldCount() == 0 && head.BodyPlan().IsErr(),
    "default head is not a valid empty message"
  );
}

@test(tag = "http_core")
func test_http_binary_controls_and_obs_text() {
  let wire: string = "GET / HTTP/1.1\r\nHost: x\r\nX: a!b\r\n\r\n";
  var bytes: owned <uint8>[] = new <uint8>[wire.length];
  var i: int32 = 0;
  while i < wire.length {
    bytes[i] = wire[i] as uint8;
    i = i + 1;
  }

  let position: int32 = wire.Find("!");
  let span: NetBytes = (NetBytes.FromRaw(&bytes[0], wire.length as intptr).get_if<NetBytes>()) as NetBytes;
  var nul: HttpHeadParser = HttpHeadParser.TestNew(false, "", HttpHeadLimits{});
  bytes[position] = 0u8;
  AssertTrueMsg(nul.Push(span).IsErr() && !nul.IsComplete(), "actual NUL bytes are rejected");
  var del: HttpHeadParser = HttpHeadParser.TestNew(false, "", HttpHeadLimits{});
  bytes[position] = 127u8;
  AssertTrueMsg(del.Push(span).IsErr(), "DEL is rejected");
  var obs: HttpHeadParser = HttpHeadParser.TestNew(false, "", HttpHeadLimits{});
  bytes[position] = 255u8;
  AssertTrueMsg(
    obs.Push(span).IsOk() && obs.IsComplete(),
    "field obs-text is opaque bytes rather than UTF-8 decoding"
  );
  bytes[position] = 0u8;
  let head: HttpHead = (obs.Head().get_if<HttpHead>()) as HttpHead;
  let value: string = ((head.FieldAt(1).get_if<HttpField>()) as HttpField).value;
  AssertTrueMsg(
    value.length == 3 && (value[1] as uint8) == 255u8,
    "owned field preserves opaque octets independently of input"
  );
}
