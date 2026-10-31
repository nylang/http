// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of HttpClientTests;

/** @brief Shared client exchange ownership and exact acknowledgement. */


static method(NetBuffer) HttpTestFromString(text: ref string) -> NetBuffer {
  let result: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(NetBytes.FromString(text));
  AssertTrueMsg(result.IsOk(), "buffer allocation succeeds");

  return (result.get_if<NetBuffer>()) as NetBuffer;
}

@test(tag = "http_core")
func test_http_client_exchange_smoke() {
  let head: NetBuffer = NetBuffer.HttpTestFromString("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
  var made: Result<HttpClientExchange, HttpError> = HttpClientExchange.New(
    head,
    NetBuffer{},
    HttpClientLimits{}
  );
  AssertTrueMsg(made.IsOk(), "exchange constructed");
  var exchange: HttpClientExchange = move((made.get_if<HttpClientExchange>()) as HttpClientExchange);
  let output: NetBuffer = (exchange.Output().get_if<NetBuffer>()) as NetBuffer;
  AssertTrueMsg(
    output.Len() == head.Len() && !exchange.RequestComplete(),
    "unacknowledged head stays pending"
  );
  AssertTrueMsg(
    exchange.AcknowledgeOutput(output.Len()).IsOk() && exchange.RequestComplete(),
    "head acknowledgement completes empty request"
  );
  AssertTrueMsg(
    exchange.Receive(NetBuffer.HttpTestFromString("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"), false).IsOk(),
    "response input admitted"
  );
  let event: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  AssertTrueMsg(
    event.kind == HttpClientEventKind.Head && event.head.Status() == 200,
    "response head event published"
  );
  let body: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  AssertTrueMsg(
    body.kind == HttpClientEventKind.Body && body.buffer.Len() == (3 as intptr) && body.complete,
    "owned response body completes exchange"
  );
}

static method(HttpClientExchange) TestNew(wire: ref string, body: ref string,
  limits: ref HttpClientLimits) -> HttpClientExchange {
  var made: Result<HttpClientExchange, HttpError> = HttpClientExchange.New(
    NetBuffer.HttpTestFromString(wire),
    NetBuffer.HttpTestFromString(body),
    limits
  );
  AssertTrueMsg(made.IsOk(), "valid exchange construction succeeds");

  return move((made.get_if<HttpClientExchange>()) as HttpClientExchange);
}

method(HttpClientExchange) TestDrainBuffered(step: intptr) -> string {
  var wire: StringBuffer = StringBuffer.New();
  var count: int32 = 0;
  while !self.RequestComplete() && count < 100000 {
    let result: Result<NetBuffer, HttpError> = self.Output();
    AssertTrueMsg(result.IsOk(), "request output succeeds");
    if result.IsErr() {
      return wire.Take();
    }

    let buffer: NetBuffer = (result.get_if<NetBuffer>()) as NetBuffer;
    if buffer.Len() == (0 as intptr) {
      AssertTrueMsg(self.RequestComplete(), "zero output implies completed upload");
      break;
    }

    var n: intptr = buffer.Len();
    if n > step {
      n = step;
    }

    let span: NetBytes = (buffer.Bytes().Slice(0 as intptr, n).get_if<NetBytes>()) as NetBytes;
    wire.Append(string.ViewFrom(span.Data() as *const int8, n as int32));
    AssertTrueMsg(self.AcknowledgeOutput(n).IsOk(), "bounded transport acknowledgement succeeds");
    count = count + 1;
  }

  AssertTrueMsg(self.RequestComplete(), "bounded upload completes");

  return wire.Take();
}

@test(tag = "http_core")
func test_http_client_partial_acknowledgement_and_owned_output() {
  let header: string = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\n";
  var exchange: HttpClientExchange = HttpClientExchange.TestNew(header, "abc", HttpClientLimits{});
  let first: NetBuffer = (exchange.Output().get_if<NetBuffer>()) as NetBuffer;
  let repeated: NetBuffer = (exchange.Output().get_if<NetBuffer>()) as NetBuffer;
  AssertTrueMsg(
    first.Len() == repeated.Len() && exchange.Stats().request_bytes_sent == 0u64,
    "generation alone never acknowledges transport bytes"
  );
  AssertTrueMsg(
    exchange.AcknowledgeOutput(-1 as intptr).IsErr()
      && exchange.AcknowledgeOutput(first.Len() + (1 as intptr)).IsErr(),
    "invalid acknowledgement is nonterminal and leaves bytes pending"
  );
  let wire: string = (exchange).TestDrainBuffered(1 as intptr);
  AssertTrueMsg(
    wire.Equal(header.Concat("abc")) && exchange.Stats().request_bytes_sent == wire.length as uint64,
    "one-byte writes never duplicate request bytes"
  );
  var moved: HttpClientExchange = move(exchange);
  moved = HttpClientExchange{};
  AssertTrueMsg(
    string.ViewFrom(first.Bytes().Data() as *const int8, first.Len() as int32).Equal(header),
    "returned output retains an owner after exchange drop"
  );
}

@test(tag = "http_core")
func test_http_client_chunked_request_and_response_events() {
  let header: string = "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n";
  var exchange: HttpClientExchange = HttpClientExchange.TestNew(header, "abc", HttpClientLimits{});
  AssertTrueMsg(
    (exchange).TestDrainBuffered(2 as intptr).Equal(header.Concat("3\r\nabc\r\n0\r\n\r\n")),
    "shared body writer finishes request chunk framing"
  );
  let response: NetBuffer = NetBuffer.HttpTestFromString(
    "HTTP/1.1 103 Hints\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc"
      .Concat("\r\n0\r\nX-End: kept\r\n\r\nNEXT")
  );
  AssertTrueMsg(exchange.Receive(response, false).IsOk(), "combined response packet admitted");
  let info: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  let head: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  let body: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  let done: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  AssertTrueMsg(
    info.kind == HttpClientEventKind.Informational
      && info.head.Status() == 103
      && head.kind == HttpClientEventKind.Head
      && body.kind == HttpClientEventKind.Body
      && done.complete,
    "informational/head/body/complete events share one buffered receive"
  );
  let trailer: HttpField = (exchange.TrailerAt(0).get_if<HttpField>()) as HttpField;
  exchange = HttpClientExchange{};
  AssertTrueMsg(
    trailer.value.Equal("kept") && body.buffer.Len() == (3 as intptr) && info.head.Status() == 103,
    "event and trailer owners survive client destruction"
  );
}

@test(tag = "http_core")
func test_http_client_input_backpressure_and_eof() {
  var exchange: HttpClientExchange = HttpClientExchange.TestNew(
    "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "",
    HttpClientLimits{}
  );
  AssertTrueMsg(
    exchange.Receive(NetBuffer{}, true).IsErr() && exchange.NextResponse().IsErr(),
    "response driving before upload is rejected without poisoning the request"
  );
  (exchange).TestDrainBuffered(16384 as intptr);
  let input: NetBuffer = NetBuffer.HttpTestFromString("HTTP/1.0 200 OK\r\n\r\nbody");
  AssertTrueMsg(
    exchange.Receive(input, true).IsOk() && exchange.Receive(input, false).IsErr(),
    "unread input cannot be overwritten"
  );
  let head: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  let body: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  AssertTrueMsg(
    head.kind == HttpClientEventKind.Head && body.buffer.Len() == (4 as intptr) && !body.complete,
    "EOF is processed only after all buffered payload"
  );
  let done: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  AssertTrueMsg(
    done.complete && exchange.Stats().response_bytes_received == input.Len() as uint64,
    "close-delimited body completes from trusted transport EOF"
  );
}

@test(tag = "http_core")
func test_http_client_response_failures_preserve_stage() {
  var exchange: HttpClientExchange = HttpClientExchange.TestNew(
    "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "",
    HttpClientLimits{}
  );
  (exchange).TestDrainBuffered(3 as intptr);
  AssertTrueMsg(
    exchange.Receive(NetBuffer.HttpTestFromString("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab"), true).IsOk(),
    "truncated response admitted before protocol validation"
  );
  AssertTrueMsg(
    exchange.NextResponse().IsOk() && exchange.NextResponse().IsOk(),
    "valid head and partial body remain observable"
  );
  let failure: Result<HttpClientEvent, HttpError> = exchange.NextResponse();
  AssertTrueMsg(
    failure.IsErr()
      && ((failure.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.UnexpectedEof
      && exchange.Stage() == HttpClientStage.ResponseBody,
    "body truncation retains the failing stage and named error"
  );
  AssertTrueMsg(
    exchange.NextResponse().IsErr() && exchange.Output().IsErr() && exchange.TrailerCount().IsErr(),
    "protocol failure is sticky across every driving surface"
  );
  var upgrade: HttpClientExchange = HttpClientExchange.TestNew(
    "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "",
    HttpClientLimits{}
  );
  (upgrade).TestDrainBuffered(16384 as intptr);
  AssertTrueMsg(
    upgrade.Receive(NetBuffer.HttpTestFromString("HTTP/1.1 101 Switching\r\n\r\nOPAQUE"), false).IsOk(),
    "unsolicited upgrade wire is admitted for validation"
  );
  let rejected: Result<HttpClientEvent, HttpError> = upgrade.NextResponse();
  AssertTrueMsg(
    rejected.IsErr()
      && ((rejected.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.Unsupported
      && upgrade.Stage() == HttpClientStage.ResponseHead,
    "connected profile rejects handoffs before exposing opaque protocol data"
  );
}

// Immutable fixture inputs and expected protocol result.
struct HttpExchangeRejectCase {
  readonly head: string;
  readonly body: string;
  readonly expected: HttpErrorKind;
}

method(HttpExchangeRejectCase) Run() -> void {
  let head: string = self.head;
  let body: string = self.body;
  let expected: HttpErrorKind = self.expected;

  var result: Result<HttpClientExchange, HttpError> = HttpClientExchange.New(
    NetBuffer.HttpTestFromString(head),
    NetBuffer.HttpTestFromString(body),
    HttpClientLimits{}
  );
  AssertTrueMsg(
    result.IsErr() && ((result.get_if<HttpError>()) as HttpError).kind == expected,
    "invalid request fails before transport adoption"
  );
}

@test(tag = "http_core")
func test_http_client_request_validation_and_retention_budget() {
  HttpExchangeRejectCase{head: "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\n", body: "ab",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpExchangeRejectCase{head: "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", body: "a",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpExchangeRejectCase{head: "GET / HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\n\r\n", body: "",
    expected: HttpErrorKind.Unsupported}.Run();
  HttpExchangeRejectCase{head: "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\r\n", body: "",
    expected: HttpErrorKind.Unsupported}.Run();
  HttpExchangeRejectCase{head: "GET / HTTP/1.1\r\nHost: localhost\r\n\r\nEXTRA", body: "",
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpExchangeRejectCase{head: "GET / HTTP/1.0\r\n\r\n", body: "", expected: HttpErrorKind.Unsupported}.Run();
  let header: NetBuffer = NetBuffer.HttpTestFromString(
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n"
  );
  let backing: NetBuffer = NetBuffer.HttpTestFromString("abcdefghijklmnop");
  let slice: NetBuffer = (backing.Slice(0 as intptr, 1 as intptr).get_if<NetBuffer>()) as NetBuffer;
  var result: Result<HttpClientExchange, HttpError> = HttpClientExchange.New(
    header,
    slice,
    HttpClientLimits{max_retained_request_bytes:(header.Len() + (1 as intptr)) as int32}
  );
  AssertTrueMsg(
    result.IsErr() && ((result.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.LimitExceeded,
    "request budget charges full backing allocations rather than visible slices"
  );
}

@test(tag = "http_core")
func test_http_client_incoming_backing_budget_and_identity() {
  var exchange: HttpClientExchange = HttpClientExchange.TestNew(
    "GET / HTTP/1.1\r\nHost: [::1]:443\r\n\r\n",
    "",
    HttpClientLimits{}
  );
  AssertTrueMsg(
    ((exchange.AuthorityHost().get_if<string>()) as string).Equal("::1"),
    "identity getter strips only validated brackets and port"
  );
  (exchange).TestDrainBuffered(16384 as intptr);
  var storage: owned <uint8>[] = new <uint8>[16385];
  let raw: NetBytes = (NetBytes.FromRaw(&storage[0], 16385 as intptr).get_if<NetBytes>()) as NetBytes;
  let root: NetBuffer = (NetBuffer.CopyFrom(raw).get_if<NetBuffer>()) as NetBuffer;
  let tiny: NetBuffer = (root.Slice(0 as intptr, 1 as intptr).get_if<NetBuffer>()) as NetBuffer;
  AssertTrueMsg(
    exchange.Receive(tiny, false).IsErr() && exchange.Receive(NetBuffer{}, true).IsOk(),
    "oversized incoming backing rejection leaves input admission available"
  );
  let end: Result<HttpClientEvent, HttpError> = exchange.NextResponse();
  AssertTrueMsg(
    end.IsErr() && ((end.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.UnexpectedEof,
    "empty transport EOF cannot invent a response head"
  );
}
