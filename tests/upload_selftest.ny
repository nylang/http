// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of HttpClientTests;

/** @brief Streamed producer ownership, continue gating and early-response scheduling. */

static method(HttpClientExchange) TestStreaming(wire: ref string, limits: ref HttpClientLimits) -> HttpClientExchange {
  var made: Result<HttpClientExchange, HttpError> = HttpClientExchange.NewStreaming(
    NetBuffer.HttpTestFromString(wire),
    limits
  );
  AssertTrueMsg(made.IsOk(), "stream constructor accepts validated head");

  return move((made.get_if<HttpClientExchange>()) as HttpClientExchange);
}

method(HttpClientExchange) TestUploadState() -> HttpUploadState {
  let result: Result<HttpUploadState, HttpError> = self.UploadState();
  AssertTrueMsg(result.IsOk(), "upload state is available");
  if result.IsErr() {
    return HttpUploadState.Stopped;
  }

  return (result.get_if<HttpUploadState>()) as HttpUploadState;
}

method(HttpClientExchange) TestDrainStreaming(step: intptr) -> string {
  var wire: StringBuffer = StringBuffer.New();
  var tries: int32 = 0;
  while tries < 100000 {
    let result: Result<NetBuffer, HttpError> = self.Output();
    AssertTrueMsg(result.IsOk(), "stream output succeeds");
    if result.IsErr() {
      break;
    }

    let block: NetBuffer = (result.get_if<NetBuffer>()) as NetBuffer;
    if block.Len() == (0 as intptr) {
      break;
    }

    var count: intptr = block.Len();
    if count > step {
      count = step;
    }

    wire.Append(string.ViewFrom(block.Bytes().Data() as *const int8, count as int32));
    AssertTrueMsg(self.AcknowledgeOutput(count).IsOk(), "stream output acknowledged exactly");
    tries = tries + 1;
  }

  AssertTrueMsg(tries < 100000, "stream drain remains bounded");

  return wire.Take();
}

@test(tag = "http_core")
func test_http_upload_fixed_producer_backpressure() {
  let head: string = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\n";
  var exchange: HttpClientExchange = HttpClientExchange.TestStreaming(head, HttpClientLimits{});
  AssertTrueMsg(
    exchange.SupplyBody(NetBuffer.HttpTestFromString("a")).IsErr() && exchange.FinishBody(new <HttpField>[0]).IsErr(),
    "producer cannot precede acknowledged head"
  );
  AssertTrueMsg(
    (exchange).TestDrainStreaming(1 as intptr).Equal(head) && (exchange).TestUploadState() == HttpUploadState.NeedBody,
    "partial head acknowledgements unblock producer once"
  );
  AssertTrueMsg(
    exchange.SupplyBody(NetBuffer.HttpTestFromString("a")).IsOk()
      && exchange.SupplyBody(NetBuffer.HttpTestFromString("b")).IsErr(),
    "only one immutable producer block is admitted"
  );
  AssertTrueMsg((exchange).TestDrainStreaming(1 as intptr).Equal("a"), "first producer block drains without finish");
  AssertTrueMsg(
    exchange.SupplyBody(NetBuffer.HttpTestFromString("bc")).IsOk()
      && (exchange).TestDrainStreaming(1 as intptr).Equal("bc"),
    "producer resumes after backpressure"
  );
  AssertTrueMsg(
    !exchange.RequestComplete()
      && exchange.FinishBody(new <HttpField>[0]).IsOk()
      && exchange.RequestComplete(),
    "explicit producer finish attests exact fixed length"
  );
  AssertTrueMsg(
    exchange.FinishBody(new <HttpField>[0]).IsOk()
      && exchange.Stats().request_bytes_sent == head.length as uint64 + 3u64,
    "finish is idempotent without duplicate wire"
  );
}

@test(tag = "http_core")
func test_http_upload_chunked_trailers_and_owned_blocks() {
  var exchange: HttpClientExchange = HttpClientExchange.TestStreaming(
    "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n",
    HttpClientLimits{}
  );
  (exchange).TestDrainStreaming(3 as intptr);
  AssertTrueMsg(exchange.SupplyBody(NetBuffer.HttpTestFromString("abc")).IsOk(), "chunk payload supplied");
  let payload: string = (exchange).TestDrainStreaming(1 as intptr);
  AssertTrueMsg(
    payload.Equal("3\r\nabc\r\n") && (exchange).TestUploadState() == HttpUploadState.NeedBody,
    "chunk metadata drains before producer resumes"
  );
  AssertTrueMsg(
    exchange.FinishBody(new <HttpField>[]{HttpField{name: "X-End", value: "kept"}}).IsOk(),
    "declared request trailer queued"
  );
  AssertTrueMsg(
    (exchange).TestDrainStreaming(1 as intptr).Equal("0\r\nX-End: kept\r\n\r\n") && exchange.RequestComplete(),
    "final framing is acknowledged separately"
  );
  AssertTrueMsg(exchange.SupplyBody(NetBuffer.HttpTestFromString("x")).IsErr(), "closed producer never reopens");
}

@test(tag = "http_core")
func test_http_upload_cumulative_body_without_full_retention() {
  var storage: <uint8>[512] = <uint8>[512] {
  };
  var i: int32 = 0;
  while i < 512 {
    storage[i] = 120u8;
    i = i + 1;
  }

  let block: NetBuffer = (NetBuffer.CopyFrom((NetBytes.FromRaw(
    &storage[0],
    512 as intptr
  ).get_if<NetBytes>()) as NetBytes).get_if<NetBuffer>()) as NetBuffer;
  var exchange: HttpClientExchange = HttpClientExchange.TestStreaming(
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 32768\r\n\r\n",
    HttpClientLimits{max_retained_request_bytes: 1024, body: HttpBodyLimits{max_body_bytes: 32768u64}}
  );
  (exchange).TestDrainStreaming(16384 as intptr);
  i = 0;
  while i < 64 {
    AssertTrueMsg(exchange.SupplyBody(block).IsOk(), "bounded producer admits another block");
    AssertTrueMsg(
      (exchange).TestDrainStreaming(511 as intptr).length == 512,
      "block acknowledged under partial writes"
    );
    i = i + 1;
  }

  AssertTrueMsg(
    exchange.FinishBody(new <HttpField>[0]).IsOk() && exchange.RequestComplete(),
    "32 KiB upload completes under 1 KiB request retention"
  );
}

@test(tag = "http_core")
func test_http_upload_admission_limits_are_nonterminal() {
  var exchange: HttpClientExchange = HttpClientExchange.TestStreaming(
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\n",
    HttpClientLimits{}
  );
  (exchange).TestDrainStreaming(16384 as intptr);
  var large: owned <uint8>[] = new <uint8>[16385];
  let root: NetBuffer = (NetBuffer.CopyFrom((NetBytes.FromRaw(
    &large[0],
    16385 as intptr
  ).get_if<NetBytes>()) as NetBytes).get_if<NetBuffer>()) as NetBuffer;
  let slice: NetBuffer = (root.Slice(0 as intptr, 1 as intptr).get_if<NetBuffer>()) as NetBuffer;
  AssertTrueMsg(
    exchange.SupplyBody(NetBuffer{}).IsErr()
      && exchange.SupplyBody(slice).IsErr()
      && exchange.SupplyBody(NetBuffer.HttpTestFromString("abcd")).IsErr(),
    "empty/backing-heavy/excess fixed input rejected before adoption"
  );
  AssertTrueMsg(
    exchange.SupplyBody(NetBuffer.HttpTestFromString("abc")).IsOk()
      && (exchange).TestDrainStreaming(2 as intptr).Equal("abc") && exchange.FinishBody(new <HttpField>[0]).IsOk(),
    "rejected admissions preserve exact producer state"
  );
  var capped: HttpClientExchange = HttpClientExchange.TestStreaming(
    "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
    HttpClientLimits{body: HttpBodyLimits{max_body_bytes: 3u64}}
  );
  (capped).TestDrainStreaming(16384 as intptr);
  capped.SupplyBody(NetBuffer.HttpTestFromString("ab"));
  (capped).TestDrainStreaming(16384 as intptr);
  AssertTrueMsg(
    capped.SupplyBody(NetBuffer.HttpTestFromString("cd")).IsErr()
      && capped.SupplyBody(NetBuffer.HttpTestFromString("c")).IsOk(),
    "cumulative decoded budget does not reset between blocks"
  );
}

@test(tag = "http_core")
func test_http_upload_expect_profile_and_legacy_rejection() {
  let head: NetBuffer = NetBuffer.HttpTestFromString(
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n"
  );
  AssertTrueMsg(
    HttpClientExchange.New(head, NetBuffer.HttpTestFromString("abc"), HttpClientLimits{}).IsErr(),
    "immutable client keeps its existing Expect rejection"
  );
  AssertTrueMsg(
    HttpClientExchange.NewStreaming(
      NetBuffer.HttpTestFromString(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nExpect: 100-continue\r\n\r\n"
      ),
      HttpClientLimits{}
    ).IsErr(),
    "expectation without content rejected"
  );
  AssertTrueMsg(
    HttpClientExchange.NewStreaming(
      NetBuffer.HttpTestFromString("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nExpect: custom\r\n\r\n"),
      HttpClientLimits{}
    ).IsErr(),
    "unknown expectation rejected"
  );
  AssertTrueMsg(
    HttpClientExchange.NewStreaming(
      NetBuffer.HttpTestFromString(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nExpect: 100-continue\r\n"
          .Concat("Expect: 100-continue\r\n\r\n")
      ),
      HttpClientLimits{}
    ).IsErr(),
    "duplicate expectation rejected"
  );
}

@test(tag = "http_core")
func test_http_upload_continue_informationals_and_buffered_final() {
  var exchange: HttpClientExchange = HttpClientExchange.TestStreaming(
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nExpect: 100-ConTinue\r\n\r\n",
    HttpClientLimits{}
  );
  (exchange).TestDrainStreaming(2 as intptr);
  AssertTrueMsg(
    (exchange).TestUploadState() == HttpUploadState.WaitingContinue
      && exchange.Output().IsOk()
      && exchange.SupplyBody(NetBuffer.HttpTestFromString("abc")).IsErr(),
    "producer cannot bypass pending continue gate"
  );
  exchange.Receive(NetBuffer.HttpTestFromString("HTTP/1.1 103 Hints\r\n\r\n"), false);
  let hint: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  AssertTrueMsg(
    hint.head.Status() == 103 && (exchange).TestUploadState() == HttpUploadState.WaitingContinue,
    "103 does not authorize body output"
  );
  exchange.Receive(
    NetBuffer.HttpTestFromString("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 413 Too Large\r\nContent-Length: 0\r\n\r\n"),
    false
  );
  let info: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  AssertTrueMsg(
    info.head.Status() == 100
      && (exchange).TestUploadState() == HttpUploadState.ReadingResponse
      && exchange.SupplyBody(NetBuffer.HttpTestFromString("abc")).IsErr(),
    "buffered final takes priority even after 100"
  );
  let final: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  AssertTrueMsg(
    final.head.Status() == 413
      && final.complete
      && (exchange).TestUploadState() == HttpUploadState.Stopped
      && !exchange.RequestComplete(),
    "early final suppresses producer without claiming sent body"
  );
}

@test(tag = "http_core")
func test_http_upload_split_continue_and_explicit_release() {
  var exchange: HttpClientExchange = HttpClientExchange.TestStreaming(
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n",
    HttpClientLimits{}
  );
  (exchange).TestDrainStreaming(16384 as intptr);
  exchange.Receive(NetBuffer.HttpTestFromString("HTTP/1.1 100 Con"), false);
  AssertTrueMsg(
    (
      (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent
    ).kind == HttpClientEventKind.NeedInput
      && (exchange).TestUploadState() == HttpUploadState.ReadingResponse,
    "partial informational head blocks upload"
  );
  AssertTrueMsg(exchange.ContinueUpload().IsErr(), "explicit release cannot discard a partial response head");
  exchange.Receive(NetBuffer.HttpTestFromString("tinue\r\n\r\n"), false);
  exchange.NextResponse();
  AssertTrueMsg(
    (exchange).TestUploadState() == HttpUploadState.NeedBody
      && exchange.SupplyBody(NetBuffer.HttpTestFromString("abc")).IsOk(),
    "complete 100 releases producer"
  );
  (exchange).TestDrainStreaming(16384 as intptr);
  exchange.FinishBody(new <HttpField>[0]);
  AssertTrueMsg(
    exchange.RequestComplete() && exchange.ContinueUpload().IsErr(),
    "continue cannot reopen finished upload"
  );
  var fallback: HttpClientExchange = HttpClientExchange.TestStreaming(
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\n",
    HttpClientLimits{}
  );
  (fallback).TestDrainStreaming(16384 as intptr);
  AssertTrueMsg(
    fallback.ContinueUpload().IsOk() && fallback.SupplyBody(NetBuffer.HttpTestFromString("x")).IsOk(),
    "caller may release gate after a bounded wait without clock mutation"
  );
}

@test(tag = "http_core")
func test_http_upload_early_final_revokes_unsent_suffix_and_keeps_owners() {
  var exchange: HttpClientExchange = HttpClientExchange.TestStreaming(
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 6\r\n\r\n",
    HttpClientLimits{}
  );
  (exchange).TestDrainStreaming(16384 as intptr);
  exchange.SupplyBody(NetBuffer.HttpTestFromString("abcdef"));
  let held: NetBuffer = (exchange.Output().get_if<NetBuffer>()) as NetBuffer;
  AssertTrueMsg(exchange.AcknowledgeOutput(2 as intptr).IsOk(), "partial payload write acknowledged");
  let sent: uint64 = exchange.Stats().request_bytes_sent;
  exchange.Receive(NetBuffer.HttpTestFromString("HTTP/1.1 409 Stop\r\nContent-Length: 3\r\n\r\nbye"), false);
  let final: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  let body: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  AssertTrueMsg(
    final.head.Status() == 409 && body.complete && body.buffer.Len() == (3 as intptr),
    "early response body remains consumable"
  );
  AssertTrueMsg(
    (exchange).TestUploadState() == HttpUploadState.Stopped
      && !exchange.RequestComplete()
      && exchange.AcknowledgeOutput(1 as intptr).IsErr()
      && exchange.FinishBody(new <HttpField>[0]).IsErr(),
    "stopped upload never resumes or accepts late acknowledgements"
  );
  AssertTrueMsg(
    ((exchange.Output().get_if<NetBuffer>()) as NetBuffer).Len() == (0 as intptr)
      && exchange.Stats().request_bytes_sent == sent,
    "revoked suffix generates no more wire or invented progress"
  );
  exchange = HttpClientExchange{};
  AssertTrueMsg(
    held.Len() == (6 as intptr) && held.Bytes().Data()[5] == 102u8 && final.head.Status() == 409,
    "retained output and response owners survive cursor drop"
  );
}

@test(tag = "http_core")
func test_http_upload_final_before_any_body_and_no_retry() {
  var exchange: HttpClientExchange = HttpClientExchange.TestStreaming(
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n",
    HttpClientLimits{}
  );
  let head: string = (exchange).TestDrainStreaming(16384 as intptr);
  exchange.Receive(NetBuffer.HttpTestFromString("HTTP/1.1 417 No Expectation\r\nContent-Length: 0\r\n\r\n"), false);
  let event: HttpClientEvent = (exchange.NextResponse().get_if<HttpClientEvent>()) as HttpClientEvent;
  AssertTrueMsg(
    event.complete && event.head.Status() == 417 && exchange.IsComplete() && !exchange.RequestComplete(),
    "417 is terminal response, never implicit producer replay"
  );
  AssertTrueMsg(
    exchange.ContinueUpload().IsErr() && exchange.Stats().request_bytes_sent == head.length as uint64,
    "only the acknowledged head counts as sent"
  );
}

@test(tag = "http_core")
func test_http_upload_shortage_trailer_and_eof_errors_stick() {
  var short: HttpClientExchange = HttpClientExchange.TestStreaming(
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\n",
    HttpClientLimits{}
  );
  (short).TestDrainStreaming(16384 as intptr);
  let end: Result<Unit, HttpError> = short.FinishBody(new <HttpField>[0]);
  AssertTrueMsg(
    end.IsErr()
      && ((end.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.UnexpectedEof
      && short.Output().IsErr()
      && short.UploadState().IsErr(),
    "fixed shortage is terminal and sticky"
  );
  var trailer: HttpClientExchange = HttpClientExchange.TestStreaming(
    "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
    HttpClientLimits{}
  );
  (trailer).TestDrainStreaming(16384 as intptr);
  AssertTrueMsg(
    trailer.FinishBody(new <HttpField>[]{HttpField{
      name: "Content-Length",
      value: "3"
    }}).IsErr() && trailer.Output().IsErr(),
    "forbidden request trailer fails closed"
  );
  var eof: HttpClientExchange = HttpClientExchange.TestStreaming(
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\n",
    HttpClientLimits{}
  );
  (eof).TestDrainStreaming(16384 as intptr);
  eof.Receive(NetBuffer{}, true);
  AssertTrueMsg(
    eof.NextResponse().IsErr() && eof.ContinueUpload().IsErr(),
    "EOF while waiting for a final head never authorizes upload"
  );
}

@test(tag = "http_core")
func test_http_upload_empty_chunked_expect_and_no_body_completion() {
  var empty: HttpClientExchange = HttpClientExchange.TestStreaming(
    "POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n",
    HttpClientLimits{}
  );
  (empty).TestDrainStreaming(16384 as intptr);
  empty.ContinueUpload();
  AssertTrueMsg(
    empty.FinishBody(new <HttpField>[0]).IsErr() && empty.Output().IsErr(),
    "Expect cannot be used to generate empty content"
  );
  var empty_request: HttpClientExchange = HttpClientExchange.TestStreaming(
    "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    HttpClientLimits{}
  );
  (empty_request).TestDrainStreaming(16384 as intptr);
  AssertTrueMsg(
    empty_request.RequestComplete() && (empty_request).TestUploadState() == HttpUploadState.Finished,
    "no-body streamed request needs no artificial producer callback"
  );
}

@test(tag = "http_core")
func test_http_upload_partial_final_blocks_queued_output() {
  var exchange: HttpClientExchange = HttpClientExchange.TestStreaming(
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\n",
    HttpClientLimits{}
  );
  (exchange).TestDrainStreaming(16384 as intptr);
  exchange.SupplyBody(NetBuffer.HttpTestFromString("abc"));
  exchange.Receive(NetBuffer.HttpTestFromString("HTTP/1.1 400"), false);
  exchange.NextResponse();
  AssertTrueMsg(
    (exchange).TestUploadState() == HttpUploadState.ReadingResponse
      && ((exchange.Output().get_if<NetBuffer>()) as NetBuffer).Len() == (0 as intptr)
      && exchange.Stage() == HttpClientStage.ResponseHead,
    "partial final head pauses queued upload and records response stage"
  );
  exchange.Receive(NetBuffer.HttpTestFromString(" Bad\r\nContent-Length: 0\r\n\r\n"), false);
  exchange.NextResponse();
  AssertTrueMsg(
    (exchange).TestUploadState() == HttpUploadState.Stopped,
    "completed early final permanently discards queued payload"
  );
}
