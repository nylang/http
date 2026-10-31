// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of HttpProtocolTests;

/** @brief Streaming body boundaries, bounded framing and caller-owned output. */

static method(HttpBodyDecoder) TestNew(wire: ref string, limits: ref HttpBodyLimits) -> HttpBodyDecoder {
  let head: HttpHead = HttpHead.TestParse(true, "GET", wire);
  var made: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(head, limits);
  AssertTrueMsg(made.IsOk(), "body construction succeeds");

  return move((made.get_if<HttpBodyDecoder>()) as HttpBodyDecoder);
}

@test(tag = "http_core")
func test_http_body_fixed_smoke() {
  var decoder: HttpBodyDecoder = HttpBodyDecoder.TestNew(
    "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n",
    HttpBodyLimits{}
  );
  var storage: <uint8>[8] = <uint8>[8] {
  };
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(
    &mut storage[0],
    8 as intptr
  ).get_if<NetMutableBytes>()) as NetMutableBytes;
  let fed: Result<HttpBodyProgress, HttpError> = decoder.Push(NetBytes.FromString("abcNEXT"), output);
  AssertTrueMsg(fed.IsOk(), "fixed body decode succeeds");
  if fed.IsOk() {
    let step: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
    AssertTrueMsg(
      step.consumed == (3 as intptr)
        && step.produced == (3 as intptr)
        && step.state == HttpBodyState.Complete
        && storage[0] == 97u8
        && storage[2] == 99u8,
      "fixed boundary preserves pipeline"
    );
  }

  AssertTrueMsg(decoder.EndInput().IsOk(), "complete fixed body survives EOF");
}

method(HttpBodyDecoder) TestFeed(wire: ref string) -> string {
  var result: StringBuffer = StringBuffer.New();
  var used: intptr = 0 as intptr;
  var storage: <uint8>[3] = <uint8>[3] {
  };
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(
    &mut storage[0],
    3 as intptr
  ).get_if<NetMutableBytes>()) as NetMutableBytes;
  while used < wire.length as intptr && !self.IsComplete() {
    let input: NetBytes = (NetBytes.FromString(wire).Slice(
      used,
      wire.length as intptr - used
    ).get_if<NetBytes>()) as NetBytes;
    let fed: Result<HttpBodyProgress, HttpError> = self.Push(input, output);
    AssertTrueMsg(fed.IsOk(), "fragment decoding succeeds");
    if fed.IsErr() {
      return result.Take();
    }

    let step: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
    AssertTrueMsg(step.consumed >(0 as intptr), "available input and output advance the decoder");
    if step.consumed == (0 as intptr) {
      return result.Take();
    }

    if step.produced >(0 as intptr) {
      result.Append(string.ViewFrom(&storage[0] as *const int8, step.produced as int32));
    }

    used = used + step.consumed;
  }

  return result.Take();
}

// Immutable fixture inputs and expected protocol result.
struct HttpBodyRejectCase {
  readonly wire: string;
  readonly limits: HttpBodyLimits;
  readonly expected: HttpErrorKind;
}

method(HttpBodyRejectCase) Run() -> void {
  let wire: string = self.wire;
  let limits: HttpBodyLimits = self.limits;
  let expected: HttpErrorKind = self.expected;

  var decoder: HttpBodyDecoder = HttpBodyDecoder.TestNew(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    limits
  );
  var storage: <uint8>[1] = <uint8>[1] {
  };
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(
    &mut storage[0],
    1 as intptr
  ).get_if<NetMutableBytes>()) as NetMutableBytes;
  var used: intptr = 0 as intptr;
  var rejected: bool = false;
  while used < wire.length as intptr && !decoder.IsComplete() {
    storage[0] = 165u8;
    let input: NetBytes = (NetBytes.FromString(wire).Slice(
      used,
      wire.length as intptr - used
    ).get_if<NetBytes>()) as NetBytes;
    let fed: Result<HttpBodyProgress, HttpError> = decoder.Push(input, output);
    if fed.IsErr() {
      rejected = true;
      let error: HttpError = (fed.get_if<HttpError>()) as HttpError;
      AssertTrueMsg(
        error.kind == expected && storage[0] == 165u8,
        "error kind matches and error call leaves output untouched"
      );
      let retry: Result<HttpBodyProgress, HttpError> = decoder.Push(NetBytes.FromString("0\r\n\r\n"), output);
      AssertTrueMsg(
        retry.IsErr()
          && decoder.EndInput().IsErr()
          && decoder.TrailerCount().IsErr()
          && !decoder.IsComplete(),
        "body failures remain terminal"
      );
      if retry.IsErr() {
        AssertTrueMsg(
          ((retry.get_if<HttpError>()) as HttpError).offset == error.offset,
          "terminal body cursor is stable"
        );
      }

      break;
    }

    let step: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
    if step.consumed == (0 as intptr) {
      break;
    }

    used = used + step.consumed;
  }

  AssertTrueMsg(rejected, "invalid chunk wire is rejected");
}

@test(tag = "http_core")
func test_http_body_chunked_every_split() {
  let wire: string = "3; name = \"a\\\"b\";flag\r\nabc\r\n2\r\nde\r\n0;done\r\nX-Hash: one\r\nX-Hash: two\r\n\r\n";
  var split: int32 = 0;
  while split <= wire.length {
    var decoder: HttpBodyDecoder = HttpBodyDecoder.TestNew(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
      HttpBodyLimits{}
    );
    let first: string = (decoder).TestFeed(wire.Substring(0, split));
    let last: string = (decoder).TestFeed(wire.Substring(split, wire.length - split));
    AssertTrueMsg(
      first.Concat(last).Equal("abcde") && decoder.IsComplete() && decoder.EndInput().IsOk(),
      "every split decodes the same body"
    );
    let count: Result<int32, HttpError> = decoder.TrailerCount();
    AssertTrueMsg(
      count.IsOk() && ((count.get_if<int32>()) as int32) == 2,
      "trailers complete separately from head"
    );
    let field: HttpField = (decoder.TrailerAt(1).get_if<HttpField>()) as HttpField;
    AssertTrueMsg(
      field.name.Equal("X-Hash") && field.value.Equal("two"),
      "ordinary duplicate trailer order is preserved"
    );
    split = split + 1;
  }
}

@test(tag = "http_core")
func test_http_body_backpressure_and_pipeline() {
  var decoder: HttpBodyDecoder = HttpBodyDecoder.TestNew(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    HttpBodyLimits{}
  );
  let empty: NetMutableBytes = NetMutableBytes{};
  let fed: Result<HttpBodyProgress, HttpError> = decoder.Push(
    NetBytes.FromString("3\r\nabc\r\n0\r\n\r\nNEXT"),
    empty
  );
  AssertTrueMsg(fed.IsOk(), "zero output consumes metadata only");
  let step: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
  AssertTrueMsg(
    step.consumed == (3 as intptr)
      && step.produced == (0 as intptr)
      && step.state == HttpBodyState.NeedOutput,
    "chunk payload waits for caller capacity"
  );
  AssertTrueMsg(decoder.TrailerCount().IsErr(), "pending trailer query does not poison body");
  var storage: <uint8>[8] = <uint8>[8] {
  };
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(
    &mut storage[0],
    8 as intptr
  ).get_if<NetMutableBytes>()) as NetMutableBytes;
  let copied: HttpBodyProgress = (decoder.Push(
    NetBytes.FromString("abc\r\n0\r\n\r\nNEXT"),
    output
  ).get_if<HttpBodyProgress>()) as HttpBodyProgress;
  AssertTrueMsg(
    copied.consumed == (3 as intptr) && copied.produced == (3 as intptr),
    "payload call returns before validating following delimiter"
  );
  let final: HttpBodyProgress = (decoder.Push(
    NetBytes.FromString("\r\n0\r\n\r\nNEXT"),
    empty
  ).get_if<HttpBodyProgress>()) as HttpBodyProgress;
  AssertTrueMsg(
    final.consumed == (7 as intptr)
      && final.produced == (0 as intptr)
      && final.state == HttpBodyState.Complete,
    "metadata completes without consuming pipeline suffix"
  );
  let again: HttpBodyProgress = (decoder.Push(
    NetBytes.FromString("NEXT"),
    output
  ).get_if<HttpBodyProgress>()) as HttpBodyProgress;
  AssertTrueMsg(
    again.consumed == (0 as intptr) && again.produced == (0 as intptr),
    "completed body consumes nothing"
  );
}

@test(tag = "http_core")
func test_http_body_fixed_every_split_and_eof() {
  var split: int32 = 0;
  while split <= 5 {
    var decoder: HttpBodyDecoder = HttpBodyDecoder.TestNew(
      "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
      HttpBodyLimits{}
    );
    let first: string = (decoder).TestFeed("abcde".Substring(0, split));
    let last: string = (decoder).TestFeed("abcde".Substring(split, 5 - split));
    AssertTrueMsg(
      first.Concat(last).Equal("abcde") && decoder.EndInput().IsOk(),
      "fixed fragments finish exactly"
    );
    var truncated: HttpBodyDecoder = HttpBodyDecoder.TestNew(
      "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n",
      HttpBodyLimits{}
    );
    (truncated).TestFeed("abcde".Substring(0, split));
    let eof: Result<bool, HttpError> = truncated.EndInput();
    AssertTrueMsg(
      eof.IsErr() && ((eof.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.UnexpectedEof,
      "fixed EOF never silently completes short bodies"
    );
    split = split + 1;
  }
}

@test(tag = "http_core")
func test_http_body_chunked_eof_every_prefix() {
  let wire: string = "1;x=y\r\na\r\n0\r\nX-End: yes\r\n\r\n";
  var i: int32 = 0;
  while i < wire.length {
    var decoder: HttpBodyDecoder = HttpBodyDecoder.TestNew(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
      HttpBodyLimits{}
    );
    (decoder).TestFeed(wire.Substring(0, i));
    let eof: Result<bool, HttpError> = decoder.EndInput();
    AssertTrueMsg(
      eof.IsErr()
        && ((eof.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.UnexpectedEof
        && decoder.TrailerAt(0).IsErr(),
      "every incomplete chunk/trailer prefix fails at EOF"
    );
    i = i + 1;
  }
}

@test(tag = "http_core")
func test_http_body_eof_delimited_and_budget() {
  var decoder: HttpBodyDecoder = HttpBodyDecoder.TestNew(
    "HTTP/1.0 200 OK\r\n\r\n",
    HttpBodyLimits{max_body_bytes: 3u64}
  );
  AssertTrueMsg(
    (decoder).TestFeed("abc").Equal("abc") && !decoder.IsComplete(),
    "EOF body waits for actual EOF at exact decoded cap"
  );
  AssertTrueMsg(decoder.EndInput().IsOk() && decoder.IsComplete(), "exact body cap can finish at EOF");
  var exceeded: HttpBodyDecoder = HttpBodyDecoder.TestNew(
    "HTTP/1.0 200 OK\r\n\r\n",
    HttpBodyLimits{max_body_bytes: 3u64}
  );
  (exceeded).TestFeed("abc");
  let fed: Result<HttpBodyProgress, HttpError> = exceeded.Push(NetBytes.FromString("d"), NetMutableBytes{});
  AssertTrueMsg(
    fed.IsErr() && ((fed.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.LimitExceeded,
    "extra EOF body data fails even without output space"
  );
}

@test(tag = "http_core")
func test_http_body_size_and_extension_rejection() {
  HttpBodyRejectCase{wire: "10000000000000000\r\n", limits: HttpBodyLimits{},
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpBodyRejectCase{wire: "ffffffffffffffff\r\n", limits: HttpBodyLimits{},
    expected: HttpErrorKind.LimitExceeded}.Run();
  HttpBodyRejectCase{wire: "+1\r\n", limits: HttpBodyLimits{}, expected: HttpErrorKind.Malformed}.Run();
  HttpBodyRejectCase{wire: " 1\r\n", limits: HttpBodyLimits{}, expected: HttpErrorKind.Malformed}.Run();
  HttpBodyRejectCase{wire: "1 \r\n", limits: HttpBodyLimits{}, expected: HttpErrorKind.Malformed}.Run();
  HttpBodyRejectCase{wire: "1;\r\n", limits: HttpBodyLimits{}, expected: HttpErrorKind.Malformed}.Run();
  HttpBodyRejectCase{wire: "1;x=\r\n", limits: HttpBodyLimits{}, expected: HttpErrorKind.Malformed}.Run();
  HttpBodyRejectCase{wire: "1;x=\"open\r\n", limits: HttpBodyLimits{}, expected: HttpErrorKind.Malformed}.Run();
  HttpBodyRejectCase{wire: "1;x=\"a\"oops\r\n", limits: HttpBodyLimits{}, expected: HttpErrorKind.Malformed}.Run();
  HttpBodyRejectCase{wire: "1;x=\"a\tb\"\r\naX", limits: HttpBodyLimits{}, expected: HttpErrorKind.Malformed}.Run();
  HttpBodyRejectCase{wire: "1\na", limits: HttpBodyLimits{}, expected: HttpErrorKind.Malformed}.Run();
  HttpBodyRejectCase{wire: "1\rXa", limits: HttpBodyLimits{}, expected: HttpErrorKind.Malformed}.Run();
  HttpBodyRejectCase{wire: "1\r\na\rX", limits: HttpBodyLimits{}, expected: HttpErrorKind.Malformed}.Run();
}

@test(tag = "http_core")
func test_http_body_cumulative_limits() {
  HttpBodyRejectCase{wire: "2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n", limits: HttpBodyLimits{max_body_bytes: 3u64},
    expected: HttpErrorKind.LimitExceeded}.Run();
  HttpBodyRejectCase{wire: "1;x=long\r\na\r\n0\r\n\r\n", limits: HttpBodyLimits{max_line_bytes: 7},
    expected: HttpErrorKind.LimitExceeded}.Run();
  HttpBodyRejectCase{wire: "1\r\na\r\n1\r\nb\r\n0\r\n\r\n", limits: HttpBodyLimits{max_framing_bytes: 14},
    expected: HttpErrorKind.LimitExceeded}.Run();
  HttpBodyRejectCase{wire: "0\r\nX: a\r\nY: b\r\n\r\n", limits: HttpBodyLimits{max_trailers: 1},
    expected: HttpErrorKind.LimitExceeded}.Run();
  var exact: HttpBodyDecoder = HttpBodyDecoder.TestNew(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    HttpBodyLimits{max_body_bytes: 1u64, max_framing_bytes: 10, max_line_bytes: 1}
  );
  AssertTrueMsg(
    (exact).TestFeed("1\r\na\r\n0\r\n\r\n").Equal("a") && exact.IsComplete(),
    "exact cumulative framing and body caps succeed"
  );
}

@test(tag = "http_core")
func test_http_body_forbidden_and_malformed_trailers() {
  HttpBodyRejectCase{wire: "0\r\nContent-Length: 0\r\n\r\n", limits: HttpBodyLimits{},
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpBodyRejectCase{wire: "0\r\ntRaNsFeR-EnCoDiNg: chunked\r\n\r\n", limits: HttpBodyLimits{},
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpBodyRejectCase{wire: "0\r\nHost: x\r\n\r\n", limits: HttpBodyLimits{},
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpBodyRejectCase{wire: "0\r\nConnection: close\r\n\r\n", limits: HttpBodyLimits{},
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpBodyRejectCase{wire: "0\r\nAuthorization: secret\r\n\r\n", limits: HttpBodyLimits{},
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpBodyRejectCase{wire: "0\r\nContent-Type: text/plain\r\n\r\n", limits: HttpBodyLimits{},
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpBodyRejectCase{wire: "0\r\nSet-Cookie: a=b\r\n\r\n", limits: HttpBodyLimits{},
    expected: HttpErrorKind.InvalidFraming}.Run();
  HttpBodyRejectCase{wire: "0\r\n Bad: value\r\n\r\n", limits: HttpBodyLimits{},
    expected: HttpErrorKind.Malformed}.Run();
  HttpBodyRejectCase{wire: "0\r\nBad : value\r\n\r\n", limits: HttpBodyLimits{},
    expected: HttpErrorKind.Malformed}.Run();
  HttpBodyRejectCase{wire: "0\r\nBad: a\r\n folded\r\n\r\n", limits: HttpBodyLimits{},
    expected: HttpErrorKind.Malformed}.Run();
  var nominated: HttpBodyDecoder = HttpBodyDecoder.TestNew(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: x-private\r\n\r\n",
    HttpBodyLimits{}
  );
  let fed: Result<HttpBodyProgress, HttpError> = nominated.Push(
    NetBytes.FromString("0\r\nX-Private: a\r\n\r\n"),
    NetMutableBytes{}
  );
  AssertTrueMsg(
    fed.IsErr() && ((fed.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.InvalidFraming,
    "connection-nominated trailer names cannot cross into application metadata"
  );
}

@test(tag = "http_core")
func test_http_body_construction_and_handoffs() {
  let fixed: HttpHead = HttpHead.TestParse(
    true,
    "GET",
    "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n"
  );
  var oversized: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(fixed, HttpBodyLimits{});
  AssertTrueMsg(
    oversized.IsErr() && ((oversized.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.LimitExceeded,
    "oversized fixed body rejected before any payload allocation"
  );
  let none: HttpHead = HttpHead.TestParse(
    true,
    "HEAD",
    "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n"
  );
  var made: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(none, HttpBodyLimits{});
  AssertTrueMsg(made.IsOk(), "HEAD metadata length does not become a body budget");
  var decoder: HttpBodyDecoder = move((made.get_if<HttpBodyDecoder>()) as HttpBodyDecoder);
  AssertTrueMsg(
    decoder.IsComplete() && decoder.EndInput().IsOk(),
    "no-body framing is complete immediately"
  );
  let upgrade: HttpHead = HttpHead.TestParse(true, "GET", "HTTP/1.1 101 Switching\r\n\r\n");
  var unsupported: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(upgrade, HttpBodyLimits{});
  AssertTrueMsg(
    unsupported.IsErr() && ((unsupported.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.Unsupported,
    "upgrade requires explicit handoff"
  );
  let tunnel: HttpHead = HttpHead.TestParse(true, "CONNECT", "HTTP/1.1 200 OK\r\n\r\n");
  var unsupported_tunnel: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(tunnel, HttpBodyLimits{});
  AssertTrueMsg(unsupported_tunnel.IsErr(), "tunnel bytes cannot enter a body decoder");
  var invalid: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(HttpHead{}, HttpBodyLimits{});
  AssertTrueMsg(invalid.IsErr(), "unvalidated default head cannot select body framing");
  var caps: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(
    none,
    HttpBodyLimits{max_line_bytes: -1}
  );
  AssertTrueMsg(caps.IsErr(), "negative limits are rejected");
}

@test(tag = "http_core")
func test_http_body_reused_byte_move_and_owned_trailer() {
  var decoder: HttpBodyDecoder = HttpBodyDecoder.TestNew(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    HttpBodyLimits{}
  );
  let wire: string = "1\r\nZ\r\n0\r\nX-Owned: kept\r\n\r\n";
  var byte: <uint8>[1] = <uint8>[1] {
  };
  var dest: <uint8>[1] = <uint8>[1] {
  };
  var i: int32 = 0;
  let input: NetBytes = (NetBytes.FromRaw(&byte[0], 1 as intptr).get_if<NetBytes>()) as NetBytes;
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(
    &mut dest[0],
    1 as intptr
  ).get_if<NetMutableBytes>()) as NetMutableBytes;
  var payload: StringBuffer = StringBuffer.New();
  while i < wire.length {
    byte[0] = wire[i] as uint8;
    let fed: Result<HttpBodyProgress, HttpError> = decoder.Push(input, output);
    AssertTrueMsg(fed.IsOk(), "reused one-byte body input accepted");
    if fed.IsErr() {
      return;
    }

    let step: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
    AssertTrueMsg(step.consumed == (1 as intptr), "one-byte body fragments always consumed");
    if step.produced != (0 as intptr) {
      payload.Append(string.ViewFrom(&dest[0] as *const int8, 1));
    }

    byte[0] = 0u8;
    dest[0] = 0u8;
    i = i + 1;
  }

  let field: HttpField = (decoder.TrailerAt(0).get_if<HttpField>()) as HttpField;
  var moved: HttpBodyDecoder = move(decoder);
  AssertTrueMsg(
    moved.IsComplete() && payload.Take().Equal("Z"),
    "move preserves completed payload cursor"
  );
  moved = HttpBodyDecoder{};
  AssertTrueMsg(field.value.Equal("kept"), "trailer strings own storage after decoder drop");
  AssertTrueMsg(
    moved.Push(input, output).IsErr() && moved.EndInput().IsErr(),
    "default decoder is closed"
  );
}

@test(tag = "http_core")
func test_http_body_binary_octets_and_extension_controls() {
  var decoder: HttpBodyDecoder = HttpBodyDecoder.TestNew(
    "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n",
    HttpBodyLimits{}
  );
  var source: <uint8>[3] = <uint8>[3] {
  };
  source[1] = 255u8;
  source[2] = 127u8;
  var target: <uint8>[4] = <uint8>[4] {
  };
  target[3] = 165u8;
  let input: NetBytes = (NetBytes.FromRaw(&source[0], 3 as intptr).get_if<NetBytes>()) as NetBytes;
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(
    &mut target[0],
    4 as intptr
  ).get_if<NetMutableBytes>()) as NetMutableBytes;
  AssertTrueMsg(
    decoder.Push(
      input,
      output
    ).IsOk() && target[0] == 0u8 && target[1] == 255u8 && target[2] == 127u8 && target[3] == 165u8,
    "payload octets remain opaque and output suffix stays untouched"
  );
  let text: string = "0;x=\"a\"\r\n\r\n";
  var bytes: owned <uint8>[] = new <uint8>[text.length];
  var i: int32 = 0;
  while i < text.length {
    bytes[i] = text[i] as uint8;
    i = i + 1;
  }

  let span: NetBytes = (NetBytes.FromRaw(&bytes[0], text.length as intptr).get_if<NetBytes>()) as NetBytes;
  var control: int32 = 0;
  while control < 2 {
    bytes[5] = 0u8;
    if control == 1 {
      bytes[5] = 127u8;
    }

    var invalid: HttpBodyDecoder = HttpBodyDecoder.TestNew(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
      HttpBodyLimits{}
    );
    let fed: Result<HttpBodyProgress, HttpError> = invalid.Push(span, output);
    AssertTrueMsg(
      fed.IsErr() && ((fed.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.Malformed,
      "quoted chunk extensions reject NUL and DEL"
    );
    control = control + 1;
  }

  bytes[5] = 255u8;
  var opaque: HttpBodyDecoder = HttpBodyDecoder.TestNew(
    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
    HttpBodyLimits{}
  );
  AssertTrueMsg(
    opaque.Push(span, output).IsOk() && opaque.IsComplete(),
    "quoted extension obs-text remains valid opaque data"
  );
}
