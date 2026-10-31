// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of HttpClientTests;

/** @brief Redirect resolution and replay policy acceptance. */

static method(HttpHead) RedirectTestResponse(status: int32, location: ref string) -> HttpHead {
  let wire: string = "HTTP/1.1 ".Concat(((status as uint64) as uint64).ToString()).Concat(
    " Test\r\nContent-Length: 0\r\n"
  ).Concat(location).Concat("\r\n");
  var made: Result<HttpHeadParser, HttpError> = HttpHeadParser.NewResponse("GET", HttpHeadLimits{});
  var parser: HttpHeadParser = move((made.get_if<HttpHeadParser>()) as HttpHeadParser);
  AssertTrueMsg(parser.Push(NetBytes.FromString(wire)).IsOk(), "valid test response head");

  return (parser.Head().get_if<HttpHead>()) as HttpHead;
}

static method(HttpRedirectChain) TestNew(
  url: ref string,
  verb: ref string,
  fields: ref <HttpField>[],
  body: ref string,
  policy: ref HttpRedirectPolicy
) -> HttpRedirectChain {
  var made: Result<HttpRedirectChain, HttpClientError> = HttpRedirectChain.New(
    HttpUrl.TestParse(url),
    verb,
    fields,
    NetBuffer.HttpTestFromString(body),
    HttpClientLimits{},
    policy,
    NetOperationOptions{}
  );
  AssertTrueMsg(made.IsOk(), "redirect chain validates initial request");

  return move((made.get_if<HttpRedirectChain>()) as HttpRedirectChain);
}

method(HttpRedirectChain) TestRequest() -> HttpRedirectRequest {
  let result: Result<HttpRedirectRequest, HttpClientError> = self.Request();
  AssertTrueMsg(result.IsOk(), "request snapshot available");

  return (result.get_if<HttpRedirectRequest>()) as HttpRedirectRequest;
}

@test(tag = "http_core")
func test_http_redirect_reference_rfc_examples() {
  let base: HttpUrl = HttpUrl.TestParse("http://a/b/c/d;p?q");
  var inputs: owned <string>[] = new <string>[] {
    "g", "./g", "g/", "/g", "//g", "?y", "g?y", "#s", "g#s", "g?y#s", ";x", "g;x", "g;x?y#s", "", ".", "./", "..",
      "../", "../g", "../..", "../../", "../../g", "../../../g", "/./g", "/../g", "g.", ".g", "g..", "..g",
      "./../g", "./g/.", "g/./h", "g/../h", "g;x=1/./y", "g;x=1/../y", "g?y/./x", "g?y/../x", "g#s/../x"
  };
  var outputs: owned <string>[] = new <string>[] {
    "http://a/b/c/g", "http://a/b/c/g", "http://a/b/c/g/", "http://a/g", "http://g/", "http://a/b/c/d;p?y",
      "http://a/b/c/g?y", "http://a/b/c/d;p?q", "http://a/b/c/g", "http://a/b/c/g?y", "http://a/b/c/;x",
      "http://a/b/c/g;x", "http://a/b/c/g;x?y", "http://a/b/c/d;p?q", "http://a/b/c/", "http://a/b/c/",
      "http://a/b/", "http://a/b/", "http://a/b/g", "http://a/", "http://a/", "http://a/g", "http://a/g",
      "http://a/g", "http://a/g", "http://a/b/c/g.", "http://a/b/c/.g", "http://a/b/c/g..", "http://a/b/c/..g",
      "http://a/b/g", "http://a/b/c/g/", "http://a/b/c/g/h", "http://a/b/c/h", "http://a/b/c/g;x=1/y",
      "http://a/b/c/y", "http://a/b/c/g?y/./x", "http://a/b/c/g?y/../x", "http://a/b/c/g"
  };
  var i: int32 = 0;
  while i < inputs.length {
    let result: Result<HttpUrl, HttpError> = base.Resolve(inputs[i]);
    AssertTrueMsg(result.IsOk(), inputs[i]);
    if result.IsOk() {
      AssertTrueMsg(((result.get_if<HttpUrl>()) as HttpUrl).ToString().Equal(outputs[i]), inputs[i]);
    }

    i = i + 1;
  }
}

@test(tag = "http_core")
func test_http_redirect_resolution_validation_and_origin() {
  let base: HttpUrl = HttpUrl.TestParse("https://LOCALHOST:443/a//b?q");
  let dotted: HttpUrl = HttpUrl.TestParse("https://localhost/x/../y?q");
  AssertTrueMsg(
    ((dotted.Resolve("#fragment").get_if<HttpUrl>()) as HttpUrl).Target().Equal("/x/../y?q")
      && ((dotted.Resolve("?z").get_if<HttpUrl>()) as HttpUrl).Target().Equal("/x/../y?z"),
    "empty-path references preserve the base path verbatim"
  );
  AssertTrueMsg(
    (base.Resolve("../%2e%2e/%2f?").get_if<HttpUrl>() as HttpUrl).Target().Equal("/a/%2e%2e/%2f?"),
    "escaped dots/slash stay literal and repeated segments preserved"
  );
  AssertTrueMsg(
    base.Resolve("bad%/../ok").IsErr()
      && base.Resolve("x\\evil/../ok").IsErr()
      && base.Resolve("javascript:x").IsErr()
      && base.Resolve("http:g").IsErr()
      && base.Resolve("//user@host/").IsErr(),
    "validate components before normalization and reject unsupported schemes/authority"
  );
  AssertTrueMsg(
    base.SameOrigin(HttpUrl.TestParse("https://localhost/x"))
      && !base.SameOrigin(HttpUrl.TestParse("http://localhost/x"))
      && !base.SameOrigin(HttpUrl.TestParse("https://localhost:444/x"))
      && !base.SameOrigin(HttpUrl{}),
    "origin includes scheme/canonical host/effective port"
  );
}

@test(tag = "http_core")
func test_http_redirect_post_rewrite_and_snapshot_lifetime() {
  var fields: owned <HttpField>[] = new <HttpField>[] {
    HttpField{name: "Content-Type", value: "text/plain"}, HttpField{
      name: "Content-Encoding",
      value: "identity"
    }, HttpField{name: "X-Keep", value: "ok"}
  };
  var chain: HttpRedirectChain = HttpRedirectChain.TestNew(
    "http://localhost/a",
    "POST",
    fields,
    "payload",
    HttpRedirectPolicy{}
  );
  let old: HttpRedirectRequest = (chain).TestRequest();
  let followed: Result<bool, HttpClientError> = chain.Follow(HttpHead.RedirectTestResponse(
    302,
    "Location: ../next\r\n"
  ));
  AssertTrueMsg(followed.IsOk() && ((followed.get_if<bool>()) as bool), "POST 302 becomes GET");
  let next: HttpRedirectRequest = (chain).TestRequest();
  chain = HttpRedirectChain{};
  AssertTrueMsg(
    next.Verb().Equal("GET")
      && next.Body().Len() == (0 as intptr)
      && next.FieldCount() == 1
      && next.Url().Target().Equal("/next"),
    "rewrite clears body and representation fields"
  );
  AssertTrueMsg(
    old.Verb().Equal("POST") && old.Body().Len() == (7 as intptr) && next.Head().Len() >(0 as intptr),
    "old and next snapshots independently own data after chain drop"
  );
}

@test(tag = "http_core")
func test_http_redirect_preserved_replay_requires_opt_in() {
  var chain: HttpRedirectChain = HttpRedirectChain.TestNew(
    "http://localhost/",
    "POST",
    new <HttpField>[0],
    "abc",
    HttpRedirectPolicy{}
  );
  let failed: Result<bool, HttpClientError> = chain.Follow(HttpHead.RedirectTestResponse(307, "Location: /next\r\n"));
  AssertTrueMsg(
    failed.IsErr()
      && (
        ((failed.get_if<HttpClientError>()) as HttpClientError).protocol_error as HttpError
      ).kind == HttpErrorKind.ReplayRejected
      && chain.Count() == 0
      && chain.Request().IsErr(),
    "307 POST fails closed without replay permission"
  );
  var allowed: HttpRedirectChain = HttpRedirectChain.TestNew(
    "http://localhost/",
    "POST",
    new <HttpField>[0],
    "abc",
    HttpRedirectPolicy{allow_unsafe_replay: true}
  );
  AssertTrueMsg(
    allowed.Follow(HttpHead.RedirectTestResponse(308, "Location: /next\r\n")).IsOk(),
    "308 preserved replay explicitly enabled"
  );
  let request: HttpRedirectRequest = (allowed).TestRequest();
  AssertTrueMsg(
    request.Verb().Equal("POST") && request.Body().Len() == (3 as intptr),
    "method and immutable body preserved"
  );
}

@test(tag = "http_core")
func test_http_redirect_cross_origin_filters_and_no_downgrade() {
  var fields: owned <HttpField>[] = new <HttpField>[] {
    HttpField{
      name: "Authorization",
      value: "secret"
    }, HttpField{name: "Cookie", value: "secret"}, HttpField{name: "X-Token", value: "secret"},
      HttpField{name: "Origin", value: "secret"}, HttpField{name: "Referer", value: "secret"},
      HttpField{name: "Accept", value: "text/plain"}, HttpField{
      name: "Connection",
      value: "User-Agent"
    }, HttpField{name: "User-Agent", value: "nominated"}
  };
  var chain: HttpRedirectChain = HttpRedirectChain.TestNew(
    "http://localhost/",
    "GET",
    fields,
    "",
    HttpRedirectPolicy{allow_cross_origin: true}
  );
  AssertTrueMsg(
    chain.Follow(HttpHead.RedirectTestResponse(301, "Location: http://localhost:81/\r\n")).IsOk(),
    "explicit cross-port follow allowed"
  );
  let next: HttpRedirectRequest = (chain).TestRequest();
  AssertTrueMsg(
    next.FieldCount() == 1 && ((next.FieldAt(0).get_if<HttpField>()) as HttpField).name.Equal("Accept"),
    "only safe allowlisted non-nominated fields survive"
  );
  AssertTrueMsg(
    chain.Follow(HttpHead.RedirectTestResponse(
      302,
      "Location: http://localhost/\r\n"
    )).IsOk() && (chain).TestRequest().FieldCount() == 1,
    "return to original origin never resurrects credentials"
  );
  var denied: HttpRedirectChain = HttpRedirectChain.TestNew(
    "http://localhost/",
    "GET",
    new <HttpField>[0],
    "",
    HttpRedirectPolicy{}
  );
  AssertTrueMsg(
    denied.Follow(HttpHead.RedirectTestResponse(302, "Location: http://elsewhere/\r\n")).IsErr(),
    "cross-origin disabled by default"
  );
  var secure: HttpRedirectChain = HttpRedirectChain.TestNew(
    "https://localhost/",
    "GET",
    new <HttpField>[0],
    "",
    HttpRedirectPolicy{allow_cross_origin: true, allow_unsafe_replay: true}
  );
  let failed: Result<bool, HttpClientError> = secure.Follow(HttpHead.RedirectTestResponse(
    302,
    "Location: http://localhost/\r\n"
  ));
  AssertTrueMsg(
    failed.IsErr()
      && (
        ((failed.get_if<HttpClientError>()) as HttpClientError).protocol_error as HttpError
      ).kind == HttpErrorKind.InsecureRedirect,
    "HTTPS downgrade cannot be enabled by another permission"
  );
}

@test(tag = "http_core")
func test_http_redirect_limits_locations_and_terminal_response() {
  var chain: HttpRedirectChain = HttpRedirectChain.TestNew(
    "http://localhost/",
    "GET",
    new <HttpField>[0],
    "",
    HttpRedirectPolicy{max_redirects: 1}
  );
  AssertTrueMsg(
    chain.Follow(HttpHead.RedirectTestResponse(302, "Location: #same\r\n")).IsOk() && chain.Count() == 1,
    "fragment-only self redirect consumes a hop"
  );
  let failed: Result<bool, HttpClientError> = chain.Follow(HttpHead.RedirectTestResponse(302, "Location: /\r\n"));
  AssertTrueMsg(
    failed.IsErr()
      && (
        ((failed.get_if<HttpClientError>()) as HttpClientError).protocol_error as HttpError
      ).kind == HttpErrorKind.RedirectLimit,
    "cycles bounded by exact hop cap"
  );
  var duplicate: HttpRedirectChain = HttpRedirectChain.TestNew(
    "http://localhost/",
    "GET",
    new <HttpField>[0],
    "",
    HttpRedirectPolicy{}
  );
  AssertTrueMsg(
    duplicate.Follow(HttpHead.RedirectTestResponse(
      302,
      "Location: /one\r\nLocation: /two\r\n"
    )).IsErr() && duplicate.Follow(HttpHead.RedirectTestResponse(200, "")).IsErr(),
    "ambiguous location remains terminal"
  );
  var terminal: HttpRedirectChain = HttpRedirectChain.TestNew(
    "http://localhost/",
    "GET",
    new <HttpField>[0],
    "",
    HttpRedirectPolicy{}
  );
  let done: Result<bool, HttpClientError> = terminal.Follow(HttpHead.RedirectTestResponse(302, ""));
  AssertTrueMsg(
    done.IsOk() && ! ((done.get_if<bool>()) as bool) && terminal.Request().IsErr(),
    "missing location is an observable terminal response"
  );
}

@test(tag = "http_core")
func test_http_redirect_method_status_matrix() {
  var statuses: owned <int32>[] = new <int32>[] {
    301, 302, 303, 307, 308
  };
  var methods: owned <string>[] = new <string>[] {
    "GET", "HEAD", "OPTIONS", "POST", "PUT", "post"
  };
  var i: int32 = 0;
  while i < statuses.length {
    var j: int32 = 0;
    while j < methods.length {
      var chain: HttpRedirectChain = HttpRedirectChain.TestNew(
        "http://localhost/start",
        methods[j],
        new <HttpField>[0],
        "",
        HttpRedirectPolicy{}
      );
      let rewrites: bool = ((statuses[i] == 301 || statuses[i] == 302) && methods[j].Equal("POST"))
        || (statuses[i] == 303 && !methods[j].Equal("HEAD"));
      let allowed: bool = rewrites
        || methods[j].Equal("GET")
        || methods[j].Equal("HEAD")
        || methods[j].Equal("OPTIONS");
      let result: Result<bool, HttpClientError> = chain.Follow(HttpHead.RedirectTestResponse(
        statuses[i],
        "Location: /next\r\n"
      ));
      AssertTrueMsg(result.IsOk() == allowed, "status/method replay matrix");
      if result.IsOk() {
        let request: HttpRedirectRequest = (chain).TestRequest();
        var expected: string = methods[j];
        if rewrites {
          expected = "GET";
        }

        AssertTrueMsg(request.Verb().Equal(expected), "correct case-sensitive method rewrite");
      }

      j = j + 1;
    }

    i = i + 1;
  }

  var body: HttpRedirectChain = HttpRedirectChain.TestNew(
    "http://localhost/",
    "GET",
    new <HttpField>[0],
    "x",
    HttpRedirectPolicy{}
  );
  AssertTrueMsg(
    body.Follow(HttpHead.RedirectTestResponse(307, "Location: /next\r\n")).IsErr(),
    "even GET body replay requires explicit permission"
  );
}

@test(tag = "http_core")
func test_http_redirect_same_origin_hop_fields_and_borrowed_sources() {
  var bytes: <int8>[6] = <int8>[6] {
  };
  bytes[0] = 's';
  bytes[1] = 'e';
  bytes[2] = 'c';
  bytes[3] = 'r';
  bytes[4] = 'e';
  bytes[5] = 't';
  var fields: owned <HttpField>[] = new <HttpField>[] {
    HttpField{
      name: "Authorization",
      value: string.ViewFrom(&bytes[0], 6)
    }, HttpField{name: "Connection", value: "X-Hop"}, HttpField{name: "X-Hop", value: "remove"}, HttpField{
      name: "Proxy-Authorization",
      value: "remove"
    }
  };
  var chain: HttpRedirectChain = HttpRedirectChain.TestNew(
    "http://localhost/",
    "GET",
    fields,
    "",
    HttpRedirectPolicy{}
  );
  bytes[0] = 'X';
  fields[0].value = "changed";
  AssertTrueMsg(
    chain.Follow(HttpHead.RedirectTestResponse(307, "Location: /next\r\n")).IsOk(),
    "same-origin GET replay allowed"
  );
  let next: HttpRedirectRequest = (chain).TestRequest();
  AssertTrueMsg(
    next.FieldCount() == 1 && ((next.FieldAt(0).get_if<HttpField>()) as HttpField).value.Equal("secret"),
    "same-origin owned credential retained and nominated/proxy fields removed"
  );
}

@test(tag = "http_core")
func test_http_redirect_controls_defaults_and_sticky_invalid_input() {
  var token: NetCancellation = NetCancellation.New();
  let options: NetOperationOptions = NetOperationOptions{cancellation: token};
  var made: Result<HttpRedirectChain, HttpClientError> = HttpRedirectChain.New(
    HttpUrl.TestParse("http://localhost/"),
    "GET",
    new <HttpField>[0],
    NetBuffer{},
    HttpClientLimits{},
    HttpRedirectPolicy{},
    options
  );
  AssertTrueMsg(made.IsOk(), "controlled chain admission");
  var chain: HttpRedirectChain = move((made.get_if<HttpRedirectChain>()) as HttpRedirectChain);
  token.Cancel();
  let failed: Result<bool, HttpClientError> = chain.Follow(HttpHead.RedirectTestResponse(302, "Location: /next\r\n"));
  AssertTrueMsg(
    failed.IsErr()
      && (
        ((failed.get_if<HttpClientError>()) as HttpClientError).transport_error as NetError
      ).kind == NetErrorKind.Cancelled
      && chain.Count() == 0
      && chain.Request().IsErr(),
    "original cancellation prevents decision publication and further request access"
  );
  AssertTrueMsg(
    HttpRedirectChain.New(
      HttpUrl.TestParse("http://localhost/"),
      "GET",
      new <HttpField>[0],
      NetBuffer{},
      HttpClientLimits{},
      HttpRedirectPolicy{max_redirects: 33},
      NetOperationOptions{}
    ).IsErr(),
    "hard policy cap enforced"
  );
  var invalid: HttpRedirectChain = HttpRedirectChain.TestNew(
    "http://localhost/",
    "GET",
    new <HttpField>[0],
    "",
    HttpRedirectPolicy{}
  );
  AssertTrueMsg(
    invalid.Follow(HttpHead{}).IsErr() && invalid.Request().IsErr(),
    "invalid/default response head retires chain"
  );
  var capped: HttpRedirectChain = HttpRedirectChain.TestNew(
    "http://localhost/",
    "GET",
    new <HttpField>[0],
    "",
    HttpRedirectPolicy{}
  );
  var i: int32 = 0;
  while i < 5 {
    AssertTrueMsg(
      capped.Follow(HttpHead.RedirectTestResponse(302, "Location: /\r\n")).IsOk(),
      "default five redirects accepted"
    );
    i = i + 1;
  }

  AssertTrueMsg(
    capped.Follow(HttpHead.RedirectTestResponse(302, "Location: /\r\n")).IsErr(),
    "sixth default redirect rejected"
  );
}

static method(HttpRedirectChain) TestStreaming(
  verb: ref string,
  fields: ref <HttpField>[],
  plan: ref HttpBodyPlan,
  policy: ref HttpRedirectPolicy,
  replay: HttpBodyReplayPolicy
) -> HttpRedirectChain {
  var made: Result<HttpRedirectChain, HttpClientError> = HttpRedirectChain.NewStreaming(
    HttpUrl.TestParse("https://localhost/start"),
    verb,
    fields,
    plan,
    HttpClientLimits{},
    policy,
    replay,
    NetOperationOptions{}
  );
  AssertTrueMsg(made.IsOk(), "streamed redirect validates metadata without retaining a body");

  return move((made.get_if<HttpRedirectChain>()) as HttpRedirectChain);
}

@test(tag = "http_core")
func test_http_stream_redirect_snapshot_and_fixed_replay() {
  var chain: HttpRedirectChain = HttpRedirectChain.TestStreaming(
    "POST",
    new <HttpField>[0],
    HttpBodyPlan{kind: HttpBodyKind.ContentLength, length: 6u64},
    HttpRedirectPolicy{allow_unsafe_replay: true},
    HttpBodyReplayPolicy.Explicit
  );
  let first: HttpRedirectRequest = (chain).TestRequest();
  AssertTrueMsg(
    first.IsStreaming() && first.Body().Len() == (0 as intptr) && first.UploadPlan().length == 6u64,
    "stream snapshot retains a plan rather than a fake empty replay body"
  );
  AssertTrueMsg(
    chain.Follow(HttpHead.RedirectTestResponse(307, "Location: /next\r\n")).IsOk(),
    "fixed body replay explicitly allowed"
  );
  let next: HttpRedirectRequest = (chain).TestRequest();
  chain = HttpRedirectChain{};
  AssertTrueMsg(
    next.Verb().Equal("POST")
      && next.UploadPlan().length == 6u64
      && next.Url().Target().Equal("/next")
      && first.Url().Target().Equal("/start"),
    "snapshots own independent routing and preserved framing after chain drop"
  );
  var resolver: AsyncResolver = AsyncResolver{};
  AssertTrueMsg(
    next.OpenTcp(resolver, HttpDialOptions{}).IsErr(),
    "immutable open cannot silently discard a streamed producer"
  );
}

@test(tag = "http_core")
func test_http_stream_redirect_two_permissions_and_sticky_failure() {
  var denied: HttpRedirectChain = HttpRedirectChain.TestStreaming(
    "POST",
    new <HttpField>[0],
    HttpBodyPlan{kind: HttpBodyKind.ContentLength, length: 6u64},
    HttpRedirectPolicy{allow_unsafe_replay: true},
    HttpBodyReplayPolicy.Never
  );
  let result: Result<bool, HttpClientError> = denied.Follow(HttpHead.RedirectTestResponse(308, "Location: /next\r\n"));
  AssertTrueMsg(
    result.IsErr()
      && (
        ((result.get_if<HttpClientError>()) as HttpClientError).protocol_error as HttpError
      ).kind == HttpErrorKind.ReplayRejected
      && denied.Count() == 0
      && denied.Request().IsErr(),
    "unsafe replay permission cannot manufacture a rewindable producer"
  );
  var no_opt_in: HttpRedirectChain = HttpRedirectChain.TestStreaming(
    "GET",
    new <HttpField>[0],
    HttpBodyPlan{kind: HttpBodyKind.Chunked},
    HttpRedirectPolicy{},
    HttpBodyReplayPolicy.Explicit
  );
  AssertTrueMsg(
    no_opt_in.Follow(HttpHead.RedirectTestResponse(307, "Location: /next\r\n")).IsErr(),
    "even GET chunked producers require unsafe replay opt-in"
  );
  var empty: HttpRedirectChain = HttpRedirectChain.TestStreaming(
    "GET",
    new <HttpField>[0],
    HttpBodyPlan{},
    HttpRedirectPolicy{},
    HttpBodyReplayPolicy.Never
  );
  AssertTrueMsg(
    empty.Follow(HttpHead.RedirectTestResponse(308, "Location: /next\r\n")).IsOk(),
    "known-empty safe requests need no producer replay permission"
  );
}

@test(tag = "http_core")
func test_http_stream_redirect_rewrite_clears_producer_negotiation() {
  let fields: owned <HttpField>[] = new <HttpField>[] {
    HttpField{name: "Expect", value: "100-continue"}, HttpField{name: "Trailer", value: "X-End"}, HttpField{
      name: "Content-Type",
      value: "text/plain"
    }, HttpField{name: "X-Keep", value: "ok"}
  };
  var chain: HttpRedirectChain = HttpRedirectChain.TestStreaming(
    "POST",
    fields,
    HttpBodyPlan{kind: HttpBodyKind.Chunked},
    HttpRedirectPolicy{},
    HttpBodyReplayPolicy.Never
  );
  AssertTrueMsg(
    chain.Follow(HttpHead.RedirectTestResponse(303, "Location: /next\r\n")).IsOk(),
    "303 safely drops even a non-replayable producer"
  );
  let next: HttpRedirectRequest = (chain).TestRequest();
  AssertTrueMsg(
    next.IsStreaming()
      && next.Verb().Equal("GET")
      && next.UploadPlan().kind == HttpBodyKind.None
      && next.FieldCount() == 1
      && ((next.FieldAt(0).get_if<HttpField>()) as HttpField).name.Equal("X-Keep"),
    "GET rewrite clears Expect, trailers and representation metadata"
  );
}

@test(tag = "http_core")
func test_http_stream_redirect_trailer_and_cross_origin_policy() {
  var fields: owned <HttpField>[] = new <HttpField>[] {
    HttpField{name: "Trailer", value: "X-End"}
  };
  var chain: HttpRedirectChain = HttpRedirectChain.TestStreaming(
    "PUT",
    fields,
    HttpBodyPlan{kind: HttpBodyKind.Chunked},
    HttpRedirectPolicy{allow_unsafe_replay: true, allow_cross_origin: true},
    HttpBodyReplayPolicy.Explicit
  );
  AssertTrueMsg(
    chain.Follow(HttpHead.RedirectTestResponse(
      307,
      "Location: /same\r\n"
    )).IsOk() && (chain).TestRequest().FieldCount() == 1,
    "same-origin replay preserves promised chunked trailers"
  );
  AssertTrueMsg(
    chain.Follow(HttpHead.RedirectTestResponse(307, "Location: https://elsewhere/\r\n")).IsErr() && chain.Count() == 1,
    "cross-origin replay cannot silently remove promised trailers"
  );
  fields = new <HttpField>[] {
    HttpField{name: "Connection", value: "Trailer"}, HttpField{name: "Trailer", value: "X-End"}
  };
  var nominated: HttpRedirectChain = HttpRedirectChain.TestStreaming(
    "PUT",
    fields,
    HttpBodyPlan{kind: HttpBodyKind.Chunked},
    HttpRedirectPolicy{allow_unsafe_replay: true},
    HttpBodyReplayPolicy.Explicit
  );
  AssertTrueMsg(
    nominated.Follow(HttpHead.RedirectTestResponse(307, "Location: /same\r\n")).IsErr(),
    "connection-nominated trailer promise cannot silently disappear"
  );
}

@test(tag = "http_core")
func test_http_stream_redirect_controls_precede_replay_and_keep_filters() {
  var token: NetCancellation = NetCancellation.New();
  var made: Result<HttpRedirectChain, HttpClientError> = HttpRedirectChain.NewStreaming(
    HttpUrl.TestParse("https://localhost/start"),
    "POST",
    new <HttpField>[0],
    HttpBodyPlan{kind: HttpBodyKind.ContentLength, length: 6u64},
    HttpClientLimits{},
    HttpRedirectPolicy{allow_unsafe_replay: true},
    HttpBodyReplayPolicy.Explicit,
    NetOperationOptions{cancellation: token}
  );
  var chain: HttpRedirectChain = move((made.get_if<HttpRedirectChain>()) as HttpRedirectChain);
  token.Cancel();
  let failed: Result<bool, HttpClientError> = chain.Follow(HttpHead.RedirectTestResponse(307, "Location: /next\r\n"));
  AssertTrueMsg(
    failed.IsErr()
      && (
        ((failed.get_if<HttpClientError>()) as HttpClientError).transport_error as NetError
      ).kind == NetErrorKind.Cancelled
      && chain.Count() == 0,
    "original controls win before replay decision"
  );
  let fields: owned <HttpField>[] = new <HttpField>[] {
    HttpField{name: "Authorization", value: "secret"}, HttpField{
      name: "Content-Type",
      value: "text/plain"
    }, HttpField{name: "X-Secret", value: "secret"}
  };
  var cross: HttpRedirectChain = HttpRedirectChain.TestStreaming(
    "PUT",
    fields,
    HttpBodyPlan{kind: HttpBodyKind.ContentLength, length: 6u64},
    HttpRedirectPolicy{allow_unsafe_replay: true, allow_cross_origin: true},
    HttpBodyReplayPolicy.Explicit
  );
  AssertTrueMsg(
    cross.Follow(HttpHead.RedirectTestResponse(
      308,
      "Location: https://other/next\r\n"
    )).IsOk() && (cross).TestRequest().FieldCount() == 1,
    "streamed cross-origin filtering retains only existing safe representation fields"
  );
  AssertTrueMsg(
    cross.Follow(HttpHead.RedirectTestResponse(307, "Location: http://other/next\r\n")).IsErr(),
    "streaming replay never enables HTTPS downgrade"
  );
}
