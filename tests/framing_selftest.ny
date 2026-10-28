/** @brief Output framing and one-request response sequencing. */
part of HttpProtocol;
@test(tag = "http_core")
func test_http_response_sequence_smoke() {
  var made: Result<HttpResponseParser, HttpError> = HttpResponseParser.New("GET", HttpResponseLimits{});
  http_test_assert(made.IsOk(), "response sequence construction succeeds");
  var parser: HttpResponseParser = move((made.get_if<HttpResponseParser>()) as HttpResponseParser);
  let wire: string = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
  let fed: Result<HttpResponseProgress, HttpError> = parser.Push(NetBytes.FromString(wire));
  http_test_assert(fed.IsOk() && !parser.IsComplete(), "informational response does not complete request association");
}
func http_test_body_writer(head: ref HttpHead, limits: ref HttpBodyLimits) -> HttpBodyWriter {
  var made: Result<HttpBodyWriter, HttpError> = HttpBodyWriter.New(head, limits);
  http_test_assert(made.IsOk(), "body writer construction succeeds");
  return move((made.get_if<HttpBodyWriter>()) as HttpBodyWriter);
}
func http_test_write(writer: ref mut HttpBodyWriter, payload: ref string, capacity: int32) -> string {
  var output: StringBuffer = StringBuffer.New(); var used: intptr = 0 as intptr;
  var storage: owned <uint8>[] = new <uint8>[capacity];
  let range: NetMutableBytes = (NetMutableBytes.FromRaw(&mut storage[0], capacity as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  var calls: int32 = 0;
  while calls < 100000 {
    let input: NetBytes = (NetBytes.FromString(payload).Slice(used, (payload.length as intptr)-used).get_if<NetBytes>()) as NetBytes;
    let fed: Result<HttpBodyProgress, HttpError> = writer.Push(input, range);
    http_test_assert(fed.IsOk(), "streaming writer call succeeds"); if fed.IsErr() { return output.Take(); }
    let step: HttpBodyProgress = (fed.get_if<HttpBodyProgress>()) as HttpBodyProgress;
    http_test_assert(step.consumed >= (0 as intptr) && step.consumed <= input.Len() && step.produced >= (0 as intptr) && step.produced <= range.Len(), "writer progress stays within caller ranges");
    used = used+step.consumed;
    if step.produced > (0 as intptr) { output.Append(string.ViewFrom(&storage[0] as *const int8, step.produced as int32)); }
    if step.state == HttpBodyState.NeedInput || step.state == HttpBodyState.Complete {
      http_test_assert(used == payload.length as intptr, "writer never silently discards supplied payload"); return output.Take();
    }
    http_test_assert(step.produced != (0 as intptr) || step.consumed != (0 as intptr), "writer progresses with nonempty output capacity");
    if step.produced == (0 as intptr) && step.consumed == (0 as intptr) { return output.Take(); }
    calls = calls+1;
  }
  http_test_assert(false, "writer terminates within bounded test calls"); return output.Take();
}
func http_test_response_parser(verb: ref string, limits: ref HttpResponseLimits) -> HttpResponseParser {
  var made: Result<HttpResponseParser, HttpError> = HttpResponseParser.New(verb, limits);
  http_test_assert(made.IsOk(), "response parser construction succeeds");
  return move((made.get_if<HttpResponseParser>()) as HttpResponseParser);
}
func http_test_response_feed(parser: ref mut HttpResponseParser, wire: ref string) -> intptr {
  var used: intptr = 0 as intptr;
  while used < wire.length as intptr && !parser.IsComplete() {
    let input: NetBytes = (NetBytes.FromString(wire).Slice(used, (wire.length as intptr)-used).get_if<NetBytes>()) as NetBytes;
    let fed: Result<HttpResponseProgress, HttpError> = parser.Push(input);
    http_test_assert(fed.IsOk(), "valid response sequence is accepted"); if fed.IsErr() { return used; }
    let step: HttpResponseProgress = (fed.get_if<HttpResponseProgress>()) as HttpResponseProgress;
    http_test_assert(step.consumed > (0 as intptr), "response fragments advance"); if step.consumed == (0 as intptr) { return used; }
    used = used+step.consumed;
    if step.state == HttpResponseState.Informational {
      let head: HttpHead = (parser.Head().get_if<HttpHead>()) as HttpHead;
      http_test_assert(head.Status() >= 100 && head.Status() < 200 && head.Status() != 101 && !parser.IsComplete(), "each non-switching informational event is observable");
    }
  }
  return used;
}
@test(tag = "http_core")
func test_http_body_writer_fixed_capacities() {
  let head: HttpHead = http_test_head(true, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
  var capacity: int32 = 1;
  while capacity <= 6 {
    var writer: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{});
    http_test_assert(http_test_write(writer, "abcde", capacity).Equal("abcde") && writer.IsComplete(), "fixed bodies preserve accepted bytes under partial output");
    http_test_assert(writer.Finish(new <HttpField>[0]).IsOk(), "exact fixed length finishes idempotently");
    http_test_assert(http_test_write(writer, "", capacity).length == 0, "completed fixed writer emits no duplicate bytes"); capacity = capacity+1;
  }
}
@test(tag = "http_core")
func test_http_body_writer_fixed_shortage_and_excess() {
  let head: HttpHead = http_test_head(true, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n");
  var writer: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{});
  http_test_assert(http_test_write(writer, "ab", 1).Equal("ab"), "accepted prefix remains exact before a short source");
  let end: Result<bool, HttpError> = writer.Finish(new <HttpField>[0]);
  http_test_assert(end.IsErr() && ((end.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.UnexpectedEof && !writer.IsComplete(), "short fixed input is a terminal EOF error");
  var excessive: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{});
  var storage: <uint8>[1] = <uint8>[1]{}; storage[0] = 165u8;
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut storage[0], 1 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  let fed: Result<HttpBodyProgress, HttpError> = excessive.Push(NetBytes.FromString("abcd"), output);
  http_test_assert(fed.IsErr() && ((fed.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.InvalidFraming && storage[0] == 165u8, "excess fixed payload fails without writing any output");
  http_test_assert(excessive.Push(NetBytes.FromString("abc"), output).IsErr() && excessive.Finish(new <HttpField>[0]).IsErr(), "write errors cannot be retried as a different message");
}
@test(tag = "http_core")
func test_http_body_writer_absent_and_metadata_length() {
  let head: HttpHead = http_test_head(true, "HEAD", "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n");
  var writer: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{});
  http_test_assert(writer.IsComplete() && http_test_write(writer, "", 1).length == 0, "HEAD metadata length never creates output");
  http_test_assert(writer.Push(NetBytes.FromString("x"), NetMutableBytes{}).IsErr() && !writer.IsComplete(), "no-body plans reject accidental payload");
  let zero: HttpHead = http_test_head(true, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
  var empty: HttpBodyWriter = http_test_body_writer(zero, HttpBodyLimits{});
  http_test_assert(empty.IsComplete() && empty.Finish(new <HttpField>[0]).IsOk(), "zero fixed length needs no body framing");
}
@test(tag = "http_core")
func test_http_body_writer_eof_and_budget() {
  let head: HttpHead = http_test_head(true, "GET", "HTTP/1.0 200 OK\r\n\r\n");
  var writer: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{max_body_bytes: 3u64});
  http_test_assert(http_test_write(writer, "abc", 1).Equal("abc") && !writer.IsComplete(), "close-delimited output remains open until Finish");
  http_test_assert(writer.Finish(new <HttpField>[0]).IsOk() && writer.IsComplete(), "EOF framing generates no synthetic wire terminator");
  var excessive: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{max_body_bytes: 3u64});
  let fed: Result<HttpBodyProgress, HttpError> = excessive.Push(NetBytes.FromString("abcd"), NetMutableBytes{});
  http_test_assert(fed.IsErr() && ((fed.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.LimitExceeded, "offered payload cannot bypass body caps under backpressure");
}
@test(tag = "http_core")
func test_http_body_writer_chunked_capacities_and_roundtrip() {
  let head: HttpHead = http_test_head(true, "GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
  var capacity: int32 = 1;
  while capacity <= 12 {
    var writer: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{});
    let payload: string = http_test_write(writer, "abc", capacity);
    http_test_assert(writer.Finish(new <HttpField>[0]).IsOk(), "chunked Finish queues terminal framing");
    let wire: string = payload.Concat(http_test_write(writer, "", capacity));
    http_test_assert(wire.Equal("3\r\nabc\r\n0\r\n\r\n") && writer.IsComplete(), "partial framing is emitted exactly once at every output capacity");
    var decoder: HttpBodyDecoder = http_test_body("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", HttpBodyLimits{});
    http_test_assert(http_test_body_feed(decoder, wire.Concat("NEXT")).Equal("abc") && decoder.IsComplete(), "generated chunk wire roundtrips with a preserved next-message suffix");
    http_test_assert(writer.Finish(new <HttpField>[0]).IsOk() && http_test_write(writer, "", capacity).length == 0, "repeated empty Finish never duplicates the zero chunk");
    capacity = capacity+1;
  }
}
@test(tag = "http_core")
func test_http_body_writer_large_chunk_bound() {
  let head: HttpHead = http_test_head(false, "", "POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n");
  var payload: StringBuffer = StringBuffer.NewWithCapacity(20000); var i: int32 = 0;
  while i < 20000 { payload.Append("z"); i = i+1; }
  let data: string = payload.Take(); var writer: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{});
  let first: string = http_test_write(writer, data, 37);
  http_test_assert(writer.Finish(new <HttpField>[0]).IsOk(), "large streaming source can finish");
  let wire: string = first.Concat(http_test_write(writer, "", 7));
  http_test_assert(wire.Substring(0, 6).Equal("4000\r\n") && wire.Substring(16392, 5).Equal("e20\r\n"), "generated chunks are bounded to 16 KiB with canonical lowercase sizes");
  var decoded_result: Result<HttpBodyDecoder, HttpError> = HttpBodyDecoder.New(head, HttpBodyLimits{});
  var decoder: HttpBodyDecoder = move((decoded_result.get_if<HttpBodyDecoder>()) as HttpBodyDecoder);
  http_test_assert(http_test_body_feed(decoder, wire).Equal(data) && decoder.IsComplete(), "request bodies roundtrip without buffering the source in the writer");
}
@test(tag = "http_core")
func test_http_body_writer_owned_trailers_and_move() {
  let head: HttpHead = http_test_head(true, "GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: x-hash, X-End\r\n\r\n");
  var writer: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{});
  let payload: string = http_test_write(writer, "a", 1);
  var trailers: <HttpField>[2] = <HttpField>[2]{};
  trailers[0] = HttpField{name: "X-Hash", value: "first"}; trailers[1] = HttpField{name: "x-hash", value: "second"};
  let finish: Result<bool, HttpError> = writer.Finish(trailers);
  http_test_assert(finish.IsOk() && !((finish.get_if<bool>()) as bool), "captured trailers remain pending until wire drain");
  trailers[0].value = "changed"; trailers[1].name = "Changed";
  var moved: HttpBodyWriter = move(writer);
  let wire: string = payload.Concat(http_test_write(moved, "", 1));
  moved = HttpBodyWriter{};
  http_test_assert(wire.Equal("1\r\na\r\n0\r\nX-Hash: first\r\nx-hash: second\r\n\r\n"), "trailers are owned, ordered, case-preserved and independent of source mutation/drop");
  http_test_assert(moved.Finish(new <HttpField>[0]).IsErr() && moved.Push(NetBytes{}, NetMutableBytes{}).IsErr(), "default body writer is closed");
}
func http_test_writer_new_reject(wire: ref string, expected: HttpErrorKind) -> void {
  let head: HttpHead = http_test_head(true, "GET", wire);
  var made: Result<HttpBodyWriter, HttpError> = HttpBodyWriter.New(head, HttpBodyLimits{});
  http_test_assert(made.IsErr() && ((made.get_if<HttpError>()) as HttpError).kind == expected, "unsafe writer construction is rejected before output");
}
@test(tag = "http_core")
func test_http_body_writer_trailer_declarations() {
  http_test_writer_new_reject("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTrailer: X-End\r\n\r\n", HttpErrorKind.InvalidFraming);
  http_test_writer_new_reject("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Content-Length\r\n\r\n", HttpErrorKind.InvalidFraming);
  http_test_writer_new_reject("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-End,\r\n\r\n", HttpErrorKind.InvalidFraming);
  http_test_writer_new_reject("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: \r\n\r\n", HttpErrorKind.InvalidFraming);
  http_test_writer_new_reject("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Bad\r\nConnection: x-bad\r\n\r\n", HttpErrorKind.InvalidFraming);
  http_test_writer_new_reject("HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n", HttpErrorKind.LimitExceeded);
  http_test_writer_new_reject("HTTP/1.1 101 Switching\r\n\r\n", HttpErrorKind.Unsupported);
}
func http_test_finish_reject(trailer: HttpField, caps: ref HttpBodyLimits, expected: HttpErrorKind) -> void {
  let head: HttpHead = http_test_head(true, "GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n");
  var writer: HttpBodyWriter = http_test_body_writer(head, caps);
  var trailers: <HttpField>[1] = <HttpField>[1]{}; trailers[0] = trailer;
  let ended: Result<bool, HttpError> = writer.Finish(trailers);
  http_test_assert(ended.IsErr() && ((ended.get_if<HttpError>()) as HttpError).kind == expected, "trailer violation is rejected before terminal wire generation");
  http_test_assert(writer.Push(NetBytes{}, NetMutableBytes{}).IsErr() && writer.Finish(new <HttpField>[0]).IsErr() && !writer.IsComplete(), "invalid trailer state remains terminal");
}
@test(tag = "http_core")
func test_http_body_writer_trailer_validation() {
  http_test_finish_reject(HttpField{name: "X-Other", value: "x"}, HttpBodyLimits{}, HttpErrorKind.InvalidFraming);
  http_test_finish_reject(HttpField{name: "Content-Type", value: "text/plain"}, HttpBodyLimits{}, HttpErrorKind.InvalidFraming);
  http_test_finish_reject(HttpField{name: "Bad Name", value: "x"}, HttpBodyLimits{}, HttpErrorKind.Malformed);
  http_test_finish_reject(HttpField{name: "X-End", value: "x\r\nInjected: y"}, HttpBodyLimits{}, HttpErrorKind.Malformed);
  http_test_finish_reject(HttpField{name: "X-End", value: "long"}, HttpBodyLimits{max_line_bytes: 10}, HttpErrorKind.LimitExceeded);
  http_test_finish_reject(HttpField{name: "X-End", value: "a"}, HttpBodyLimits{max_framing_bytes: 14}, HttpErrorKind.LimitExceeded);
}
@test(tag = "http_core")
func test_http_body_writer_framing_budget() {
  let head: HttpHead = http_test_head(true, "GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
  var exact: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{max_framing_bytes: 10});
  let prefix: string = http_test_write(exact, "a", 1);
  http_test_assert(exact.Finish(new <HttpField>[0]).IsOk() && prefix.Concat(http_test_write(exact, "", 1)).Equal("1\r\na\r\n0\r\n\r\n"), "exact framing budget includes header, data delimiter and terminal chunk");
  var terminal: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{max_framing_bytes: 9});
  http_test_assert(http_test_write(terminal, "a", 1).Equal("1\r\na\r\n"), "accepted payload is preserved before terminal budget failure");
  let finish: Result<bool, HttpError> = terminal.Finish(new <HttpField>[0]);
  http_test_assert(finish.IsErr() && ((finish.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.LimitExceeded, "terminal metadata is included in framing admission");
  var first: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{max_framing_bytes: 4});
  var storage: <uint8>[1] = <uint8>[1]{}; storage[0] = 165u8;
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut storage[0], 1 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  let fed: Result<HttpBodyProgress, HttpError> = first.Push(NetBytes.FromString("a"), output);
  http_test_assert(fed.IsErr() && storage[0] == 165u8, "chunk header and suffix are reserved before any header output");
  var line: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{max_line_bytes: 1});
  let wide: Result<HttpBodyProgress, HttpError> = line.Push(NetBytes.FromString("0123456789abcdef"), output);
  http_test_assert(wide.IsErr() && ((wide.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.LimitExceeded && storage[0] == 165u8, "chunk-size line caps apply before any header output");
}
@test(tag = "http_core")
func test_http_body_writer_announced_chunk_shortage_and_finish_drain() {
  let head: HttpHead = http_test_head(true, "GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
  var writer: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{});
  var storage: <uint8>[1] = <uint8>[1]{};
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut storage[0], 1 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  let header: HttpBodyProgress = (writer.Push(NetBytes.FromString("abc"), output).get_if<HttpBodyProgress>()) as HttpBodyProgress;
  http_test_assert(header.consumed == (0 as intptr) && header.produced == (1 as intptr), "partial chunk header reports no accepted payload");
  let short: Result<bool, HttpError> = writer.Finish(new <HttpField>[0]);
  http_test_assert(short.IsErr() && ((short.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.UnexpectedEof, "announced chunk cannot be abandoned by Finish");
  var draining: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{});
  let prefix: HttpBodyProgress = (draining.Push(NetBytes.FromString("a"), output).get_if<HttpBodyProgress>()) as HttpBodyProgress;
  http_test_assert(prefix.consumed == (0 as intptr), "chunk framing can precede payload acceptance");
  let payload: string = http_test_write(draining, "a", 1);
  http_test_assert(draining.Finish(new <HttpField>[0]).IsOk(), "finish can queue final metadata");
  http_test_assert(!draining.IsComplete() && http_test_write(draining, "", 1).Equal("0\r\n\r\n") && draining.IsComplete() && payload.Equal("\r\na\r\n"), "final drain owns pending metadata and emits no payload twice");
}
@test(tag = "http_core")
func test_http_body_writer_finish_behind_pending_delimiter() {
  let head: HttpHead = http_test_head(true, "GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
  var writer: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{});
  let blocked: HttpBodyProgress = (writer.Push(NetBytes.FromString("a"), NetMutableBytes{}).get_if<HttpBodyProgress>()) as HttpBodyProgress;
  http_test_assert(blocked.consumed == (0 as intptr) && blocked.produced == (0 as intptr) && blocked.state == HttpBodyState.NeedOutput, "zero capacity accepts no payload and generates no framing");
  var storage: <uint8>[8] = <uint8>[8]{};
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut storage[0], 8 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  let header: HttpBodyProgress = (writer.Push(NetBytes.FromString("a"), output).get_if<HttpBodyProgress>()) as HttpBodyProgress;
  http_test_assert(header.consumed == (0 as intptr) && header.produced == (3 as intptr) && string.ViewFrom(&storage[0] as *const int8, 3).Equal("1\r\n"), "header output does not accept payload");
  let copied: HttpBodyProgress = (writer.Push(NetBytes.FromString("a"), output).get_if<HttpBodyProgress>()) as HttpBodyProgress;
  http_test_assert(copied.consumed == (1 as intptr) && copied.produced == (1 as intptr) && storage[0] == 97u8, "payload copy queues but does not emit its delimiter");
  http_test_assert(writer.Finish(new <HttpField>[0]).IsOk(), "Finish accepts a fully copied chunk with pending delimiter");
  http_test_assert(http_test_write(writer, "", 1).Equal("\r\n0\r\n\r\n") && writer.IsComplete(), "pending data CRLF precedes final chunk under one-byte output");
}
@test(tag = "http_core")
func test_http_body_writer_binary_and_trailer_count() {
  let head: HttpHead = http_test_head(true, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n");
  var writer: HttpBodyWriter = http_test_body_writer(head, HttpBodyLimits{});
  var bytes: <uint8>[3] = <uint8>[3]{}; bytes[1] = 255u8; bytes[2] = 127u8;
  var storage: <uint8>[4] = <uint8>[4]{}; storage[3] = 165u8;
  let input: NetBytes = (NetBytes.FromRaw(&bytes[0], 3 as intptr).get_if<NetBytes>()) as NetBytes;
  let output: NetMutableBytes = (NetMutableBytes.FromRaw(&mut storage[0], 4 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  let step: HttpBodyProgress = (writer.Push(input, output).get_if<HttpBodyProgress>()) as HttpBodyProgress;
  bytes[1] = 0u8;
  http_test_assert(step.produced == (3 as intptr) && storage[0] == 0u8 && storage[1] == 255u8 && storage[2] == 127u8 && storage[3] == 165u8, "writer copies opaque octets into independent caller-owned output only");
  let chunked: HttpHead = http_test_head(true, "GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n");
  var capped: HttpBodyWriter = http_test_body_writer(chunked, HttpBodyLimits{max_trailers: 1});
  var fields: <HttpField>[2] = <HttpField>[2]{}; fields[0] = HttpField{name: "X-End", value: "a"}; fields[1] = HttpField{name: "X-End", value: "b"};
  let excess: Result<bool, HttpError> = capped.Finish(fields);
  http_test_assert(excess.IsErr() && ((excess.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.LimitExceeded, "duplicate ordinary trailers still consume the trailer count budget");
  var invalid: Result<HttpBodyWriter, HttpError> = HttpBodyWriter.New(HttpHead{}, HttpBodyLimits{});
  http_test_assert(invalid.IsErr(), "default unvalidated head cannot construct a writer");
}
@test(tag = "http_core")
func test_http_response_sequence_every_split() {
  let heads: string = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 199 Extension\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n";
  var split: int32 = 0;
  while split <= heads.length {
    var parser: HttpResponseParser = http_test_response_parser("GET", HttpResponseLimits{});
    let first: intptr = http_test_response_feed(parser, heads.Substring(0, split));
    let rest: intptr = http_test_response_feed(parser, heads.Substring(split, heads.length-split).Concat("abcNEXT"));
    http_test_assert(first+rest == heads.length as intptr && parser.InformationalCount() == 3 && parser.IsComplete(), "all response splits preserve body/pipeline suffixes and final association");
    let head: HttpHead = (parser.EndInput().get_if<HttpHead>()) as HttpHead;
    http_test_assert(head.Status() == 200 && ((head.BodyPlan().get_if<HttpBodyPlan>()) as HttpBodyPlan).length == 3u64, "final framing remains associated with the original GET");
    let again: HttpResponseProgress = (parser.Push(NetBytes.FromString("abcNEXT")).get_if<HttpResponseProgress>()) as HttpResponseProgress;
    http_test_assert(again.consumed == (0 as intptr) && again.state == HttpResponseState.Final, "final association cannot advance into a body or next request"); split = split+1;
  }
}
@test(tag = "http_core")
func test_http_response_informational_count_limits() {
  let wire: string = "HTTP/1.1 100 Continue\r\n\r\n";
  var parser: HttpResponseParser = http_test_response_parser("GET", HttpResponseLimits{max_informational: 1});
  http_test_assert(parser.Push(NetBytes.FromString(wire)).IsOk() && parser.InformationalCount() == 1, "first informational response consumes the count budget");
  let excess: Result<HttpResponseProgress, HttpError> = parser.Push(NetBytes.FromString(wire));
  http_test_assert(excess.IsErr() && ((excess.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.LimitExceeded && ((excess.get_if<HttpError>()) as HttpError).offset == (wire.length*2) as int64, "excess informational response fails at an aggregate byte offset");
  http_test_assert(parser.Head().IsErr() && parser.EndInput().IsErr() && !parser.IsComplete(), "count failure cannot expose a final response");
  var defaults: HttpResponseParser = http_test_response_parser("GET", HttpResponseLimits{}); var i: int32 = 0;
  while i < 16 { http_test_assert(defaults.Push(NetBytes.FromString(wire)).IsOk(), "default informational count includes 16 events"); i = i+1; }
  http_test_assert(defaults.Push(NetBytes.FromString(wire)).IsErr(), "default count rejects the seventeenth event");
  var bad: Result<HttpResponseParser, HttpError> = HttpResponseParser.New("GET", HttpResponseLimits{max_informational: 65});
  http_test_assert(bad.IsErr(), "hard informational cap cannot be increased beyond 64");
}
@test(tag = "http_core")
func test_http_response_aggregate_and_per_head_limits() {
  let info: string = "HTTP/1.1 100 Continue\r\n\r\n";
  let final_head: string = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n";
  let wire: string = info.Concat(final_head);
  var exact: HttpResponseParser = http_test_response_parser("GET", HttpResponseLimits{max_total_head_bytes: wire.length});
  http_test_assert(http_test_response_feed(exact, wire.Concat("aNEXT")) == wire.length as intptr && exact.IsComplete(), "aggregate head cap excludes final body and next-message bytes");
  var short: HttpResponseParser = http_test_response_parser("GET", HttpResponseLimits{max_total_head_bytes: wire.length-1});
  http_test_assert(short.Push(NetBytes.FromString(info)).IsOk(), "initial head fits aggregate cap");
  let excess: Result<HttpResponseProgress, HttpError> = short.Push(NetBytes.FromString(final_head));
  http_test_assert(excess.IsErr() && ((excess.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.LimitExceeded && ((excess.get_if<HttpError>()) as HttpError).offset == (wire.length-1) as int64, "aggregate limit is enforced in the middle of a final head");
  var fields: HttpResponseParser = http_test_response_parser("GET", HttpResponseLimits{head: HttpHeadLimits{max_fields: 1}});
  http_test_assert(fields.Push(NetBytes.FromString(info)).IsOk(), "per-head field counts reset after informational events");
  let fed: Result<HttpResponseProgress, HttpError> = fields.Push(NetBytes.FromString("HTTP/1.1 200 OK\r\nX: a\r\nY: b\r\n\r\n"));
  http_test_assert(fed.IsErr() && ((fed.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.LimitExceeded, "per-head field caps remain active for the final response");
}
@test(tag = "http_core")
func test_http_response_eof_every_prefix() {
  let wire: string = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Hints\r\n\r\nHTTP/1.1 204 Empty\r\n\r\n";
  var i: int32 = 0;
  while i < wire.length {
    var parser: HttpResponseParser = http_test_response_parser("GET", HttpResponseLimits{});
    http_test_assert(http_test_response_feed(parser, wire.Substring(0, i)) == i as intptr, "valid incomplete prefix is consumed");
    let end: Result<HttpHead, HttpError> = parser.EndInput();
    http_test_assert(end.IsErr() && ((end.get_if<HttpError>()) as HttpError).kind == HttpErrorKind.UnexpectedEof && ((end.get_if<HttpError>()) as HttpError).offset == i as int64 && !parser.IsComplete(), "EOF after informational or partial final heads cannot complete the response");
    http_test_assert(parser.Push(NetBytes.FromString(wire)).IsErr(), "truncated sequence cannot restart on a new response"); i = i+1;
  }
}
@test(tag = "http_core")
func test_http_response_head_connect_and_101_context() {
  let info: string = "HTTP/1.1 100 Continue\r\n\r\n";
  var head_parser: HttpResponseParser = http_test_response_parser("HEAD", HttpResponseLimits{});
  let head_wire: string = info.Concat("HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n");
  http_test_assert(http_test_response_feed(head_parser, head_wire.Concat("NEXT")) == head_wire.length as intptr, "HEAD preserves next-message suffix after informational heads");
  let head: HttpHead = (head_parser.Head().get_if<HttpHead>()) as HttpHead;
  http_test_assert(((head.BodyPlan().get_if<HttpBodyPlan>()) as HttpBodyPlan).kind == HttpBodyKind.None, "originating HEAD context survives all response parser resets");
  var tunnel: HttpResponseParser = http_test_response_parser("CONNECT", HttpResponseLimits{});
  let tunnel_wire: string = info.Concat("HTTP/1.1 200 OK\r\n\r\n");
  http_test_assert(http_test_response_feed(tunnel, tunnel_wire.Concat("OPAQUE")) == tunnel_wire.length as intptr, "CONNECT preserves tunnel payload exactly");
  let tunnel_head: HttpHead = (tunnel.Head().get_if<HttpHead>()) as HttpHead;
  http_test_assert(((tunnel_head.BodyPlan().get_if<HttpBodyPlan>()) as HttpBodyPlan).kind == HttpBodyKind.Tunnel, "successful CONNECT remains an explicit tunnel handoff");
  var upgrade: HttpResponseParser = http_test_response_parser("GET", HttpResponseLimits{});
  let switched: string = info.Concat("HTTP/1.1 101 Switching\r\n\r\n");
  http_test_assert(http_test_response_feed(upgrade, switched.Concat("PROTOCOL")) == switched.length as intptr && upgrade.IsComplete() && upgrade.InformationalCount() == 1, "101 ends response sequencing without consuming upgraded bytes or counting as an interim response");
}
@test(tag = "http_core")
func test_http_response_owned_events_and_partial_next_head() {
  var parser: HttpResponseParser = http_test_response_parser("GET", HttpResponseLimits{});
  http_test_assert(parser.Head().IsErr(), "pending event query does not poison response parsing");
  http_test_assert(parser.Push(NetBytes.FromString("HTTP/1.1 103 Hints\r\nX-Owned: kept\r\n\r\n")).IsOk(), "informational head is published");
  let info: HttpHead = (parser.Head().get_if<HttpHead>()) as HttpHead;
  http_test_assert(parser.Push(NetBytes{}).IsOk() && parser.Head().IsOk(), "empty input preserves the last informational event");
  http_test_assert(parser.Push(NetBytes.FromString("HTTP/1.1 2")).IsOk() && parser.Head().IsErr(), "starting a new head clears stale event publication");
  var moved: HttpResponseParser = move(parser);
  let fed: Result<HttpResponseProgress, HttpError> = moved.Push(NetBytes.FromString("00 OK\r\nContent-Length: 0\r\n\r\nNEXT"));
  http_test_assert(fed.IsOk() && moved.IsComplete(), "move retains in-progress final association");
  let final: HttpHead = (moved.Head().get_if<HttpHead>()) as HttpHead;
  moved = HttpResponseParser{};
  http_test_assert(((info.FieldAt(0).get_if<HttpField>()) as HttpField).value.Equal("kept") && final.Status() == 200, "retained event heads own metadata after cursor reset/move/drop");
  http_test_assert(moved.Push(NetBytes{}).IsErr() && moved.Head().IsErr() && moved.EndInput().IsErr(), "default sequence parser is closed");
}
@test(tag = "http_core")
func test_http_response_malformed_and_sticky_aggregate_offset() {
  let info: string = "HTTP/1.1 100 Continue\r\n\r\n";
  var parser: HttpResponseParser = http_test_response_parser("GET", HttpResponseLimits{});
  http_test_assert(parser.Push(NetBytes.FromString(info)).IsOk(), "informational prefix is valid");
  let bad: string = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n";
  let fed: Result<HttpResponseProgress, HttpError> = parser.Push(NetBytes.FromString(bad));
  http_test_assert(fed.IsErr(), "final framing conflict is rejected");
  let error: HttpError = (fed.get_if<HttpError>()) as HttpError;
  http_test_assert(error.kind == HttpErrorKind.InvalidFraming && error.offset == (info.length+bad.length) as int64, "inner head error offsets include preceding informational heads exactly once");
  let again: Result<HttpResponseProgress, HttpError> = parser.Push(NetBytes.FromString("HTTP/1.1 204 OK\r\n\r\n"));
  http_test_assert(again.IsErr() && ((again.get_if<HttpError>()) as HttpError).offset == error.offset && parser.Head().IsErr() && parser.EndInput().IsErr(), "terminal aggregate error stays stable on retries and EOF");
  var invalid: Result<HttpResponseParser, HttpError> = HttpResponseParser.New("GET\r\nBad", HttpResponseLimits{});
  http_test_assert(invalid.IsErr(), "request context cannot contain injection bytes");
}

@test(tag = "http_core")
func test_http_response_borrowed_method_context_and_limits() {
  var chars: <int8>[4] = <int8>[4]{}; chars[0] = 72 as int8; chars[1] = 69 as int8; chars[2] = 65 as int8; chars[3] = 68 as int8;
  let verb: string = string.ViewFrom(&chars[0], 4);
  var parser: HttpResponseParser = http_test_response_parser(verb, HttpResponseLimits{});
  chars[0] = 71 as int8; chars[1] = 69 as int8; chars[2] = 84 as int8; chars[3] = 32 as int8;
  http_test_response_feed(parser, "HTTP/1.1 103 Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nNEXT");
  let head: HttpHead = (parser.Head().get_if<HttpHead>()) as HttpHead;
  http_test_assert(parser.IsComplete() && ((head.BodyPlan().get_if<HttpBodyPlan>()) as HttpBodyPlan).kind == HttpBodyKind.None, "originating HEAD context owns its bytes through informational resets");
  var aggregate: Result<HttpResponseParser, HttpError> = HttpResponseParser.New("GET", HttpResponseLimits{max_total_head_bytes: 16777217});
  var per_head: Result<HttpResponseParser, HttpError> = HttpResponseParser.New("GET", HttpResponseLimits{head: HttpHeadLimits{max_line_bytes: -1}});
  http_test_assert(aggregate.IsErr() && per_head.IsErr(), "response constructors validate both aggregate and nested head caps");
}
