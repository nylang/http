// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

import "stdlib:stdlib.ny";
import "ntest:ntest.ny";
import "net_core:net_core.ny";
import "http.ny";
import "private/websocket_crypto.ny";

struct WebSocketTestState {
  output: ByteBuffer;
  aborted: bool;
}

struct WebSocketTestTransport implements WebSocketTransport {
  state: arc<WebSocketTestState>;
}

@override
method(WebSocketTestTransport) Read(
  buffer: ref NetMutableBytes, options: ref NetOperationOptions
) -> Result<intptr, WebSocketError> {
  return 0ip;
}

@override
method(WebSocketTestTransport) WriteAll(
  buffer: ref NetBytes, options: ref NetOperationOptions
) -> Result<Unit, WebSocketError> {
  var state = self.state;
  if state.output.Write(buffer.Data(), buffer.Len()).IsErr() {
    return WebSocketError{kind: WebSocketErrorKind.ResourceExhausted};
  }

  return UnitValue();
}

@override
method(WebSocketTestTransport) Abort() -> void {
  var state = self.state;
  state.aborted = true;
}

// nyra-lint-allow: prefer-type-owned-functions -- Build a fixed HTTP request for these wire tests.
func websocket_request() -> HttpHead {
  var made = HttpHeadParser.NewRequest(HttpHeadLimits{});
  var parser = move(made.get_if<HttpHeadParser>() as HttpHeadParser);
  let request = "GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive, Upgrade\r\n"
    .Concat("Upgrade: WebSocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
  AssertTrue(parser.Push(NetBytes.FromString(request)).IsOk());

  return parser.Head().get_if<HttpHead>() as HttpHead;
}

// nyra-lint-allow: prefer-type-owned-functions -- Copy test byte views without a session owner.
func websocket_text(bytes: ref NetBytes) -> string {
  unsafe {
    return copy(string.ViewFrom(bytes.Data() as *const int8, bytes.Len() as int32));
  }
}

@test(tag = "http_core")
func test_http_websocket_rfc_challenge_and_url() {
  let key = WebSocketKey{text: "dGhlIHNhbXBsZSBub25jZQ=="};
  AssertTrue(key.IsValid());
  AssertEqString(key.Accept(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
  AssertTrue(!WebSocketKey{text: "dGhlIHNhbXBsZSBub25jZR=="}.IsValid());

  let parsed = WebSocket.ParseUrl("WSS://example.com:444/chat?x=%2F");
  AssertTrue(parsed.IsOk());
  let route = parsed.get_if<HttpUrl>() as HttpUrl;
  AssertTrue(route.IsSecure());
  AssertEqString(route.HostField(), "example.com:444");
  AssertEqString(route.Target(), "/chat?x=%2F");
  AssertTrue(WebSocket.ParseUrl("ws://example.com/#fragment").IsErr());
}

@test(tag = "http_core")
func test_http_websocket_server_fragmentation_control_and_prefix() {
  var state = new arc<WebSocketTestState>{output: ByteBuffer.New()};
  let adapter = WebSocketTestTransport{state: state};
  // Two text fragments enclose Ping. All three masked frames are in the read-ahead.
  let wire: <uint8>[21] = {
    0x01u8, 0x81u8, 1u8, 2u8, 3u8, 4u8, 73u8,
    0x89u8, 0x81u8, 1u8, 2u8, 3u8, 4u8, 121u8,
    0x80u8, 0x81u8, 1u8, 2u8, 3u8, 4u8, 104u8
  };
  let prefix = websocket_buffer(wire);
  let options = NetOperationOptions{};
  var opened = WebSocket.Accept(adapter, websocket_request(), prefix, WebSocketLimits{}, options);
  if AssertTrueMsg(opened.IsOk(), "opening handshake failed\n") != 0 {
    return;
  }
  var ws = move(opened.get_if<WebSocket>() as WebSocket);
  let event = ws.Receive(options);
  if AssertTrueMsg(event.IsOk(), "fragmented receive failed\n") != 0 {
    return;
  }
  let message = event.get_if<WebSocketMessage>() as WebSocketMessage;
  AssertTrueMsg(message.kind == WebSocketMessageKind.Text, "expected text\n");
  AssertEqStringMsg(websocket_text(message.payload.Bytes()), "Hi", "wrong fragment bytes\n");

  let wire_out = NetBytes.FromRaw(state.output.Data(), state.output.Len() as intptr).get_if<NetBytes>() as NetBytes;
  let output = websocket_text(wire_out);
  AssertTrue(output.Contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
  let pong = output.View(output.length - 3, 3);
  AssertEqI32(pong.ByteAt(0), 138);
  AssertEqI32(pong.ByteAt(1), 1);
  AssertEqI32(pong.ByteAt(2), 120);
  ws.Abort();
  AssertTrue(state.aborted);
}

@test(tag = "http_core")
func test_http_websocket_rejects_unmasked_and_oversized_frames() {
  let request = websocket_request();
  let options = NetOperationOptions{};
  let unmasked: <uint8>[3] = {0x81u8, 1u8, 120u8};
  let oversized: <uint8>[8] = {0x82u8, 0x82u8, 0u8, 0u8, 0u8, 0u8, 120u8, 120u8};
  let invalid_utf8: <uint8>[7] = {0x81u8, 0x81u8, 0u8, 0u8, 0u8, 0u8, 255u8};
  let nonminimal: <uint8>[4] = {0x82u8, 0xfeu8, 0u8, 1u8};
  let missing_continuation: <uint8>[6] = {0x80u8, 0x80u8, 0u8, 0u8, 0u8, 0u8};
  check_rejected_frame(request, unmasked, WebSocketErrorKind.Protocol, options);
  check_rejected_frame(request, oversized, WebSocketErrorKind.LimitExceeded, options);
  check_rejected_frame(request, invalid_utf8, WebSocketErrorKind.InvalidUtf8, options);
  check_rejected_frame(request, nonminimal, WebSocketErrorKind.Protocol, options);
  check_rejected_frame(request, missing_continuation, WebSocketErrorKind.Protocol, options);
}

// nyra-lint-allow: prefer-type-owned-functions -- Copy fixture octets without a live session.
func websocket_buffer(bytes: ref <uint8>[]) -> NetBuffer {
  let input = NetBytes.FromRaw(&bytes[0], bytes.length as intptr).get_if<NetBytes>() as NetBytes;
  return NetBuffer.CopyFrom(input).get_if<NetBuffer>() as NetBuffer;
}

// nyra-lint-allow: prefer-type-owned-functions -- Share malformed-frame assertions in this test TU.
func check_rejected_frame(
  request: ref HttpHead, wire: ref <uint8>[], expected: WebSocketErrorKind,
  options: ref NetOperationOptions
) -> void {
  var state = new arc<WebSocketTestState>{output: ByteBuffer.New()};
  let adapter = WebSocketTestTransport{state: state};
  var opened = WebSocket.Accept(adapter, request, websocket_buffer(wire), WebSocketLimits{max_message_bytes: 1}, options);
  if AssertTrueMsg(opened.IsOk(), "opening handshake failed\n") != 0 {
    return;
  }

  var ws = move(opened.get_if<WebSocket>() as WebSocket);
  let event = ws.Receive(options);
  if AssertTrueMsg(event.IsErr(), "invalid frame was accepted\n") != 0 {
    return;
  }

  let failure = event.get_if<WebSocketError>() as WebSocketError;
  AssertTrueMsg(failure.kind == expected, "wrong frame error kind\n");
  AssertTrue(state.aborted);
}
