// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Owns one upgraded connection, its read-ahead and RFC 6455 session state. */
module WebSocketSession;
part "websocket_handshake.ny";
part "websocket_frame.ny";
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/url.ni";
import "interface/websocket.ni";
import "private/websocket_crypto.ny";

constexpr kWebSocketDefaultLimit: int32 = 16777216;
constexpr kWebSocketMaxMessage: int32 = 1073741824;

/** @brief Move-only WebSocket session. */
pub struct WebSocket {
  cell: arc<WebSocketState>?;
}

struct WebSocketState {
  transport: WebSocketTransport;
  client: bool;
  prefix: NetBuffer;
  prefix_offset: intptr;
  frame_limit: int32;
  message_limit: int32;
  close_sent: bool;
  message_opcode: uint8;
  message: ByteBuffer;
}

pub method(WebSocket) operator move() -> WebSocket {
  let cell = self.cell;
  self.cell = nil;

  return WebSocket{cell: cell};
}

pub method(WebSocket) operator drop() -> void {
  self.Abort();
}

pub method(WebSocket) Abort() -> void {
  let cell = self.cell;
  self.cell = nil;
  if cell != nil {
    var state = cell as arc<WebSocketState>;
    state.transport.Abort();
  }
}

static method(WebSocket) Adopt(
  transport: WebSocketTransport, limits: ref WebSocketLimits, client: bool
) -> Result<WebSocket, WebSocketError> {
  if !limits.IsValid() {
    transport.Abort();
    return WebSocketError{kind: WebSocketErrorKind.InvalidArgument};
  }

  let frame_limit = limits.max_frame_bytes == 0 ? kWebSocketDefaultLimit : limits.max_frame_bytes;
  let message_limit = limits.max_message_bytes == 0 ? kWebSocketDefaultLimit : limits.max_message_bytes;

  return WebSocket{cell: new arc<WebSocketState>{
    transport: transport, client: client, frame_limit: frame_limit, message_limit: message_limit,
    message: ByteBuffer.New()
  }};
}

pub method(WebSocketLimits) IsValid() -> bool {
  return self.max_frame_bytes >= 0 && self.max_message_bytes >= 0
    && self.max_message_bytes <= kWebSocketMaxMessage;
}

method(WebSocketState) ReadExact(
  output: ref NetMutableBytes, options: ref NetOperationOptions
) -> Result<Unit, WebSocketError> {
  var offset: intptr = 0;
  while offset < output.Len() {
    let rest = output.Slice(offset, output.Len() - offset).get_if<NetMutableBytes>() as NetMutableBytes;
    var count: intptr = 0;
    if self.prefix_offset < self.prefix.Len() {
      let control = options.Check(Instant.Now().ToDurationSinceEpochish().ToNanoseconds());
      if control.IsErr() {
        return WebSocketError{kind: WebSocketErrorKind.Transport, network_error: control.get_if<NetError>()};
      }

      let available = self.prefix.Len() - self.prefix_offset;
      count = available < rest.Len() ? available : rest.Len();
      let bytes = self.prefix.Bytes().Slice(self.prefix_offset, count).get_if<NetBytes>() as NetBytes;
      unsafe {
        memcpy(rest.Data(), bytes.Data(), count as uintptr);
      }
      self.prefix_offset += count;
      if self.prefix_offset == self.prefix.Len() {
        self.prefix = NetBuffer{};
        self.prefix_offset = 0ip;
      }
    } else {
      let got = self.transport.Read(rest, options);
      if got.IsErr() {
        return got.get_if<WebSocketError>() as WebSocketError;
      }
      count = got.get_if<intptr>() as intptr;
      if count <= 0ip || count > rest.Len() {
        return WebSocketError{kind: WebSocketErrorKind.UnexpectedEof};
      }
    }
    offset += count;
  }

  return UnitValue();
}

pub method(WebSocket) SendText(text: ref string, options: ref NetOperationOptions) -> Result<Unit, WebSocketError> {
  if !text.IsValidUtf8() {
    return WebSocketError{kind: WebSocketErrorKind.InvalidUtf8};
  }

  return self.Send(1u8, NetBytes.FromString(text), options);
}

pub method(WebSocket) SendBinary(bytes: ref NetBytes, options: ref NetOperationOptions) -> Result<Unit, WebSocketError> {
  return self.Send(2u8, bytes, options);
}

pub method(WebSocket) Ping(bytes: ref NetBytes, options: ref NetOperationOptions) -> Result<Unit, WebSocketError> {
  if bytes.Len() > 125ip {
    return WebSocketError{kind: WebSocketErrorKind.InvalidArgument};
  }

  return self.Send(9u8, bytes, options);
}

method(WebSocket) Send(
  opcode: uint8, bytes: ref NetBytes, options: ref NetOperationOptions
) -> Result<Unit, WebSocketError> {
  let cell = self.cell;
  if cell == nil {
    return WebSocketError{kind: WebSocketErrorKind.Closed};
  }

  var state = cell as arc<WebSocketState>;
  if state.close_sent {
    return WebSocketError{kind: WebSocketErrorKind.Closed};
  }

  if opcode < 8u8 && (bytes.Len() > state.message_limit as intptr || bytes.Len() > state.frame_limit as intptr) {
    return WebSocketError{kind: WebSocketErrorKind.LimitExceeded};
  }

  let written = state.WriteFrame(opcode, bytes, options);
  if written.IsErr() {
    self.Abort();
  } else if opcode == 8u8 {
    state.close_sent = true;
  }

  return written;
}

pub method(WebSocket) StartClose(
  code: int32, reason: ref string, options: ref NetOperationOptions
) -> Result<Unit, WebSocketError> {
  if !valid_close_code(code) || reason.length > 123 || !reason.IsValidUtf8() {
    return WebSocketError{kind: WebSocketErrorKind.InvalidArgument};
  }

  var bytes: <uint8>[125] = <uint8>[125]{};
  bytes[0] = (code >> 8) as uint8;
  bytes[1] = (code & 255) as uint8;
  var i: int32 = 0;
  while i < reason.length {
    bytes[i + 2] = reason.ByteAt(i) as uint8;
    i += 1;
  }

  let payload = NetBytes.FromRaw(&bytes[0], (reason.length + 2) as intptr).get_if<NetBytes>() as NetBytes;
  return self.Send(8u8, payload, options);
}

pub method(WebSocket) Receive(options: ref NetOperationOptions) -> Result<WebSocketMessage, WebSocketError> {
  let cell = self.cell;
  if cell == nil {
    return WebSocketError{kind: WebSocketErrorKind.Closed};
  }

  var state = cell as arc<WebSocketState>;
  let result = state.NextMessage(options);
  if result.IsErr() {
    let failure = result.get_if<WebSocketError>() as WebSocketError;
    state.RejectPeer(failure.kind, options);
    self.Abort();
  } else if (result.get_if<WebSocketMessage>() as WebSocketMessage).kind == WebSocketMessageKind.Close {
    self.Abort();
  }

  return result;
}

method(WebSocketState) RejectPeer(kind: WebSocketErrorKind, options: ref NetOperationOptions) -> void {
  if self.close_sent || !options.deadline.IsFinite() {
    return;
  }

  // On a protocol failure, attempt a close only under the caller's finite budget.
  var code: int32 = 0;
  if kind == WebSocketErrorKind.Protocol {
    code = 1002;
  } else if kind == WebSocketErrorKind.InvalidUtf8 {
    code = 1007;
  } else if kind == WebSocketErrorKind.LimitExceeded {
    code = 1009;
  }
  if code == 0 {
    return;
  }

  var bytes: <uint8>[2] = <uint8>[2]{};
  bytes[0] = (code >> 8) as uint8;
  bytes[1] = (code & 255) as uint8;
  let payload = NetBytes.FromRaw(&bytes[0], 2ip).get_if<NetBytes>() as NetBytes;
  self.WriteFrame(8u8, payload, options);
}
