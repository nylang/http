// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/url.ni";

/** @brief Opening, wire, transport and local WebSocket failures. */
pub enum WebSocketErrorKind {
  InvalidArgument,
  Closed,
  Handshake,
  Protocol,
  InvalidUtf8,
  LimitExceeded,
  UnexpectedEof,
  EntropyUnavailable,
  Transport,
  Tls,
  ResourceExhausted
}

/** @brief First operation failure, with the underlying network or HTTP error when available. */
pub struct WebSocketError {
  kind: WebSocketErrorKind;
  network_error: NetError?;
  http_error: HttpError?;
}

/** @brief Session limits. Zero selects 16 MiB per frame and per reassembled message.
 * @note The message limit may be raised to 1 GiB, the maximum supported by the receive buffer. */
pub struct WebSocketLimits {
  max_frame_bytes: int32;
  max_message_bytes: int32;
}

/** @brief Whether both limits are usable by the session. */
pub method(WebSocketLimits) IsValid() -> bool;

/** @brief Events returned by Receive. Incoming Ping frames are answered automatically. */
pub enum WebSocketMessageKind {
  Text,
  Binary,
  Pong,
  Close
}

/** @brief Owned payload; for Close, the payload contains the UTF-8 reason only. */
pub struct WebSocketMessage {
  kind: WebSocketMessageKind;
  payload: NetBuffer;
  close_code: int32?;
}

/** @brief An ordered duplex byte transport adopted by the WebSocket session.
 * @note Read returns a partial count or zero at EOF. WriteAll must write the complete span.
 * Implementations honor the supplied controls. Abort is immediate and idempotent. */
pub interface WebSocketTransport {
  Read(buffer: ref NetMutableBytes, options: ref NetOperationOptions) -> Result<intptr, WebSocketError>;
  WriteAll(buffer: ref NetBytes, options: ref NetOperationOptions) -> Result<Unit, WebSocketError>;
  Abort() -> void;
}

/** @brief Move-only RFC 6455 session. Drive its operations serially on one caller thread. */
pub struct WebSocket;

/** @brief A live session has one owner. */
pub method(WebSocket) operator copy() -> WebSocket = delete;

/** @brief Move the session, leaving the source closed. */
pub method(WebSocket) operator move() -> WebSocket;

/** @brief Abort any remaining transport during destruction. */
pub method(WebSocket) operator drop() -> void;

/** @brief Parse an absolute ws/wss URL using the HTTP authority and origin-target rules.
 * @returns The corresponding HTTP(S) URL for dialing, with fragments rejected. */
pub static method(WebSocket) ParseUrl(url: ref string) -> Result<HttpUrl, WebSocketError>;

/** @brief Resolve, connect and upgrade a ws:// URL using the supplied DNS and controls.
 * @returns An open WebSocket or the opening failure. */
pub static method(WebSocket) Open(
  url: ref string, resolver: ref mut AsyncResolver, dial: ref HttpDialOptions,
  limits: ref WebSocketLimits, options: ref NetOperationOptions
) -> Result<WebSocket, WebSocketError>;

/** @brief Run the client upgrade over an exclusively supplied, already connected byte transport.
 * @note Use ParseUrl to obtain the HTTP(S) routing URL. This operation takes over the transport
 * even when the handshake fails. No extensions or subprotocols are offered. */
pub static method(WebSocket) Connect(
  transport: WebSocketTransport, url: ref HttpUrl, limits: ref WebSocketLimits,
  options: ref NetOperationOptions
) -> Result<WebSocket, WebSocketError>;

/** @brief Adopt TCP and upgrade an already parsed, application-approved request.
 * @note The caller admits the route, authentication and Origin before calling. Pass any bytes
 * read after the HTTP head as prefix. The socket is consumed even when the upgrade fails. */
pub static method(WebSocket) AcceptTcp(
  connection: ref mut TcpConnection, request: ref HttpHead, prefix: ref NetBuffer,
  limits: ref WebSocketLimits, options: ref NetOperationOptions
) -> Result<WebSocket, WebSocketError>;

/** @brief Upgrade an application-approved request on a caller-provided byte transport.
 * @note The same admission and ownership contract as AcceptTcp applies. */
pub static method(WebSocket) Accept(
  transport: WebSocketTransport, request: ref HttpHead, prefix: ref NetBuffer,
  limits: ref WebSocketLimits, options: ref NetOperationOptions
) -> Result<WebSocket, WebSocketError>;

/** @brief Write one UTF-8 text message using the supplied operation deadline and cancellation. */
pub method(WebSocket) SendText(text: ref string, options: ref NetOperationOptions) -> Result<Unit, WebSocketError>;

/** @brief Write one complete binary message. The input is borrowed only for this call. */
pub method(WebSocket) SendBinary(bytes: ref NetBytes, options: ref NetOperationOptions) -> Result<Unit, WebSocketError>;

/** @brief Send a Ping control frame with up to 125 bytes. */
pub method(WebSocket) Ping(bytes: ref NetBytes, options: ref NetOperationOptions) -> Result<Unit, WebSocketError>;

/** @brief Receive a reassembled message, Pong or the peer's Close. Replies to Ping and Close.
 * @note EOF without a Close frame is an error. An I/O or peer-protocol failure retires the
 * connection. A received Close event ends the session. */
pub method(WebSocket) Receive(options: ref NetOperationOptions) -> Result<WebSocketMessage, WebSocketError>;

/** @brief Send Close with a valid code and up to 123 UTF-8 reason bytes.
 * @note Drive Receive to complete the close handshake under a finite deadline, or call Abort. */
pub method(WebSocket) StartClose(
  code: int32, reason: ref string, options: ref NetOperationOptions
) -> Result<Unit, WebSocketError>;

/** @brief Immediately retire the transport without a close handshake. */
pub method(WebSocket) Abort() -> void;
