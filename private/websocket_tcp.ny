// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Owns TCP I/O for the plain WebSocket adapter. */
module WebSocketTcpAdapter;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/client.ni";
import "interface/url.ni";
import "interface/websocket.ni";

struct WebSocketTcp implements WebSocketTransport {
  connection: TcpConnection;
}

@override
method(WebSocketTcp) Read(buffer: ref NetMutableBytes, options: ref NetOperationOptions) -> Result<intptr, WebSocketError> {
  let got = self.connection.Read(buffer, options);
  if got.IsErr() {
    return WebSocketError{kind: WebSocketErrorKind.Transport, network_error: got.get_if<NetError>()};
  }

  return got.get_if<intptr>() as intptr;
}

@override
method(WebSocketTcp) WriteAll(buffer: ref NetBytes, options: ref NetOperationOptions) -> Result<Unit, WebSocketError> {
  var offset: intptr = 0;
  while offset < buffer.Len() {
    let rest = buffer.Slice(offset, buffer.Len() - offset).get_if<NetBytes>() as NetBytes;
    let sent = self.connection.Write(rest, options);
    if sent.IsErr() {
      return WebSocketError{kind: WebSocketErrorKind.Transport, network_error: sent.get_if<NetError>()};
    }
    let count = sent.get_if<intptr>() as intptr;
    if count <= 0ip {
      return WebSocketError{kind: WebSocketErrorKind.UnexpectedEof};
    }
    offset += count;
  }

  return UnitValue();
}

@override
method(WebSocketTcp) Abort() -> void {
  self.connection.Close();
}

/** @brief Resolve and connect a cleartext WebSocket URL.
 * @returns An owned session or a URL, network or opening-handshake error.
 */
pub static method(WebSocket) Open(
  url: ref string, resolver: ref mut AsyncResolver, dial: ref HttpDialOptions,
  limits: ref WebSocketLimits, options: ref NetOperationOptions
) -> Result<WebSocket, WebSocketError> {
  let parsed = WebSocket.ParseUrl(url);
  if parsed.IsErr() {
    return parsed.get_if<WebSocketError>() as WebSocketError;
  }

  let route = parsed.get_if<HttpUrl>() as HttpUrl;
  if route.IsSecure() || !limits.IsValid() {
    return WebSocketError{kind: WebSocketErrorKind.InvalidArgument};
  }

  var dialed = route.Dial(resolver, dial, options);
  if dialed.IsErr() {
    let error = dialed.get_if<HttpClientError>() as HttpClientError;
    return WebSocketError{kind: WebSocketErrorKind.Transport, network_error: error.transport_error,
      http_error: error.protocol_error};
  }

  var adapter = WebSocketTcp{connection: move(dialed.get_if<TcpConnection>() as TcpConnection)};
  return WebSocket.Connect(move(adapter), route, limits, options);
}

/** @brief Adopt accepted TCP and upgrade an application-approved request.
 * @returns An owned session or an opening error; the socket is consumed on either path.
 */
pub static method(WebSocket) AcceptTcp(
  connection: ref mut TcpConnection, request: ref HttpHead, prefix: ref NetBuffer,
  limits: ref WebSocketLimits, options: ref NetOperationOptions
) -> Result<WebSocket, WebSocketError> {
  var adapter = WebSocketTcp{connection: move(connection)};
  return WebSocket.Accept(move(adapter), request, prefix, limits, options);
}
