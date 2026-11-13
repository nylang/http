// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of WebSocketSession;

pub static method(WebSocket) ParseUrl(url: ref string) -> Result<HttpUrl, WebSocketError> {
  if url.Contains("#") {
    return WebSocketError{kind: WebSocketErrorKind.InvalidArgument};
  }

  var mapped: string = "";
  if url.View(0, 5).EqualAsciiIgnoreCase("ws://") {
    mapped = "http".Concat(url.View(2, url.length - 2));
  } else if url.View(0, 6).EqualAsciiIgnoreCase("wss://") {
    mapped = "https".Concat(url.View(3, url.length - 3));
  } else {
    return WebSocketError{kind: WebSocketErrorKind.InvalidArgument};
  }

  let result = HttpUrl.Parse(mapped);
  if result.IsErr() {
    return WebSocketError{kind: WebSocketErrorKind.InvalidArgument, http_error: result.get_if<HttpError>()};
  }

  return result.get_if<HttpUrl>() as HttpUrl;
}

pub static method(WebSocket) Connect(
  transport: WebSocketTransport, url: ref HttpUrl, limits: ref WebSocketLimits,
  options: ref NetOperationOptions
) -> Result<WebSocket, WebSocketError> {
  var made = WebSocket.Adopt(transport, limits, true);
  if made.IsErr() {
    return made.get_if<WebSocketError>() as WebSocketError;
  }

  var socket = move(made.get_if<WebSocket>() as WebSocket);
  var state = socket.cell as arc<WebSocketState>;
  let upgraded = state.ClientHandshake(url, options);
  if upgraded.IsErr() {
    socket.Abort();
    return upgraded.get_if<WebSocketError>() as WebSocketError;
  }

  return move(socket);
}

method(WebSocketState) ClientHandshake(
  url: ref HttpUrl, options: ref NetOperationOptions
) -> Result<Unit, WebSocketError> {
  var entropy = WebSocketEntropy{};
  if !entropy.Fill(16) {
    return WebSocketError{kind: WebSocketErrorKind.EntropyUnavailable};
  }

  let key = WebSocketKey{text: Base64.Encode(entropy.Bytes(16))};
  var fields: <HttpField>[5] = <HttpField>[5]{};
  fields[0] = HttpField{name: "Host", value: url.HostField()};
  fields[1] = HttpField{name: "Connection", value: "Upgrade"};
  fields[2] = HttpField{name: "Upgrade", value: "websocket"};
  fields[3] = HttpField{name: "Sec-WebSocket-Version", value: "13"};
  fields[4] = HttpField{name: "Sec-WebSocket-Key", value: key.text};
  let request = HttpHead.EncodeRequest("GET", url.Target(), fields);
  if request.IsErr() {
    return WebSocketError{kind: WebSocketErrorKind.Handshake, http_error: request.get_if<HttpError>()};
  }

  let request_bytes = request.get_if<NetBuffer>() as NetBuffer;
  let written = self.transport.WriteAll(request_bytes.Bytes(), options);
  if written.IsErr() {
    return written;
  }

  let response = self.ReadResponse(options);
  if response.IsErr() {
    return response.get_if<WebSocketError>() as WebSocketError;
  }

  let head = response.get_if<HttpHead>() as HttpHead;
  let upgrade = WebSocketUpgrade.From(head);
  if head.MinorVersion() != 1 || head.Status() != 101 || !upgrade.IsUpgrade() ||
      upgrade.accept_count != 1 || upgrade.accept != key.Accept() ||
      upgrade.protocol || upgrade.extensions {
    return WebSocketError{kind: WebSocketErrorKind.Handshake};
  }

  return UnitValue();
}

method(WebSocketState) ReadResponse(options: ref NetOperationOptions) -> Result<HttpHead, WebSocketError> {
  var created = HttpResponseParser.New("GET", HttpResponseLimits{});
  if created.IsErr() {
    return WebSocketError{kind: WebSocketErrorKind.Handshake, http_error: created.get_if<HttpError>()};
  }

  var parser = move(created.get_if<HttpResponseParser>() as HttpResponseParser);
  var storage: <uint8>[4096] = <uint8>[4096]{};
  let buffer = NetMutableBytes.FromRaw(&mut storage[0], 4096ip).get_if<NetMutableBytes>() as NetMutableBytes;
  while true {
    let received = self.transport.Read(buffer, options);
    if received.IsErr() {
      return received.get_if<WebSocketError>() as WebSocketError;
    }

    let size = received.get_if<intptr>() as intptr;
    if size <= 0ip || size > buffer.Len() {
      return WebSocketError{kind: WebSocketErrorKind.UnexpectedEof};
    }

    var offset: intptr = 0;
    while offset < size {
      let bytes = buffer.AsReadOnly().Slice(offset, size - offset).get_if<NetBytes>() as NetBytes;
      let result = parser.Push(bytes);
      if result.IsErr() {
        return WebSocketError{kind: WebSocketErrorKind.Handshake, http_error: result.get_if<HttpError>()};
      }

      let progress = result.get_if<HttpResponseProgress>() as HttpResponseProgress;
      offset += progress.consumed;
      if progress.state == HttpResponseState.Final {
        let suffix = buffer.AsReadOnly().Slice(offset, size - offset).get_if<NetBytes>() as NetBytes;
        let copied = NetBuffer.CopyFrom(suffix);
        if copied.IsErr() {
          return WebSocketError{kind: WebSocketErrorKind.ResourceExhausted, network_error: copied.get_if<NetError>()};
        }
        self.prefix = copied.get_if<NetBuffer>() as NetBuffer;
        let head = parser.Head();
        if head.IsErr() {
          return WebSocketError{kind: WebSocketErrorKind.Handshake, http_error: head.get_if<HttpError>()};
        }
        return head.get_if<HttpHead>() as HttpHead;
      }
    }
  }

  return WebSocketError{kind: WebSocketErrorKind.Handshake};
}

pub static method(WebSocket) Accept(
  transport: WebSocketTransport, request: ref HttpHead, prefix: ref NetBuffer,
  limits: ref WebSocketLimits, options: ref NetOperationOptions
) -> Result<WebSocket, WebSocketError> {
  var made = WebSocket.Adopt(transport, limits, false);
  if made.IsErr() {
    return made.get_if<WebSocketError>() as WebSocketError;
  }

  var socket = move(made.get_if<WebSocket>() as WebSocket);
  var state = socket.cell as arc<WebSocketState>;
  let upgraded = state.ServerHandshake(request, options);
  if upgraded.IsErr() {
    socket.Abort();
    return upgraded.get_if<WebSocketError>() as WebSocketError;
  }

  state.prefix = prefix;
  return move(socket);
}

method(WebSocketState) ServerHandshake(
  request: ref HttpHead, options: ref NetOperationOptions
) -> Result<Unit, WebSocketError> {
  let upgrade = WebSocketUpgrade.From(request);
  let key = WebSocketKey{text: upgrade.key};
  let plan = request.BodyPlan().get_if<HttpBodyPlan>();
  if request.IsResponse() || request.MinorVersion() != 1 || request.Method() != "GET" ||
      plan == nil || (plan as HttpBodyPlan).kind != HttpBodyKind.None || !upgrade.IsUpgrade() ||
      upgrade.version_count != 1 || upgrade.version != "13" || upgrade.key_count != 1 ||
      upgrade.accept_count != 0 || !key.IsValid() {
    return WebSocketError{kind: WebSocketErrorKind.Handshake};
  }

  var fields: <HttpField>[3] = <HttpField>[3]{};
  fields[0] = HttpField{name: "Connection", value: "Upgrade"};
  fields[1] = HttpField{name: "Upgrade", value: "websocket"};
  fields[2] = HttpField{name: "Sec-WebSocket-Accept", value: key.Accept()};
  let response = HttpHead.EncodeResponse(101, "Switching Protocols", fields, "GET");
  if response.IsErr() {
    return WebSocketError{kind: WebSocketErrorKind.Handshake, http_error: response.get_if<HttpError>()};
  }

  let response_bytes = response.get_if<NetBuffer>() as NetBuffer;
  return self.transport.WriteAll(response_bytes.Bytes(), options);
}

struct WebSocketUpgrade {
  connection: bool;
  closing: bool;
  websocket: bool;
  key_count: int32;
  key: string;
  accept_count: int32;
  accept: string;
  version_count: int32;
  version: string;
  protocol: bool;
  extensions: bool;
}

method(WebSocketUpgrade) IsUpgrade() -> bool {
  return self.connection && !self.closing && self.websocket;
}

static method(WebSocketUpgrade) From(head: ref HttpHead) -> WebSocketUpgrade {
  var result = WebSocketUpgrade{};
  var i: int32 = 0;
  while i < head.FieldCount() {
    let field = head.FieldAt(i).get_if<HttpField>() as HttpField;
    if field.name.EqualAsciiIgnoreCase("Connection") {
      result.connection = result.connection || contains_token(field.value, "upgrade");
      result.closing = result.closing || contains_token(field.value, "close");
    } else if field.name.EqualAsciiIgnoreCase("Upgrade") {
      result.websocket = result.websocket || contains_token(field.value, "websocket");
    } else if field.name.EqualAsciiIgnoreCase("Sec-WebSocket-Key") {
      result.key_count += 1;
      result.key = field.value;
    } else if field.name.EqualAsciiIgnoreCase("Sec-WebSocket-Accept") {
      result.accept_count += 1;
      result.accept = field.value;
    } else if field.name.EqualAsciiIgnoreCase("Sec-WebSocket-Version") {
      result.version_count += 1;
      result.version = field.value;
    } else if field.name.EqualAsciiIgnoreCase("Sec-WebSocket-Protocol") {
      result.protocol = true;
    } else if field.name.EqualAsciiIgnoreCase("Sec-WebSocket-Extensions") {
      result.extensions = true;
    }
    i += 1;
  }

  return result;
}

func contains_token(value: ref string, token: ref string) -> bool {
  var start: int32 = 0;
  var end: int32 = 0;
  while end <= value.length {
    if end == value.length || value.ByteAt(end) == 44 {
      if value.View(start, end - start).Trim().EqualAsciiIgnoreCase(token) {
        return true;
      }
      start = end + 1;
    }
    end += 1;
  }

  return false;
}
