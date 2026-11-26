// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of WebSocketSession;

struct WebSocketFrame {
  opcode: uint8;
  final: bool;
  length: int32;
  mask: <uint8>[4];
}

method(WebSocketState) ReadFrame(options: ref NetOperationOptions) -> Result<WebSocketFrame, WebSocketError> {
  var bytes: <uint8>[8] = <uint8>[8]{};
  var output = NetMutableBytes.FromRaw(&mut bytes[0], 2ip).get_if<NetMutableBytes>() as NetMutableBytes;
  let header = self.ReadExact(output, options);
  if header.IsErr() {
    return header.get_if<WebSocketError>() as WebSocketError;
  }

  let flags: uint8 = bytes[0];
  let masked = (bytes[1] & 128u8) != 0u8;
  let opcode = flags & 15u8;
  let final = (flags & 128u8) != 0u8;
  let small = bytes[1] & 127u8;
  let control = opcode >= 8u8;
  if (flags & 112u8) != 0u8 || masked == self.client ||
      (opcode > 2u8 && (opcode < 8u8 || opcode > 10u8)) ||
      (control && (!final || small > 125u8)) {
    return WebSocketError{kind: WebSocketErrorKind.Protocol};
  }

  var length: uint64 = small as uint64;
  if small >= 126u8 {
    let width: int32 = small == 126u8 ? 2 : 8;
    output = NetMutableBytes.FromRaw(&mut bytes[0], width as intptr).get_if<NetMutableBytes>() as NetMutableBytes;
    let extended = self.ReadExact(output, options);
    if extended.IsErr() {
      return extended.get_if<WebSocketError>() as WebSocketError;
    }

    if width == 8 && bytes[0] >= 128u8 {
      return WebSocketError{kind: WebSocketErrorKind.Protocol};
    }
    length = 0u64;
    var i: int32 = 0;
    while i < width {
      length = (length << 8u64) | (bytes[i] as uint64);
      i += 1;
    }
    if (width == 2 && length < 126u64) || (width == 8 && length < 65536u64) {
      return WebSocketError{kind: WebSocketErrorKind.Protocol};
    }
  }

  if !control {
    if (opcode == 0u8) != (self.message_opcode != 0u8) {
      return WebSocketError{kind: WebSocketErrorKind.Protocol};
    }
    if length > self.frame_limit as uint64 || length > (self.message_limit - self.message.Len()) as uint64 {
      return WebSocketError{kind: WebSocketErrorKind.LimitExceeded};
    }
  }

  var frame = WebSocketFrame{opcode: opcode, final: final, length: length as int32};
  if masked {
    output = NetMutableBytes.FromRaw(&mut frame.mask[0], 4ip).get_if<NetMutableBytes>() as NetMutableBytes;
    let mask = self.ReadExact(output, options);
    if mask.IsErr() {
      return mask.get_if<WebSocketError>() as WebSocketError;
    }
  }

  return frame;
}

method(WebSocketState) ReadPayload(
  frame: ref WebSocketFrame, dest: ref mut ByteBuffer, options: ref NetOperationOptions
) -> Result<Unit, WebSocketError> {
  var block: <uint8>[4096] = <uint8>[4096]{};
  var offset: int32 = 0;
  while offset < frame.length {
    let remaining = frame.length - offset;
    let size: int32 = remaining < 4096 ? remaining : 4096;
    let output = NetMutableBytes.FromRaw(&mut block[0], size as intptr).get_if<NetMutableBytes>() as NetMutableBytes;
    let read = self.ReadExact(output, options);
    if read.IsErr() {
      return read;
    }
    if !self.client {
      var i: int32 = 0;
      while i < size {
        block[i] = block[i] ^ frame.mask[(offset + i) % 4];
        i += 1;
      }
    }

    if dest.Write(&block[0], size as intptr).IsErr() {
      return WebSocketError{kind: WebSocketErrorKind.ResourceExhausted};
    }
    offset += size;
  }

  return UnitValue();
}

method(WebSocketState) NextMessage(options: ref NetOperationOptions) -> Result<WebSocketMessage, WebSocketError> {
  while true {
    let header = self.ReadFrame(options);
    if header.IsErr() {
      return header.get_if<WebSocketError>() as WebSocketError;
    }

    let frame = header.get_if<WebSocketFrame>() as WebSocketFrame;
    if frame.opcode >= 8u8 {
      var control = ByteBuffer.New();
      let read = self.ReadPayload(frame, control, options);
      if read.IsErr() {
        return read.get_if<WebSocketError>() as WebSocketError;
      }

      let payload = NetBytes.FromRaw(control.Data(), control.Len() as intptr).get_if<NetBytes>() as NetBytes;
      if frame.opcode != 9u8 {
        return self.Control(frame.opcode, payload, options);
      }

      let pong = self.WriteFrame(10u8, payload, options);
      if pong.IsErr() {
        return pong.get_if<WebSocketError>() as WebSocketError;
      }
    } else {
      if frame.opcode != 0u8 {
        self.message_opcode = frame.opcode;
      }
      let read = self.ReadPayload(frame, self.message, options);
      if read.IsErr() {
        return read.get_if<WebSocketError>() as WebSocketError;
      }

      if frame.final {
        let opcode = self.message_opcode;
        self.message_opcode = 0u8;
        let data = NetBytes.FromRaw(self.message.Data(), self.message.Len() as intptr).get_if<NetBytes>() as NetBytes;
        let result = self.DataMessage(opcode, data);
        self.message = ByteBuffer.New();
        if !self.close_sent || result.IsErr() {
          return result;
        }
      }
    }
  }

  return WebSocketError{kind: WebSocketErrorKind.Protocol};
}

method(WebSocketState) DataMessage(opcode: uint8, payload: ref NetBytes) -> Result<WebSocketMessage, WebSocketError> {
  if opcode == 1u8 && !valid_text(payload) {
    return WebSocketError{kind: WebSocketErrorKind.InvalidUtf8};
  }

  let kind = opcode == 1u8 ? WebSocketMessageKind.Text : WebSocketMessageKind.Binary;
  return own_message(kind, payload, nil);
}

method(WebSocketState) Control(
  opcode: uint8, payload: ref NetBytes, options: ref NetOperationOptions
) -> Result<WebSocketMessage, WebSocketError> {
  if opcode == 10u8 {
    return own_message(WebSocketMessageKind.Pong, payload, nil);
  }

  var code: int32? = nil;
  var reason: NetBytes = NetBytes{};
  if payload.Len() == 1ip {
    return WebSocketError{kind: WebSocketErrorKind.Protocol};
  }
  if payload.Len() >= 2ip {
    var number: int32 = 0;
    unsafe {
      number = ((payload.Data()[0] as int32) << 8) | (payload.Data()[1] as int32);
    }
    if !valid_close_code(number) {
      return WebSocketError{kind: WebSocketErrorKind.Protocol};
    }
    code = number;
    reason = payload.Slice(2ip, payload.Len() - 2ip).get_if<NetBytes>() as NetBytes;
    if !valid_text(reason) {
      return WebSocketError{kind: WebSocketErrorKind.InvalidUtf8};
    }
  }

  if !self.close_sent {
    let sent = self.WriteFrame(8u8, payload, options);
    if sent.IsErr() {
      return sent.get_if<WebSocketError>() as WebSocketError;
    }
  }

  return own_message(WebSocketMessageKind.Close, reason, code);
}

method(WebSocketState) WriteFrame(
  opcode: uint8, payload: ref NetBytes, options: ref NetOperationOptions
) -> Result<Unit, WebSocketError> {
  var header: <uint8>[14] = <uint8>[14]{};
  let length = payload.Len();
  header[0] = 128u8 | opcode;
  var count: int32 = 2;
  if length <= 125ip {
    header[1] = length as uint8;
  } else {
    let width: int32 = length <= 65535ip ? 2 : 8;
    header[1] = width == 2 ? 126u8 : 127u8;
    var i: int32 = 0;
    while i < width {
      header[2 + i] = (((length as uint64) >> (((width - i - 1) * 8) as uint64)) & 255u64) as uint8;
      i += 1;
    }
    count += width;
  }

  var mask: string = "";
  var entropy = WebSocketEntropy{};
  if self.client {
    if !entropy.Fill(4) {
      return WebSocketError{kind: WebSocketErrorKind.EntropyUnavailable};
    }
    mask = entropy.Bytes(4);
    header[1] = header[1] | 128u8;
    var i: int32 = 0;
    while i < 4 {
      header[count + i] = mask.ByteAt(i) as uint8;
      i += 1;
    }
    count += 4;
  }

  let bytes = NetBytes.FromRaw(&header[0], count as intptr).get_if<NetBytes>() as NetBytes;
  let written = self.transport.WriteAll(bytes, options);
  if written.IsErr() || length == 0ip {
    return written;
  }

  if !self.client {
    return self.transport.WriteAll(payload, options);
  }

  var block: <uint8>[4096] = <uint8>[4096]{};
  var offset: intptr = 0;
  while offset < length {
    let remaining = length - offset;
    let size = remaining < 4096ip ? remaining : 4096ip;
    unsafe {
      let input = cast<uint8>.pointer((payload.Data() as intptr) + offset);
      var i: int32 = 0;
      while i < size as int32 {
        let mask_index = ((offset + (i as intptr)) % 4ip) as int32;
        block[i] = input[i] ^ (mask.ByteAt(mask_index) as uint8);
        i += 1;
      }
    }
    let chunk = NetBytes.FromRaw(&block[0], size).get_if<NetBytes>() as NetBytes;
    let sent = self.transport.WriteAll(chunk, options);
    if sent.IsErr() {
      return sent;
    }
    offset += size;
  }

  return UnitValue();
}

// nyra-lint-allow: prefer-type-owned-functions -- Copy a payload without access to session state.
func own_message(
  kind: WebSocketMessageKind, bytes: ref NetBytes, code: int32?
) -> Result<WebSocketMessage, WebSocketError> {
  let result = NetBuffer.CopyFrom(bytes);
  if result.IsErr() {
    return WebSocketError{kind: WebSocketErrorKind.ResourceExhausted, network_error: result.get_if<NetError>()};
  }

  return WebSocketMessage{kind: kind, payload: result.get_if<NetBuffer>() as NetBuffer, close_code: code};
}

// nyra-lint-allow: prefer-type-owned-functions -- Pure UTF-8 validation of borrowed wire bytes.
func valid_text(bytes: ref NetBytes) -> bool {
  if bytes.Len() == 0ip {
    return true;
  }

  unsafe {
    return string.ViewFrom(bytes.Data() as *const int8, bytes.Len() as int32).IsValidUtf8();
  }
}

// nyra-lint-allow: prefer-type-owned-functions -- Pure RFC close-code predicate without state.
func valid_close_code(code: int32) -> bool {
  return (code >= 1000 && code <= 1014 && code != 1004 && code != 1005 && code != 1006)
    || (code >= 3000 && code <= 4999);
}
