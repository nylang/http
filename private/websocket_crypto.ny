// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief WebSocket-only nonce, masking entropy and RFC 6455 accept computation. */
module WebSocketHandshakeCrypto;
import "stdlib:stdlib.ny";

/** @brief OS-provided unpredictable bytes, with no TLS provider dependency. */
pub struct WebSocketEntropy {
  words: <uint32>[4];
}

@target("macos", "linux", "ios") {
  @extern("C") func getentropy(output: *mut uint8, size: uintptr) -> int32;

  /** @brief Fill a fresh 4- or 16-byte value from OS entropy.
   * @returns True on complete success; false when the entropy provider fails.
   */
  pub method(WebSocketEntropy) Fill(size: int32) -> bool {
    unsafe {
      return getentropy((&mut self.words[0]) as *mut uint8, size as uintptr) == 0;
    }
  }
}

@target("android") {
  /** @brief Read OS entropy on Android, including API levels without getentropy. */
  pub method(WebSocketEntropy) Fill(size: int32) -> bool {
    var opened = File.New("/dev/urandom").Open(FileMode.Read);
    if opened.IsErr() {
      return false;
    }

    var stream = opened.get_if<FileStream>() as FileStream;
    var offset: intptr = 0;
    while offset < size as intptr {
      let target = cast<uint8>.pointer(((&mut self.words[0]) as intptr) + offset);
      let result = stream.Read(target, (size as intptr) - offset);
      if result.IsErr() || (result.get_if<intptr>() as intptr) <= 0ip {
        return false;
      }
      offset += result.get_if<intptr>() as intptr;
    }

    return true;
  }
}

@target("windows") {
  @extern("C") func rand_s(output: *mut uint32) -> int32;

  /** @brief Fill a fresh 4- or 16-byte value from OS entropy.
   * @returns True on complete success; false when the entropy provider fails.
   */
  pub method(WebSocketEntropy) Fill(size: int32) -> bool {
    var i: int32 = 0;
    while i < size / 4 {
      if rand_s(&mut self.words[i]) != 0 {
        return false;
      }
      i += 1;
    }

    return true;
  }
}

/** @brief Borrow the generated octets for the lifetime of this value.
 * @returns A view of the requested bytes, valid only for the lifetime of this value.
 */
pub method(WebSocketEntropy) Bytes(size: int32) -> string {
  unsafe {
    return string.ViewFrom((&self.words[0]) as *const int8, size);
  }
}

/** @brief A validated 24-byte Sec-WebSocket-Key text value. */
pub struct WebSocketKey {
  readonly text: string;
}

/** @brief Validate the canonical Base64 encoding of exactly 16 bytes.
 * @returns True only for a canonical 24-byte WebSocket key.
 */
pub method(WebSocketKey) IsValid() -> bool {
  if self.text.length != 24 {
    return false;
  }

  let decoded = Base64.Decode(self.text);
  if decoded == nil {
    return false;
  }

  let bytes = decoded as string;
  return bytes.length == 16 && Base64.Encode(bytes) == self.text;
}

// SHA-1 is used exclusively for the RFC 6455 opening challenge.
struct WebSocketDigest {
  hash: <uint32>[5];
  words: <uint32>[80];
}

/** @brief Compute the accept digest for a validated key.
 * @note The 24-byte key plus the 36-byte GUID always form two padded SHA-1 blocks.
 * @returns An owned Base64 SHA-1 digest of the key and protocol GUID.
 */
pub method(WebSocketKey) Accept() -> string {
  let input = self.text.Concat("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  var digest = WebSocketDigest{};
  digest.hash[0] = 0x67452301u32;
  digest.hash[1] = 0xefcdab89u32;
  digest.hash[2] = 0x98badcfeu32;
  digest.hash[3] = 0x10325476u32;
  digest.hash[4] = 0xc3d2e1f0u32;

  var i: int32 = 0;
  while i < 15 {
    var word: uint32 = 0;
    var j: int32 = 0;
    while j < 4 {
      word = (word << 8u32) | (input.ByteAt(i * 4 + j) as uint32);
      j += 1;
    }
    digest.words[i] = word;
    i += 1;
  }
  digest.words[15] = 0x80000000u32;
  digest.Compress();

  i = 0;
  while i < 15 {
    digest.words[i] = 0u32;
    i += 1;
  }
  digest.words[15] = 480u32;
  digest.Compress();

  var bytes: <uint8>[20] = <uint8>[20]{};
  i = 0;
  while i < 20 {
    bytes[i] = ((digest.hash[i / 4] >> (((3 - i % 4) * 8) as uint32)) & 255u32) as uint8;
    i += 1;
  }

  unsafe {
    return Base64.Encode(string.ViewFrom((&bytes[0]) as *const int8, 20));
  }
}

method(WebSocketDigest) Compress() -> void {
  var i: int32 = 16;
  while i < 80 {
    let word: uint32 = self.words[i - 3] ^ self.words[i - 8] ^ self.words[i - 14] ^ self.words[i - 16];
    self.words[i] = (word << 1u32) | (word >> 31u32);
    i += 1;
  }

  var a: uint32 = self.hash[0];
  var b: uint32 = self.hash[1];
  var c: uint32 = self.hash[2];
  var d: uint32 = self.hash[3];
  var e: uint32 = self.hash[4];
  i = 0;
  while i < 80 {
    var f: uint32 = b ^ c ^ d;
    var k: uint32 = 0xca62c1d6u32;
    if i < 20 {
      f = (b & c) | ((~b) & d);
      k = 0x5a827999u32;
    } else if i < 40 {
      k = 0x6ed9eba1u32;
    } else if i < 60 {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8f1bbcdcu32;
    }
    let next: uint32 = ((a << 5u32) | (a >> 27u32)) + f + e + k + self.words[i];
    e = d;
    d = c;
    c = (b << 30u32) | (b >> 2u32);
    b = a;
    a = next;
    i += 1;
  }

  self.hash[0] += a;
  self.hash[1] += b;
  self.hash[2] += c;
  self.hash[3] += d;
  self.hash[4] += e;
}
