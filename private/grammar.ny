// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief HTTP byte grammar, ASCII comparison and value formatting without mutable protocol state. */
module HttpGrammar;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";

/** @brief Retained HTTP wire lexeme; grammar operations preserve original bytes. */
pub struct HttpLexeme {
  readonly raw: string;
}

/** @brief Retain source bytes without decoding, folding or normalization.
 * @returns Independent lexeme retaining its source payload; empty input is valid. */
@inline pub static method(HttpLexeme) New(raw: ref string) -> HttpLexeme {
  return HttpLexeme{raw: raw};
}

/** @brief HTTP/URI ASCII byte observation; out-of-range integers remain invalid values. */
pub struct HttpWireByte {
  readonly value: int32;
}

/** @brief Retain an integer byte observation without narrowing.
 * @returns Value suitable for grammar predicates, including negative miss sentinels. */
@inline pub static method(HttpWireByte) New(value: int32) -> HttpWireByte {
  return HttpWireByte{value: value};
}

/**
 * @brief Read an HTTP source byte through a bounds-checked byte accessor.
 * @returns The widened source byte, or the implementation sentinel outside the range.
 */
/**
 * @brief Recognize the HTTP token character grammar.
 * @returns True only for admitted token bytes.
 */
pub method(HttpWireByte) IsTokenCharacter() -> bool {
  if (self.value >= 48 && self.value <= 57) || (self.value >= 65 && self.value <= 90) || (self.value >= 97
    && self.value <= 122) {
    return true;
  }

  let punctuation: string = "!#$%&'*+-.^_`|~";
  var i: int32 = 0;
  while i < punctuation.length {
    if (punctuation).ByteAtOr(i, 0) == self.value {
      return true;
    }

    i = i + 1;
  }

  return false;
}

/**
 * @brief Validate a nonempty HTTP token without decoding its bytes.
 * @returns True when every byte satisfies the token grammar.
 */
pub method(HttpLexeme) IsToken() -> bool {
  if self.raw.length == 0 {
    return false;
  }

  var i: int32 = 0;
  while i < self.raw.length {
    if !HttpWireByte.New((self.raw).ByteAtOr(i, 0)).IsTokenCharacter() {
      return false;
    }

    i = i + 1;
  }

  return true;
}

/**
 * @brief Validate field-value bytes before admitting or emitting an HTTP header.
 * @returns True when the value contains no forbidden control or injection bytes.
 */
pub method(HttpLexeme) IsFieldValue() -> bool {
  var i: int32 = 0;
  while i < self.raw.length {
    let ch: int32 = (self.raw).ByteAtOr(i, 0);
    if (ch < 32 && ch != 9) || ch == 127 {
      return false;
    }

    i = i + 1;
  }

  return true;
}

/**
 * @brief Compare HTTP ASCII case-insensitive identifiers without locale conversion.
 * @returns True when lengths and ASCII-folded bytes match.
 */
/**
 * @brief Remove HTTP optional whitespace from both ends of a field component.
 * @returns The retained trimmed string value.
 */
pub method(HttpLexeme) TrimWhitespace() -> string {
  var begin: int32 = 0;
  var end: int32 = self.raw.length;
  while begin < end && (self.raw[begin] == ' ' || self.raw[begin] == '\t') {
    begin = begin + 1;
  }

  while end > begin && (self.raw[end - 1] == ' ' || self.raw[end - 1] == '\t') {
    end = end - 1;
  }

  return self.raw.Substring(begin, end - begin);
}

/**
 * @brief Recognize the supported HTTP version spellings.
 * @returns The supported minor-version discriminator, or the invalid-version sentinel.
 */
pub method(HttpLexeme) MinorVersion() -> int32 {
  if self.raw.Equal("HTTP/1.0") {
    return 0;
  }

  if self.raw.Equal("HTTP/1.1") {
    return 1;
  }

  return -1;
}

/**
 * @brief Recognize ASCII hexadecimal bytes for HTTP framing and escaped targets.
 * @returns True for decimal digits and ASCII a-f or A-F.
 */
pub method(HttpWireByte) IsHex() -> bool {
  return (self.value >= 48 && self.value <= 57) || (self.value >= 65 && self.value <= 70) || (self.value >= 97
    && self.value <= 102);
}

/**
 * @brief Validate request-target syntax in the context of the originating method.
 * @returns True for an admitted target spelling without fragment or injection bytes.
 */
pub method(HttpLexeme) AcceptsTarget(target: ref string) -> bool {
  if target.Equal("*") {
    return self.raw.Equal("OPTIONS");
  }

  if target.length == 0 || target[0] != '/' {
    return false;
  }

  var i: int32 = 0;
  while i < target.length {
    let ch: int32 = (target).ByteAtOr(i, 0);
    if ch <= 32 || ch >= 127 || ch == 35 || ch == 92 {
      return false;
    }

    if ch == 37 {
      if target.length - i < 3 || !HttpWireByte.New((target).ByteAtOr(i + 1, 0)).IsHex()
        || !HttpWireByte.New((target).ByteAtOr(i + 2, 0)).IsHex() {
        return false;
      }

      i = i + 2;
    }

    i = i + 1;
  }

  return true;
}

/**
 * @brief Validate an HTTP authority field, including numeric address forms.
 * @returns True for an admitted host/port spelling.
 */
pub method(HttpLexeme) IsHost() -> bool {
  if self.raw.length == 0 {
    return false;
  }

  var end: int32 = 0;
  if self.raw[0] == '[' {
    end = 1;
    while end < self.raw.length && self.raw[end] != ']' {
      end = end + 1;
    }

    if end == self.raw.length {
      return false;
    }

    let literal: string = self.raw.Substring(1, end - 1);
    if literal.Find("%") >= 0 {
      return false;
    }

    let parsed: Result<IpAddress, NetError> = IpAddress.Parse(literal);
    if parsed.IsErr() {
      return false;
    }

    if ((parsed.get_if<IpAddress>()) as IpAddress).Family() != IpFamily.V6 {
      return false;
    }

    end = end + 1;
  } else {
    while end < self.raw.length && self.raw[end] != ':' {
      let ch: int32 = (self.raw).ByteAtOr(end, 0);
      if ! ((ch >= 48 && ch <= 57)
        || (ch >= 65 && ch <= 90)
        || (ch >= 97 && ch <= 122)
        || ch == 45
        || ch == 46
        || ch == 95
        || ch == 126) {
        return false;
      }

      end = end + 1;
    }

    if end == 0 {
      return false;
    }
  }

  if end == self.raw.length {
    return true;
  }

  if self.raw[end] != ':' || end + 1 == self.raw.length {
    return false;
  }

  var port: uint32 = 0;
  end = end + 1;
  while end < self.raw.length {
    let ch: int32 = (self.raw).ByteAtOr(end, 0);
    if ch < 48 || ch > 57 {
      return false;
    }

    port = port * 10u32 + (ch - 48) as uint32;
    if port > 65535u32 {
      return false;
    }

    end = end + 1;
  }

  return true;
}
/**
 * @brief Construct a protocol error before any input offset has been committed.
 * @returns The requested protocol error kind with the default offset.
 */
/**
 * @brief Fold only ASCII letters in a URL scheme or host component.
 * @returns A retained lowercase spelling without Unicode or IDNA normalization.
 */
/**
 * @brief Format a URL port or generated length as unsigned decimal text.
 * @returns Exact locale-independent base-10 text.
 */
