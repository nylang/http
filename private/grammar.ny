// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief HTTP byte grammar, ASCII comparison and value formatting without mutable protocol state. */
module HttpGrammar;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";

/**
 * @brief Read an HTTP source byte through a bounds-checked byte accessor.
 * @returns The widened source byte, or the implementation sentinel outside the range.
 */
pub func HttpChar(text: ref string, index: int32) -> int32 {
  return (text[index] as uint8) as int32;
}

/**
 * @brief Recognize the HTTP token character grammar.
 * @returns True only for admitted token bytes.
 */
pub func HttpTchar(ch: int32) -> bool {
  if (ch >= 48 && ch <= 57) || (ch >= 65 && ch <= 90) || (ch >= 97 && ch <= 122) {
    return true;
  }

  let punctuation: string = "!#$%&'*+-.^_`|~";
  var i: int32 = 0;
  while i < punctuation.length {
    if HttpChar(punctuation, i) == ch {
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
pub func HttpToken(text: ref string) -> bool {
  if text.length == 0 {
    return false;
  }

  var i: int32 = 0;
  while i < text.length {
    if !HttpTchar(HttpChar(text, i)) {
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
pub func HttpValue(text: ref string) -> bool {
  var i: int32 = 0;
  while i < text.length {
    let ch: int32 = HttpChar(text, i);
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
pub func HttpEqual(left: ref string, right: ref string) -> bool {
  if left.length != right.length {
    return false;
  }

  var i: int32 = 0;
  while i < left.length {
    var a: int32 = HttpChar(left, i);
    var b: int32 = HttpChar(right, i);
    if a >= 65 && a <= 90 {
      a = a + 32;
    }

    if b >= 65 && b <= 90 {
      b = b + 32;
    }

    if a != b {
      return false;
    }

    i = i + 1;
  }

  return true;
}

/**
 * @brief Remove HTTP optional whitespace from both ends of a field component.
 * @returns The retained trimmed string value.
 */
pub func HttpTrim(text: ref string) -> string {
  var begin: int32 = 0;
  var end: int32 = text.length;
  while begin < end && (text[begin] == ' ' || text[begin] == '\t') {
    begin = begin + 1;
  }

  while end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t') {
    end = end - 1;
  }

  return text.Substring(begin, end - begin);
}

/**
 * @brief Recognize the supported HTTP version spellings.
 * @returns The supported minor-version discriminator, or the invalid-version sentinel.
 */
pub func HttpVersion(text: ref string) -> int32 {
  if text.Equal("HTTP/1.0") {
    return 0;
  }

  if text.Equal("HTTP/1.1") {
    return 1;
  }

  return -1;
}

/**
 * @brief Recognize ASCII hexadecimal bytes for HTTP framing and escaped targets.
 * @returns True for decimal digits and ASCII a-f or A-F.
 */
pub func HttpHex(ch: int32) -> bool {
  return (ch >= 48 && ch <= 57) || (ch >= 65 && ch <= 70) || (ch >= 97 && ch <= 102);
}

/**
 * @brief Validate request-target syntax in the context of the originating method.
 * @returns True for an admitted target spelling without fragment or injection bytes.
 */
pub func HttpTarget(verb: ref string, target: ref string) -> bool {
  if target.Equal("*") {
    return verb.Equal("OPTIONS");
  }

  if target.length == 0 || target[0] != '/' {
    return false;
  }

  var i: int32 = 0;
  while i < target.length {
    let ch: int32 = HttpChar(target, i);
    if ch <= 32 || ch >= 127 || ch == 35 || ch == 92 {
      return false;
    }

    if ch == 37 {
      if target.length - i < 3 || !HttpHex(HttpChar(target, i + 1)) || !HttpHex(HttpChar(target, i + 2)) {
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
pub func HttpHost(text: ref string) -> bool {
  if text.length == 0 {
    return false;
  }

  var end: int32 = 0;
  if text[0] == '[' {
    end = 1;
    while end < text.length && text[end] != ']' {
      end = end + 1;
    }

    if end == text.length {
      return false;
    }

    let literal: string = text.Substring(1, end - 1);
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
    while end < text.length && text[end] != ':' {
      let ch: int32 = HttpChar(text, end);
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

  if end == text.length {
    return true;
  }

  if text[end] != ':' || end + 1 == text.length {
    return false;
  }

  var port: uint32 = 0u32;
  end = end + 1;
  while end < text.length {
    let ch: int32 = HttpChar(text, end);
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
pub func HttpMakeError(kind: HttpErrorKind) -> HttpError {
  return HttpError{kind: kind};
}
/**
 * @brief Fold only ASCII letters in a URL scheme or host component.
 * @returns A retained lowercase spelling without Unicode or IDNA normalization.
 */
pub func UrlLower(text: ref string) -> string {
  var out: StringBuffer = StringBuffer.New();
  var i: int32 = 0;
  while i < text.length {
    var c: int32 = (text[i] as uint8) as int32;
    if c >= 65 && c <= 90 {
      c = c + 32;
    }

    var byte: int8 = c as int8;
    out.Append(string.ViewFrom(&byte, 1));
    i = i + 1;
  }

  return out.Take();
}

/**
 * @brief Format a URL port or generated length as unsigned decimal text.
 * @returns Exact locale-independent base-10 text.
 */
pub func UrlDecimal(n: uint64) -> string {
  if n == 0u64 {
    return "0";
  }

  var value: uint64 = n;
  var out: string = "";
  while value != 0u64 {
    var digit: StringBuffer = StringBuffer.New();
    var byte: int8 = (((value % 10u64) as int32) + 48) as int8;
    digit.Append(string.ViewFrom(&byte, 1));
    out = digit.Take().Concat(out);
    value = value / 10u64;
  }

  return out;
}
