// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Body bounds and trailer admission shared by decoding and encoding. */
module HttpFramingRules;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "private/grammar.ny";

/**
 * @brief Normalize and validate body framing bounds shared by decoder and encoder.
 * @returns Validated limits, or InvalidArgument for unsafe or unsupported bounds.
 */
pub method(HttpBodyLimits) Normalize() -> Result<HttpBodyLimits, HttpError> {
  var caps: HttpBodyLimits = self;
  if caps.max_body_bytes == 0u64 {
    caps.max_body_bytes = 16777216u64;
  }

  if caps.max_framing_bytes == 0 {
    caps.max_framing_bytes = 1048576;
  }

  if caps.max_line_bytes == 0 {
    caps.max_line_bytes = 8192;
  }

  if caps.max_trailers == 0 {
    caps.max_trailers = 100;
  }

  if caps.max_body_bytes > 9223372036837998591u64
    || caps.max_framing_bytes < 1
    || caps.max_framing_bytes > 16777216
    || caps.max_line_bytes < 1
    || caps.max_line_bytes > 65536
    || caps.max_trailers < 1
    || caps.max_trailers > 128 {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  return caps;
}

/**
 * @brief Apply framing, routing, authentication and connection-nominated trailer restrictions.
 * @returns True when the field must be rejected as a trailer for this head.
 */
pub method(HttpHead) ForbidsTrailer(name: ref string) -> bool {
  if (name).EqualAsciiIgnoreCase("Content-Length")
    || (name).EqualAsciiIgnoreCase("Transfer-Encoding")
    || (name).EqualAsciiIgnoreCase("Host")
    || (name).EqualAsciiIgnoreCase("Connection")
    || (name).EqualAsciiIgnoreCase("Trailer")
    || (name).EqualAsciiIgnoreCase("TE")
    || (name).EqualAsciiIgnoreCase("Upgrade")
    || (name).EqualAsciiIgnoreCase("Keep-Alive")
    || (name).EqualAsciiIgnoreCase("Proxy-Connection")
    || (name).EqualAsciiIgnoreCase("Authorization")
    || (name).EqualAsciiIgnoreCase("Proxy-Authorization")
    || (name).EqualAsciiIgnoreCase("WWW-Authenticate")
    || (name).EqualAsciiIgnoreCase("Proxy-Authenticate")
    || (name).EqualAsciiIgnoreCase("Authentication-Info")
    || (name).EqualAsciiIgnoreCase("Proxy-Authentication-Info")
    || (name).EqualAsciiIgnoreCase("Content-Type")
    || (name).EqualAsciiIgnoreCase("Content-Encoding")
    || (name).EqualAsciiIgnoreCase("Content-Range")
    || (name).EqualAsciiIgnoreCase("Content-Language")
    || (name).EqualAsciiIgnoreCase("Content-Location")
    || (name).EqualAsciiIgnoreCase("Content-Disposition")
    || (name).EqualAsciiIgnoreCase("Cache-Control")
    || (name).EqualAsciiIgnoreCase("Location")
    || (name).EqualAsciiIgnoreCase("Set-Cookie")
    || (name).EqualAsciiIgnoreCase("Cookie")
    || (name).EqualAsciiIgnoreCase("Range")
    || (name).EqualAsciiIgnoreCase("Expect")
    || (name).EqualAsciiIgnoreCase("Max-Forwards") {
    return true;
  }

  var f: int32 = 0;
  while f < self.FieldCount() {
    let field: HttpField = (self.FieldAt(f).get_if<HttpField>()) as HttpField;
    if (field.name).EqualAsciiIgnoreCase("Connection") {
      var i: int32 = 0;
      while i < field.value.length {
        let start: int32 = i;
        while i < field.value.length && (field.value).ByteAtOr(i, 0) != 44 {
          i = i + 1;
        }

        let token: string = HttpLexeme.New(field.value.Substring(start, i - start)).TrimWhitespace();
        if (token).EqualAsciiIgnoreCase(name) {
          return true;
        }

        i = i + 1;
      }
    }

    f = f + 1;
  }

  return false;
}
