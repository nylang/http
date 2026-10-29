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
pub func HttpNormalizeBodyLimits(limits: ref HttpBodyLimits) -> Result<HttpBodyLimits, HttpError> {
  var caps: HttpBodyLimits = limits;
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
    return HttpMakeError(HttpErrorKind.InvalidArgument);
  }

  return caps;
}

/**
 * @brief Apply framing, routing, authentication and connection-nominated trailer restrictions.
 * @returns True when the field must be rejected as a trailer for this head.
 */
pub func HttpTrailerForbidden(head: ref HttpHead, name: ref string) -> bool {
  if HttpEqual(name, "Content-Length")
    || HttpEqual(name, "Transfer-Encoding")
    || HttpEqual(name, "Host")
    || HttpEqual(name, "Connection")
    || HttpEqual(name, "Trailer")
    || HttpEqual(name, "TE")
    || HttpEqual(name, "Upgrade")
    || HttpEqual(name, "Keep-Alive")
    || HttpEqual(name, "Proxy-Connection")
    || HttpEqual(name, "Authorization")
    || HttpEqual(name, "Proxy-Authorization")
    || HttpEqual(name, "WWW-Authenticate")
    || HttpEqual(name, "Proxy-Authenticate")
    || HttpEqual(name, "Authentication-Info")
    || HttpEqual(name, "Proxy-Authentication-Info")
    || HttpEqual(name, "Content-Type")
    || HttpEqual(name, "Content-Encoding")
    || HttpEqual(name, "Content-Range")
    || HttpEqual(name, "Content-Language")
    || HttpEqual(name, "Content-Location")
    || HttpEqual(name, "Content-Disposition")
    || HttpEqual(name, "Cache-Control")
    || HttpEqual(name, "Location")
    || HttpEqual(name, "Set-Cookie")
    || HttpEqual(name, "Cookie")
    || HttpEqual(name, "Range")
    || HttpEqual(name, "Expect")
    || HttpEqual(name, "Max-Forwards") {
    return true;
  }

  var f: int32 = 0;
  while f < head.FieldCount() {
    let field: HttpField = (head.FieldAt(f).get_if<HttpField>()) as HttpField;
    if HttpEqual(field.name, "Connection") {
      var i: int32 = 0;
      while i < field.value.length {
        let start: int32 = i;
        while i < field.value.length && HttpChar(field.value, i) != 44 {
          i = i + 1;
        }

        let token: string = HttpTrim(field.value.Substring(start, i - start));
        if HttpEqual(token, name) {
          return true;
        }

        i = i + 1;
      }
    }

    f = f + 1;
  }

  return false;
}
