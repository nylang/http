// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

module HttpUrl;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/client.ni";
import "interface/url.ni";
import "interface/redirect.ni";
import "private/grammar.ny";
import "private/writer.ny";

/** @brief Owned strict URL parsing without decoding or transport side effects. */

struct HttpUrlData {
  scheme: string;
  host: string;
  port: int32;
  authority: string;
  target: string;
}

/** @brief Immutable owned validated URL; default is invalid and copies retain its storage. */
pub struct HttpUrl {
  cell: arc<HttpUrlData>?;
}

// Fold ASCII host bytes only; this parser deliberately does not apply Unicode or IDNA normalization.

// Render the numeric authority port without introducing locale-dependent formatting.

method(HttpWireByte) IsUnreserved() -> bool {
  return (self.value >= 'a' && self.value <= 'z')
    || (self.value >= 'A' && self.value <= 'Z')
    || (self.value >= '0' && self.value <= '9')
    || self.value == '-'
    || self.value == '.'
    || self.value == '_'
    || self.value == '~';
}

method(HttpWireByte) IsSubdelimiter() -> bool {
  return self.value == '!'
    || self.value == '$'
    || self.value == '&'
    || self.value == '\''
    || self.value == '('
    || self.value == ')'
    || self.value == '*'
    || self.value == '+'
    || self.value == ','
    || self.value == ';'
    || self.value == '=';
}

// Validate escaped bytes without decoding: routing and Host identity must retain the original URL spelling.
method(HttpLexeme) InvalidUrlComponent(start: int32, end: int32, query: bool) -> int32 {
  var i: int32 = start;
  while i < end {
    let c: int32 = self.raw[i];
    if c == '%' {
      if i + 2 >= end || !HttpWireByte.New(self.raw[i + 1]).IsHex() || !HttpWireByte.New(self.raw[i + 2]).IsHex() {
        return i;
      }

      i = i + 3;
      continue;
    }

    if !HttpWireByte.New(c).IsUnreserved() && !HttpWireByte.New(c).IsSubdelimiter() && c != ':' && c != '@'
      && c != '/' && ! (query && c == '?') {
      return i;
    }

    i = i + 1;
  }

  return -1;
}

// OS getaddrinfo may interpret shortened, octal, hex or integer forms as IPv4.
method(HttpLexeme) LooksNumericHost() -> bool {
  var start: int32 = 0;
  var i: int32 = 0;
  while i <= self.raw.length {
    if i == self.raw.length || self.raw[i] == '.' {
      var j: int32 = start;
      var hex: bool = false;
      if i - start > 2 && self.raw[start] == '0' && self.raw[start + 1] == 'x' {
        hex = true;
        j = j + 2;
      }

      if j == i {
        return false;
      }

      while j < i {
        if hex {
          if !HttpWireByte.New(self.raw[j]).IsHex() {
            return false;
          }
        } else {
          if self.raw[j] < '0' || self.raw[j] > '9' {
            return false;
          }
        }

        j = j + 1;
      }

      start = i + 1;
    }

    i = i + 1;
  }

  return true;
}

/**
 * @brief Parse at most 8192 ASCII bytes; only absolute http/https, LDH DNS and strict IP
 *   literals.
 * @note Reject userinfo, empty/zero ports, trailing-dot DNS, IDNA, zone IDs, legacy numeric IP,
 *   backslash and raw non-ASCII/control/space. Validate percent triplets; never decode them.
 *   Normalize scheme/host/IP/default port, default empty path to /, omit validated fragment.
 *   Preserve path/query octets, percent spelling, dot segments and an empty query delimiter.
 * @returns Owned URL or HttpError with an input byte offset when available.
 */
pub static method(HttpUrl) Parse(text: ref string) -> Result<HttpUrl, HttpError> {
  if text.length > 8192 {
    return HttpError{kind: HttpErrorKind.LimitExceeded, offset: (8192) as int64};
  }

  var i: int32 = 0;
  while i < text.length {
    let c: int32 = (text[i] as uint8) as int32;
    if c <= 32 || c >= 127 || c == 92 {
      return HttpError{kind: HttpErrorKind.Malformed, offset: (i) as int64};
    }

    i = i + 1;
  }

  let sep: int32 = text.Find("://");
  if sep < 0 {
    return HttpError{kind: HttpErrorKind.Malformed, offset: (0) as int64};
  }

  let scheme: string = (text.Substring(0, sep)).ToLowerAscii();
  if !scheme.Equal("http") && !scheme.Equal("https") {
    return HttpError{kind: HttpErrorKind.Unsupported, offset: (0) as int64};
  }

  let start: int32 = sep + 3;
  var end: int32 = start;
  while end < text.length && text[end] != '/' && text[end] != '?' && text[end] != '#' {
    if text[end] == '@' {
      return HttpError{kind: HttpErrorKind.Unsupported, offset: (end) as int64};
    }

    end = end + 1;
  }

  if start == end {
    return HttpError{kind: HttpErrorKind.Malformed, offset: (start) as int64};
  }

  var host: string = "";
  var port_start: int32 = -1;
  var bracket: bool = false;
  if text[start] == '[' {
    bracket = true;
    var close: int32 = start + 1;
    while close < end && text[close] != ']' {
      if text[close] == '%' {
        return HttpError{kind: HttpErrorKind.Unsupported, offset: (close) as int64};
      }

      close = close + 1;
    }

    if close == end {
      return HttpError{kind: HttpErrorKind.Malformed, offset: (start) as int64};
    }

    let literal: string = text.Substring(start + 1, close - start - 1);
    let parsed: Result<IpAddress, NetError> = IpAddress.Parse(literal);
    if parsed.IsErr() || ((parsed.get_if<IpAddress>()) as IpAddress).Family() != IpFamily.V6 {
      return HttpError{kind: HttpErrorKind.Malformed, offset: (start) as int64};
    }

    host = ((parsed.get_if<IpAddress>()) as IpAddress).ToString();
    if close + 1 < end {
      if text[close + 1] != ':' {
        return HttpError{kind: HttpErrorKind.Malformed, offset: (close + 1) as int64};
      }

      port_start = close + 2;
    }
  } else {
    var stop: int32 = start;
    while stop < end && text[stop] != ':' {
      stop = stop + 1;
    }

    host = (text.Substring(start, stop - start)).ToLowerAscii();
    if stop < end {
      port_start = stop + 1;
    }

    if host.length == 0 || host.length > 253 {
      return HttpError{kind: HttpErrorKind.Malformed, offset: (start) as int64};
    }

    let ip: Result<IpAddress, NetError> = IpAddress.Parse(host);
    if ip.IsOk() {
      if ((ip.get_if<IpAddress>()) as IpAddress).Family() != IpFamily.V4 {
        return HttpError{kind: HttpErrorKind.Malformed, offset: (start) as int64};
      }

      host = ((ip.get_if<IpAddress>()) as IpAddress).ToString();
    } else {
      if HttpLexeme.New(host).LooksNumericHost() {
        return HttpError{kind: HttpErrorKind.Unsupported, offset: (start) as int64};
      }

      var label: int32 = 0;
      i = 0;
      while i <= host.length {
        if i == host.length || host[i] == '.' {
          if i == label || i - label > 63 || host[label] == '-' || host[i - 1] == '-' {
            return HttpError{kind: HttpErrorKind.Malformed, offset: (start + label) as int64};
          }

          label = i + 1;
        } else {
          let c: int32 = host[i];
          if ! ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
            return HttpError{kind: HttpErrorKind.Unsupported, offset: (start + i) as int64};
          }
        }

        i = i + 1;
      }
    }
  }

  var port: int32 = 80;
  if scheme.Equal("https") {
    port = 443;
  }

  let default_port: int32 = port;
  if port_start >= 0 {
    if port_start == end {
      return HttpError{kind: HttpErrorKind.Malformed, offset: (port_start) as int64};
    }

    port = 0;
    i = port_start;
    while i < end {
      if text[i] < '0' || text[i] > '9' {
        return HttpError{kind: HttpErrorKind.Malformed, offset: (i) as int64};
      }

      let digit: int32 = (text[i] as int32) - 48;
      if port >(65535 - digit) / 10 {
        return HttpError{kind: HttpErrorKind.Malformed, offset: (i) as int64};
      }

      port = port * 10 + digit;
      i = i + 1;
    }

    if port == 0 {
      return HttpError{kind: HttpErrorKind.Unsupported, offset: (port_start) as int64};
    }
  }

  var authority: string = host;
  if bracket {
    authority = "[".Concat(host).Concat("]");
  }

  if port != default_port {
    authority = authority.Concat(":").Concat(((port as uint64) as uint64).ToString());
  }

  var fragment: int32 = end;
  while fragment < text.length && text[fragment] != '#' {
    fragment = fragment + 1;
  }

  var query: int32 = end;
  while query < fragment && text[query] != '?' {
    query = query + 1;
  }

  let bad_path: int32 = HttpLexeme.New(text).InvalidUrlComponent(end, query, false);
  if bad_path >= 0 {
    return HttpError{kind: HttpErrorKind.Malformed, offset: (bad_path) as int64};
  }

  if query < fragment {
    let bad: int32 = HttpLexeme.New(text).InvalidUrlComponent(query + 1, fragment, true);
    if bad >= 0 {
      return HttpError{kind: HttpErrorKind.Malformed, offset: (bad) as int64};
    }
  }

  if fragment < text.length {
    let bad: int32 = HttpLexeme.New(text).InvalidUrlComponent(fragment + 1, text.length, true);
    if bad >= 0 {
      return HttpError{kind: HttpErrorKind.Malformed, offset: (bad) as int64};
    }
  }

  var target: string = text.Substring(end, fragment - end);
  if end == query {
    target = "/".Concat(target);
  }

  return HttpUrl{cell: new arc<HttpUrlData>{
    scheme: scheme,
    host: host,
    port: port,
    authority: authority,
    target: target
  }};
}

/**
 * @brief Whether Parse created this value successfully.
 * @returns Whether Parse created this value successfully.
 */
pub method(HttpUrl) IsValid() -> bool {
  return self.cell != nil;
}

/**
 * @brief Lowercase http/https, or empty for an invalid default.
 * @returns Lowercase http/https, or empty for an invalid default.
 */
pub method(HttpUrl) Scheme() -> string {
  if self.cell == nil {
    return "";
  }

  return (self.cell as arc<HttpUrlData>).scheme;
}

/**
 * @brief Canonical unbracketed DNS/IP host for resolution and certificate identity, or empty.
 * @returns Canonical unbracketed DNS/IP host for resolution and certificate identity, or empty.
 */
pub method(HttpUrl) Host() -> string {
  if self.cell == nil {
    return "";
  }

  return (self.cell as arc<HttpUrlData>).host;
}

/**
 * @brief Effective port, including default 80/443; zero for an invalid default.
 * @returns Effective port, including default 80/443; zero for an invalid default.
 */
pub method(HttpUrl) Port() -> int32 {
  if self.cell == nil {
    return 0;
  }

  return (self.cell as arc<HttpUrlData>).port;
}

/**
 * @brief Whether this URL requires verified TLS.
 * @returns Whether this URL requires verified TLS.
 */
pub method(HttpUrl) IsSecure() -> bool {
  return self.Scheme().Equal("https");
}

/**
 * @brief Canonical Host field, brackets for IPv6 and port only when nondefault; empty if
 *   invalid.
 * @returns Canonical Host field, brackets for IPv6 and port only when nondefault; empty if
 *   invalid.
 */
pub method(HttpUrl) HostField() -> string {
  if self.cell == nil {
    return "";
  }

  return (self.cell as arc<HttpUrlData>).authority;
}

/**
 * @brief Origin-form path and optional query, without fragment; empty if invalid.
 * @returns Origin-form path and optional query, without fragment; empty if invalid.
 */
pub method(HttpUrl) Target() -> string {
  if self.cell == nil {
    return "";
  }

  return (self.cell as arc<HttpUrlData>).target;
}

/**
 * @brief Canonical absolute URL without fragment; empty if invalid.
 * @returns Canonical absolute URL without fragment; empty if invalid.
 */
pub method(HttpUrl) ToString() -> string {
  if self.cell == nil {
    return "";
  }

  return self.Scheme().Concat("://").Concat(self.HostField()).Concat(self.Target());
}

// Generate routing fields in one place for buffered and streamed URL requests.
method(HttpUrl) BuildRequestHead(
  verb: ref string,
  fields: ref <HttpField>[],
  body_length: uint64,
  chunked: bool,
  streaming: bool
) -> Result<NetBuffer, HttpError> {
  if !self.IsValid() {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  if fields.length > 126 {
    return HttpError{kind: HttpErrorKind.LimitExceeded};
  }

  var all: owned <HttpField>[] = new <HttpField>[fields.length + 2];
  all[0] = HttpField{name: "Host", value: self.HostField()};
  all[1] = HttpField{name: "Content-Length", value: ((body_length) as uint64).ToString()};
  if chunked {
    all[1] = HttpField{name: "Transfer-Encoding", value: "chunked"};
  }

  var i: int32 = 0;
  while i < fields.length {
    let name: string = fields[i].name;
    if (name).EqualAsciiIgnoreCase("Host")
      || (name).EqualAsciiIgnoreCase("Content-Length")
      || (name).EqualAsciiIgnoreCase("Transfer-Encoding") {
      return HttpError{kind: HttpErrorKind.InvalidArgument};
    }

    if (!streaming && (name).EqualAsciiIgnoreCase("Expect")) || (name).EqualAsciiIgnoreCase("Upgrade") {
      return HttpError{kind: HttpErrorKind.Unsupported};
    }

    all[i + 2] = fields[i];
    i = i + 1;
  }

  if verb.Equal("CONNECT") {
    return HttpError{kind: HttpErrorKind.Unsupported};
  }

  return HttpHead.EncodeRequest(verb, self.Target(), all);
}

/**
 * @brief Serialize one HTTP/1.1 request with generated Host and Content-Length.
 * @returns Ok with NetBuffer on success; Err with HttpError on the failure paths described
 *   above.
 * @note Additional fields must not supply Host, Content-Length or Transfer-Encoding. The
 *   connected profile rejects CONNECT/Expect/Upgrade before network I/O. Body length is plaintext
 *   bytes.
 */
pub method(HttpUrl) RequestHead(
  verb: ref string,
  fields: ref <HttpField>[],
  body_length: uint64
) -> Result<NetBuffer, HttpError> {
  return self.BuildRequestHead(verb, fields, body_length, false, false);
}

/**
 * @brief Build an owned streamed HTTP/1.1 head with URL-derived Host and target.
 * @param plan None (zero length), ContentLength, or Chunked (zero length); close_connection must
 *   be false.
 * @returns Ok with NetBuffer on success; Err with HttpError on the failure paths described
 *   above.
 * @note None generates Content-Length: 0. Additional fields cannot override Host/framing or
 *   Upgrade. One case-insensitive Expect: 100-continue is allowed for nonempty fixed or chunked
 *   producers. Shared writer/exchange validation rejects unsupported negotiation before I/O. No
 *   body retained.
 */
pub method(HttpUrl) StreamingRequestHead(
  verb: ref string,
  fields: ref <HttpField>[],
  plan: ref HttpBodyPlan
) -> Result<NetBuffer, HttpError> {
  if plan.close_connection
    || (
      plan.kind != HttpBodyKind.None
        && plan.kind != HttpBodyKind.ContentLength
        && plan.kind != HttpBodyKind.Chunked
    )
    || (plan.kind != HttpBodyKind.ContentLength && plan.length != 0u64) {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  let made: Result<NetBuffer, HttpError> = self.BuildRequestHead(verb,
    fields,
    plan.length,
    plan.kind == HttpBodyKind.Chunked,
    true);
  if made.IsErr() {
    return (made.get_if<HttpError>()) as HttpError;
  }

  let wire: NetBuffer = (made.get_if<NetBuffer>()) as NetBuffer;
  // Share Expect/upgrade/framing validation without imposing a caller's body budget.
  var checked: Result<HttpClientExchange, HttpError> = HttpClientExchange.NewStreaming(
    wire,
    HttpClientLimits{
      max_retained_request_bytes: 1073741824,
      body: HttpBodyLimits{max_body_bytes: 9223372036837998591u64}
    }
  );
  if checked.IsErr() {
    return (checked.get_if<HttpError>()) as HttpError;
  }

  return wire;
}
