// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of HttpHeadCodec;

/** @brief Strict line syntax and unambiguous HTTP/1.x framing decisions. */

// Validate authority syntax before allowing a parsed Host field to influence request routing.

// Separate request and response start-line rules before accepting any framing headers.
method(HttpParserData) ParseStartLine(text: ref string) -> HttpErrorKind? {
  var head: arc<HttpHeadData> = self.head;
  if head.response {
    if text.length < 13 || text[8] != ' ' || text[12] != ' ' {
      return HttpErrorKind.Malformed;
    }

    head.minor = HttpLexeme.New(text.Substring(0, 8)).MinorVersion();
    if head.minor < 0 {
      return HttpErrorKind.Unsupported;
    }

    var status: int32 = 0;
    var i: int32 = 9;
    while i < 12 {
      let ch: int32 = (text).ByteAtOr(i, 0);
      if ch < 48 || ch > 57 {
        return HttpErrorKind.Malformed;
      }

      status = status * 10 + ch - 48;
      i = i + 1;
    }

    if status < 100 || status > 599 {
      return HttpErrorKind.Malformed;
    }

    let reason: string = text.Substring(13, text.length - 13);
    if !HttpLexeme.New(reason).IsFieldValue() {
      return HttpErrorKind.Malformed;
    }

    head.status = status;
    head.reason = reason;
  } else {
    let first: int32 = text.Find(" ");
    if first < 1 {
      return HttpErrorKind.Malformed;
    }

    let tail: string = text.Substring(first + 1, text.length - first - 1);
    let second: int32 = tail.Find(" ");
    if second < 1 {
      return HttpErrorKind.Malformed;
    }

    let verb: string = text.Substring(0, first);
    let target: string = tail.Substring(0, second);
    if !HttpLexeme.New(verb).IsToken() {
      return HttpErrorKind.Malformed;
    }

    if !HttpLexeme.New(verb).AcceptsTarget(target) {
      return HttpErrorKind.Unsupported;
    }

    head.minor = HttpLexeme.New(tail.Substring(second + 1, tail.length - second - 1)).MinorVersion();
    if head.minor < 0 {
      return HttpErrorKind.Unsupported;
    }

    head.verb = verb;
    head.target = target;
  }

  self.started = true;

  return nil;
}

method(HttpParserData) ParseConnectionTokens(text: ref string) -> bool {
  var begin: int32 = 0;
  while begin < text.length {
    var end: int32 = begin;
    while end < text.length && text[end] != ',' {
      end = end + 1;
    }

    let token: string = HttpLexeme.New(text.Substring(begin, end - begin)).TrimWhitespace();
    if !HttpLexeme.New(token).IsToken() {
      return false;
    }

    if (token).EqualAsciiIgnoreCase("close") {
      self.close = true;
    }

    if (token).EqualAsciiIgnoreCase("keep-alive") {
      self.keep_alive = true;
    }

    if end == text.length {
      return true;
    }

    begin = end + 1;
  }

  return false;
}

method(HttpParserData) FinishHead() -> HttpErrorKind? {
  var head: arc<HttpHeadData> = self.head;
  if !head.response && head.minor == 1 && self.hosts != 1 {
    return HttpErrorKind.Malformed;
  }

  if self.has_length && self.has_transfer {
    return HttpErrorKind.InvalidFraming;
  }

  if self.has_transfer && head.minor == 0 {
    return HttpErrorKind.InvalidFraming;
  }

  if self.has_transfer && !(self.transfer).EqualAsciiIgnoreCase("chunked") {
    return HttpErrorKind.Unsupported;
  }

  var plan: HttpBodyPlan = HttpBodyPlan{close_connection: self.close
    || (head.minor == 0 && !self.keep_alive)};
  if head.response && ((head.status >= 100 && head.status < 200) || head.status == 204) {
    if self.has_length || self.has_transfer {
      return HttpErrorKind.InvalidFraming;
    }

    if head.status == 101 {
      plan.kind = HttpBodyKind.Upgrade;
    }
  } else if head.response && self.request_method.Equal("CONNECT") && head.status >= 200 && head.status < 300 {
    if self.has_length || self.has_transfer {
      return HttpErrorKind.InvalidFraming;
    }

    plan.kind = HttpBodyKind.Tunnel;
  } else if head.response && (self.request_method.Equal("HEAD") || head.status == 304) {
    plan.kind = HttpBodyKind.None;
  } else if self.has_transfer {
    plan.kind = HttpBodyKind.Chunked;
  } else if self.has_length {
    plan.kind = HttpBodyKind.ContentLength;
    plan.length = self.length;
  } else if head.response {
    plan.kind = HttpBodyKind.UntilEof;
    plan.close_connection = true;
  }

  head.plan = plan;
  self.complete = true;

  return nil;
}

// Accumulate framing decisions only after the complete header line passes syntax checks.
method(HttpParserData) ParseLine(text: ref string) -> HttpErrorKind? {
  var head: arc<HttpHeadData> = self.head;
  if !self.started {
    return self.ParseStartLine(text);
  }

  if text.length == 0 {
    return self.FinishHead();
  }

  if head.field_count >= self.limits.max_fields {
    return HttpErrorKind.LimitExceeded;
  }

  let colon: int32 = text.Find(":");
  if colon < 1 {
    return HttpErrorKind.Malformed;
  }

  let name: string = text.Substring(0, colon);
  let value: string = HttpLexeme.New(text.Substring(colon + 1, text.length - colon - 1)).TrimWhitespace();
  if !HttpLexeme.New(name).IsToken() || !HttpLexeme.New(value).IsFieldValue() {
    return HttpErrorKind.Malformed;
  }

  if (name).EqualAsciiIgnoreCase("host") {
    self.hosts = self.hosts + 1;
    if self.hosts > 1 || !HttpLexeme.New(value).IsHost() {
      return HttpErrorKind.Malformed;
    }
  } else if (name).EqualAsciiIgnoreCase("content-length") {
    if self.has_length || value.length == 0 {
      return HttpErrorKind.InvalidFraming;
    }

    var length: uint64 = 0;
    var i: int32 = 0;
    while i < value.length {
      let ch: int32 = (value).ByteAtOr(i, 0);
      if ch < 48 || ch > 57 {
        return HttpErrorKind.InvalidFraming;
      }

      let digit: uint64 = (ch - 48) as uint64;
      if length >(18446744073709551615u64 - digit) / 10u64 {
        return HttpErrorKind.InvalidFraming;
      }

      length = length * 10u64 + digit;
      i = i + 1;
    }

    self.has_length = true;
    self.length = length;
  } else if (name).EqualAsciiIgnoreCase("transfer-encoding") {
    if self.has_transfer {
      return HttpErrorKind.InvalidFraming;
    }

    self.has_transfer = true;
    self.transfer = value;
  } else if (name).EqualAsciiIgnoreCase("connection") {
    if !self.ParseConnectionTokens(value) {
      return HttpErrorKind.Malformed;
    }
  }

  head.fields[head.field_count] = HttpField{name: name, value: value};
  head.field_count = head.field_count + 1;

  return nil;
}
