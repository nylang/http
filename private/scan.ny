// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of HttpHeadCodec;

/** @brief Strict line syntax and unambiguous HTTP/1.x framing decisions. */

// Validate authority syntax before allowing a parsed Host field to influence request routing.

// Separate request and response start-line rules before accepting any framing headers.
func http_start(state: arc<HttpParserData>, text: ref string) -> HttpErrorKind? {
  var cell: arc<HttpParserData> = state;
  var head: arc<HttpHeadData> = cell.head;
  if head.response {
    if text.length < 13 || text[8] != ' ' || text[12] != ' ' {
      return HttpErrorKind.Malformed;
    }

    head.minor = HttpVersion(text.Substring(0, 8));
    if head.minor < 0 {
      return HttpErrorKind.Unsupported;
    }

    var status: int32 = 0;
    var i: int32 = 9;
    while i < 12 {
      let ch: int32 = HttpChar(text, i);
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
    if !HttpValue(reason) {
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
    if !HttpToken(verb) {
      return HttpErrorKind.Malformed;
    }

    if !HttpTarget(verb, target) {
      return HttpErrorKind.Unsupported;
    }

    head.minor = HttpVersion(tail.Substring(second + 1, tail.length - second - 1));
    if head.minor < 0 {
      return HttpErrorKind.Unsupported;
    }

    head.verb = verb;
    head.target = target;
  }

  cell.started = true;

  return nil;
}

func http_connection(state: arc<HttpParserData>, text: ref string) -> bool {
  var cell: arc<HttpParserData> = state;
  var begin: int32 = 0;
  while begin < text.length {
    var end: int32 = begin;
    while end < text.length && text[end] != ',' {
      end = end + 1;
    }

    let token: string = HttpTrim(text.Substring(begin, end - begin));
    if !HttpToken(token) {
      return false;
    }

    if HttpEqual(token, "close") {
      cell.close = true;
    }

    if HttpEqual(token, "keep-alive") {
      cell.keep_alive = true;
    }

    if end == text.length {
      return true;
    }

    begin = end + 1;
  }

  return false;
}

func http_finish(state: arc<HttpParserData>) -> HttpErrorKind? {
  var cell: arc<HttpParserData> = state;
  var head: arc<HttpHeadData> = cell.head;
  if !head.response && head.minor == 1 && cell.hosts != 1 {
    return HttpErrorKind.Malformed;
  }

  if cell.has_length && cell.has_transfer {
    return HttpErrorKind.InvalidFraming;
  }

  if cell.has_transfer && head.minor == 0 {
    return HttpErrorKind.InvalidFraming;
  }

  if cell.has_transfer && !HttpEqual(cell.transfer, "chunked") {
    return HttpErrorKind.Unsupported;
  }

  var plan: HttpBodyPlan = HttpBodyPlan{close_connection: cell.close
    || (head.minor == 0 && !cell.keep_alive)};
  if head.response && ((head.status >= 100 && head.status < 200) || head.status == 204) {
    if cell.has_length || cell.has_transfer {
      return HttpErrorKind.InvalidFraming;
    }

    if head.status == 101 {
      plan.kind = HttpBodyKind.Upgrade;
    }
  } else if head.response && cell.request_method.Equal("CONNECT") && head.status >= 200 && head.status < 300 {
    if cell.has_length || cell.has_transfer {
      return HttpErrorKind.InvalidFraming;
    }

    plan.kind = HttpBodyKind.Tunnel;
  } else if head.response && (cell.request_method.Equal("HEAD") || head.status == 304) {
    plan.kind = HttpBodyKind.None;
  } else if cell.has_transfer {
    plan.kind = HttpBodyKind.Chunked;
  } else if cell.has_length {
    plan.kind = HttpBodyKind.ContentLength;
    plan.length = cell.length;
  } else if head.response {
    plan.kind = HttpBodyKind.UntilEof;
    plan.close_connection = true;
  }

  head.plan = plan;
  cell.complete = true;

  return nil;
}

// Accumulate framing decisions only after the complete header line passes syntax checks.
func http_line(state: arc<HttpParserData>, text: ref string) -> HttpErrorKind? {
  var cell: arc<HttpParserData> = state;
  var head: arc<HttpHeadData> = cell.head;
  if !cell.started {
    return http_start(cell, text);
  }

  if text.length == 0 {
    return http_finish(cell);
  }

  if head.field_count >= cell.limits.max_fields {
    return HttpErrorKind.LimitExceeded;
  }

  let colon: int32 = text.Find(":");
  if colon < 1 {
    return HttpErrorKind.Malformed;
  }

  let name: string = text.Substring(0, colon);
  let value: string = HttpTrim(text.Substring(colon + 1, text.length - colon - 1));
  if !HttpToken(name) || !HttpValue(value) {
    return HttpErrorKind.Malformed;
  }

  if HttpEqual(name, "host") {
    cell.hosts = cell.hosts + 1;
    if cell.hosts > 1 || !HttpHost(value) {
      return HttpErrorKind.Malformed;
    }
  } else if HttpEqual(name, "content-length") {
    if cell.has_length || value.length == 0 {
      return HttpErrorKind.InvalidFraming;
    }

    var length: uint64 = 0u64;
    var i: int32 = 0;
    while i < value.length {
      let ch: int32 = HttpChar(value, i);
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

    cell.has_length = true;
    cell.length = length;
  } else if HttpEqual(name, "transfer-encoding") {
    if cell.has_transfer {
      return HttpErrorKind.InvalidFraming;
    }

    cell.has_transfer = true;
    cell.transfer = value;
  } else if HttpEqual(name, "connection") {
    if !http_connection(cell, value) {
      return HttpErrorKind.Malformed;
    }
  }

  head.fields[head.field_count] = HttpField{name: name, value: value};
  head.field_count = head.field_count + 1;

  return nil;
}
