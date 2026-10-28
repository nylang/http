/** @brief Strict line syntax and unambiguous HTTP/1.x framing decisions. */
part of HttpProtocol;

func http_char(text: ref string, index: int32) -> int32 { return (text[index] as uint8) as int32; }
func http_tchar(ch: int32) -> bool {
  if (ch >= 48 && ch <= 57) || (ch >= 65 && ch <= 90) || (ch >= 97 && ch <= 122) { return true; }
  let punctuation: string = "!#$%&'*+-.^_`|~";
  var i: int32 = 0; while i < punctuation.length { if http_char(punctuation, i) == ch { return true; } i = i + 1; }
  return false;
}
func http_token(text: ref string) -> bool {
  if text.length == 0 { return false; }
  var i: int32 = 0; while i < text.length { if !http_tchar(http_char(text, i)) { return false; } i = i + 1; }
  return true;
}
func http_value(text: ref string) -> bool {
  var i: int32 = 0;
  while i < text.length { let ch: int32 = http_char(text, i); if (ch < 32 && ch != 9) || ch == 127 { return false; } i = i + 1; }
  return true;
}
func http_equal(left: ref string, right: ref string) -> bool {
  if left.length != right.length { return false; }
  var i: int32 = 0;
  while i < left.length {
    var a: int32 = http_char(left, i); var b: int32 = http_char(right, i);
    if a >= 65 && a <= 90 { a = a + 32; } if b >= 65 && b <= 90 { b = b + 32; }
    if a != b { return false; } i = i + 1;
  }
  return true;
}
func http_trim(text: ref string) -> string {
  var begin: int32 = 0; var end: int32 = text.length;
  while begin < end && (text[begin] == ' ' || text[begin] == '\t') { begin = begin + 1; }
  while end > begin && (text[end-1] == ' ' || text[end-1] == '\t') { end = end - 1; }
  return text.Substring(begin, end-begin);
}
func http_version(text: ref string) -> int32 {
  if text.Equal("HTTP/1.0") { return 0; } if text.Equal("HTTP/1.1") { return 1; } return -1;
}
func http_hex(ch: int32) -> bool { return (ch >= 48 && ch <= 57) || (ch >= 65 && ch <= 70) || (ch >= 97 && ch <= 102); }
func http_target(verb: ref string, target: ref string) -> bool {
  if target.Equal("*") { return verb.Equal("OPTIONS"); }
  if target.length == 0 || target[0] != '/' { return false; }
  var i: int32 = 0;
  while i < target.length {
    let ch: int32 = http_char(target, i);
    if ch <= 32 || ch >= 127 || ch == 35 || ch == 92 { return false; }
    if ch == 37 {
      if target.length-i < 3 || !http_hex(http_char(target, i+1)) || !http_hex(http_char(target, i+2)) { return false; }
      i = i + 2;
    }
    i = i + 1;
  }
  return true;
}
func http_host(text: ref string) -> bool {
  if text.length == 0 { return false; }
  var end: int32 = 0;
  if text[0] == '[' {
    end = 1; while end < text.length && text[end] != ']' { end = end + 1; }
    if end == text.length { return false; }
    let literal: string = text.Substring(1, end-1);
    if literal.Find("%") >= 0 { return false; }
    let parsed: Result<IpAddress, NetError> = IpAddress.Parse(literal);
    if parsed.IsErr() { return false; }
    if ((parsed.get_if<IpAddress>()) as IpAddress).Family() != IpFamily.V6 { return false; }
    end = end + 1;
  } else {
    while end < text.length && text[end] != ':' {
      let ch: int32 = http_char(text, end);
      if !((ch >= 48 && ch <= 57) || (ch >= 65 && ch <= 90) || (ch >= 97 && ch <= 122) || ch == 45 || ch == 46 || ch == 95 || ch == 126) { return false; }
      end = end + 1;
    }
    if end == 0 { return false; }
  }
  if end == text.length { return true; }
  if text[end] != ':' || end+1 == text.length { return false; }
  var port: uint32 = 0u32; end = end + 1;
  while end < text.length {
    let ch: int32 = http_char(text, end); if ch < 48 || ch > 57 { return false; }
    port = port*10u32+(ch-48) as uint32; if port > 65535u32 { return false; } end = end + 1;
  }
  return true;
}
func http_start(state: arc<HttpParserData>, text: ref string) -> HttpErrorKind? {
  var cell: arc<HttpParserData> = state; var head: arc<HttpHeadData> = cell.head;
  if head.response {
    if text.length < 13 || text[8] != ' ' || text[12] != ' ' { return HttpErrorKind.Malformed; }
    head.minor = http_version(text.Substring(0, 8));
    if head.minor < 0 { return HttpErrorKind.Unsupported; }
    var status: int32 = 0; var i: int32 = 9;
    while i < 12 { let ch: int32 = http_char(text, i); if ch < 48 || ch > 57 { return HttpErrorKind.Malformed; } status = status*10+ch-48; i = i+1; }
    if status < 100 || status > 599 { return HttpErrorKind.Malformed; }
    let reason: string = text.Substring(13, text.length-13);
    if !http_value(reason) { return HttpErrorKind.Malformed; }
    head.status = status; head.reason = reason;
  } else {
    let first: int32 = text.Find(" "); if first < 1 { return HttpErrorKind.Malformed; }
    let tail: string = text.Substring(first+1, text.length-first-1);
    let second: int32 = tail.Find(" "); if second < 1 { return HttpErrorKind.Malformed; }
    let verb: string = text.Substring(0, first); let target: string = tail.Substring(0, second);
    if !http_token(verb) { return HttpErrorKind.Malformed; }
    if !http_target(verb, target) { return HttpErrorKind.Unsupported; }
    head.minor = http_version(tail.Substring(second+1, tail.length-second-1));
    if head.minor < 0 { return HttpErrorKind.Unsupported; }
    head.verb = verb; head.target = target;
  }
  cell.started = true; return nil;
}
func http_connection(state: arc<HttpParserData>, text: ref string) -> bool {
  var cell: arc<HttpParserData> = state; var begin: int32 = 0;
  while begin < text.length {
    var end: int32 = begin; while end < text.length && text[end] != ',' { end = end+1; }
    let token: string = http_trim(text.Substring(begin, end-begin)); if !http_token(token) { return false; }
    if http_equal(token, "close") { cell.close = true; }
    if http_equal(token, "keep-alive") { cell.keep_alive = true; }
    if end == text.length { return true; } begin = end+1;
  }
  return false;
}
func http_finish(state: arc<HttpParserData>) -> HttpErrorKind? {
  var cell: arc<HttpParserData> = state; var head: arc<HttpHeadData> = cell.head;
  if !head.response && head.minor == 1 && cell.hosts != 1 { return HttpErrorKind.Malformed; }
  if cell.has_length && cell.has_transfer { return HttpErrorKind.InvalidFraming; }
  if cell.has_transfer && head.minor == 0 { return HttpErrorKind.InvalidFraming; }
  if cell.has_transfer && !http_equal(cell.transfer, "chunked") { return HttpErrorKind.Unsupported; }
  var plan: HttpBodyPlan = HttpBodyPlan{close_connection: cell.close || (head.minor == 0 && !cell.keep_alive)};
  if head.response && ((head.status >= 100 && head.status < 200) || head.status == 204) {
    if cell.has_length || cell.has_transfer { return HttpErrorKind.InvalidFraming; }
    if head.status == 101 { plan.kind = HttpBodyKind.Upgrade; }
  } else if head.response && cell.request_method.Equal("CONNECT") && head.status >= 200 && head.status < 300 {
    if cell.has_length || cell.has_transfer { return HttpErrorKind.InvalidFraming; }
    plan.kind = HttpBodyKind.Tunnel;
  } else if head.response && (cell.request_method.Equal("HEAD") || head.status == 304) { plan.kind = HttpBodyKind.None; }
  else if cell.has_transfer { plan.kind = HttpBodyKind.Chunked; }
  else if cell.has_length { plan.kind = HttpBodyKind.ContentLength; plan.length = cell.length; }
  else if head.response { plan.kind = HttpBodyKind.UntilEof; plan.close_connection = true; }
  head.plan = plan; cell.complete = true; return nil;
}
func http_line(state: arc<HttpParserData>, text: ref string) -> HttpErrorKind? {
  var cell: arc<HttpParserData> = state; var head: arc<HttpHeadData> = cell.head;
  if !cell.started { return http_start(cell, text); }
  if text.length == 0 { return http_finish(cell); }
  if head.field_count >= cell.limits.max_fields { return HttpErrorKind.LimitExceeded; }
  let colon: int32 = text.Find(":"); if colon < 1 { return HttpErrorKind.Malformed; }
  let name: string = text.Substring(0, colon); let value: string = http_trim(text.Substring(colon+1, text.length-colon-1));
  if !http_token(name) || !http_value(value) { return HttpErrorKind.Malformed; }
  if http_equal(name, "host") {
    cell.hosts = cell.hosts+1; if cell.hosts > 1 || !http_host(value) { return HttpErrorKind.Malformed; }
  } else if http_equal(name, "content-length") {
    if cell.has_length || value.length == 0 { return HttpErrorKind.InvalidFraming; }
    var length: uint64 = 0u64; var i: int32 = 0;
    while i < value.length {
      let ch: int32 = http_char(value, i); if ch < 48 || ch > 57 { return HttpErrorKind.InvalidFraming; }
      let digit: uint64 = (ch-48) as uint64;
      if length > (18446744073709551615u64-digit)/10u64 { return HttpErrorKind.InvalidFraming; }
      length = length*10u64+digit; i = i+1;
    }
    cell.has_length = true; cell.length = length;
  } else if http_equal(name, "transfer-encoding") {
    if cell.has_transfer { return HttpErrorKind.InvalidFraming; } cell.has_transfer = true; cell.transfer = value;
  } else if http_equal(name, "connection") { if !http_connection(cell, value) { return HttpErrorKind.Malformed; } }
  head.fields[head.field_count] = HttpField{name: name, value: value}; head.field_count = head.field_count+1;
  return nil;
}
