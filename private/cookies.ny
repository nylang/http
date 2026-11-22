// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Owns validated Cookie pairs and response attribute serialization. */
module HttpCookieCodec;
import "stdlib:stdlib.ny";
import "interface/http.ni";
import "interface/cookies.ni";
import "private/grammar.ny";

pub struct HttpCookie {}

static method(HttpCookie) IsValue(value: ref string) -> bool {
  var index: int32 = 0;
  while index < value.length {
    let byte = value.ByteAt(index);
    if byte < 33 || byte > 126 || byte == 34 || byte == 44 || byte == 59 || byte == 92 {
      return false;
    }

    index += 1;
  }

  return true;
}

pub static method(HttpCookie) Parse(text: ref string, limits: ref HttpHeadLimits) -> Result<Array<HttpField>, HttpError> {
  let bytes = limits.max_head_bytes == 0 ? 32768 : limits.max_head_bytes;
  let pairs = limits.max_fields == 0 ? 100 : limits.max_fields;
  if bytes < 1 || bytes > 1048576 || pairs < 1 || pairs > 128 {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  if text.length > bytes {
    return HttpError{kind: HttpErrorKind.LimitExceeded};
  }

  if text.length == 0 {
    return HttpError{kind: HttpErrorKind.Malformed};
  }

  var fields = Array<HttpField>.New();
  var index: int32 = 0;
  while index < text.length {
    let start = index;
    while index < text.length && text.ByteAt(index) != 59 {
      index += 1;
    }

    let pair = HttpLexeme.New(text.View(start, index - start)).TrimWhitespace();
    let equals = pair.Find("=");
    if equals <= 0 {
      return HttpError{kind: HttpErrorKind.Malformed, offset: start as int64};
    }

    let name = pair.View(0, equals);
    var value = pair.View(equals + 1, pair.length - equals - 1);
    if value.StartsWith("\"") && value.EndsWith("\"") && value.length >= 2 {
      value = value.View(1, value.length - 2);
    }

    if !HttpLexeme.New(name).IsToken() || !HttpCookie.IsValue(value) {
      return HttpError{kind: HttpErrorKind.Malformed, offset: start as int64};
    }

    if fields.Len() >= pairs {
      return HttpError{kind: HttpErrorKind.LimitExceeded, offset: start as int64};
    }

    fields.Push(HttpField{name: copy(name), value: copy(value)});
    index += 1;
    if index == text.length {
      return HttpError{kind: HttpErrorKind.Malformed, offset: index as int64};
    }
  }

  return move(fields);
}

pub static method(HttpCookie) Encode(fields: ref Array<HttpField>) -> Result<HttpField, HttpError> {
  if fields.Len() == 0 {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  if fields.Len() > 128 {
    return HttpError{kind: HttpErrorKind.LimitExceeded};
  }

  var output = StringBuffer.New();
  var index: int32 = 0;
  while index < fields.Len() {
    let field = fields.Get(index);
    if !HttpLexeme.New(field.name).IsToken() || !HttpCookie.IsValue(field.value) {
      return HttpError{kind: HttpErrorKind.InvalidArgument};
    }

    let additional = (field.name.length as int64) + (field.value.length as int64) + (index > 0 ? 3i64 : 1i64);
    if (output.Len() as int64) + additional > 32768i64 {
      return HttpError{kind: HttpErrorKind.LimitExceeded};
    }

    if index > 0 {
      output.Append("; ");
    }

    output.Append(field.name);
    output.Append("=");
    output.Append(field.value);
    index += 1;
  }

  return HttpField{name: "Cookie", value: output.Take()};
}

static method(HttpCookie) IsDomain(domain: ref string) -> bool {
  var index: int32 = domain.StartsWith(".") ? 1 : 0;
  var label: int32 = 0;
  while index < domain.length {
    let byte = domain.ByteAt(index);
    if byte == 46 {
      if label == 0 || domain.ByteAt(index - 1) == 45 {
        return false;
      }

      label = 0;
    } else {
      let alphanumeric = (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) || (byte >= 48 && byte <= 57);
      if (!alphanumeric && byte != 45) || (label == 0 && byte == 45) {
        return false;
      }

      label += 1;
      if label > 63 {
        return false;
      }
    }

    index += 1;
  }

  return label > 0 && domain.ByteAt(domain.length - 1) != 45 && domain.length <= 254;
}

pub static method(HttpCookie) Set(cookie: ref HttpField, settings: ref HttpCookieSettings) -> Result<HttpField, HttpError> {
  if !HttpLexeme.New(cookie.name).IsToken() || !HttpCookie.IsValue(cookie.value) {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  if settings.same_site == HttpSameSite.None && !settings.secure {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  if (cookie.name.StartsWith("__Secure-") || cookie.name.StartsWith("__Host-")) && !settings.secure {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  if cookie.name.StartsWith("__Host-") && (settings.domain.length > 0 || settings.path != "/") {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  if settings.domain.length > 0 && !HttpCookie.IsDomain(settings.domain) {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  var index: int32 = 0;
  while index < settings.path.length {
    let byte = settings.path.ByteAt(index);
    if byte < 32 || byte > 126 || byte == 59 {
      return HttpError{kind: HttpErrorKind.InvalidArgument};
    }

    index += 1;
  }

  if settings.path.length > 0 && !settings.path.StartsWith("/") {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  if (cookie.name.length as int64) + (cookie.value.length as int64)
      + (settings.path.length as int64) + (settings.domain.length as int64) > 32000i64 {
    return HttpError{kind: HttpErrorKind.LimitExceeded};
  }

  var output = StringBuffer.New();
  output.Append(cookie.name);
  output.Append("=");
  output.Append(cookie.value);
  if settings.domain.length > 0 {
    output.Append("; Domain=");
    output.Append(settings.domain);
  }

  if settings.path.length > 0 {
    output.Append("; Path=");
    output.Append(settings.path);
  }

  if settings.max_age != nil {
    let age = settings.max_age as int64;
    output.Append("; Max-Age=");
    output.Append(age <= 0i64 ? "0" : age.ToString());
  }

  if settings.secure {
    output.Append("; Secure");
  }

  if settings.http_only {
    output.Append("; HttpOnly");
  }

  if settings.same_site != HttpSameSite.Unspecified {
    output.Append("; SameSite=");
    output.Append(settings.same_site == HttpSameSite.Strict ? "Strict" :
      (settings.same_site == HttpSameSite.Lax ? "Lax" : "None"));
  }

  return HttpField{name: "Set-Cookie", value: output.Take()};
}
