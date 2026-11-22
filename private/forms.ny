// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Owns strict URL-encoded field decoding and serialization under explicit bounds. */
module HttpFormCodec;
import "stdlib:stdlib.ny";
import "interface/forms.ni";
import "interface/http.ni";

readonly static kHttpFormHex: string = "0123456789ABCDEF";

pub struct HttpForm {}

method(HttpFormLimits) Normalized() -> HttpFormLimits? {
  let bytes = self.max_bytes == 0 ? 1048576 : self.max_bytes;
  let fields = self.max_fields == 0 ? 1024 : self.max_fields;
  if bytes < 1 || bytes > 16777216 || fields < 1 || fields > 65536 {
    return nil;
  }

  return HttpFormLimits{max_bytes: bytes, max_fields: fields};
}

static method(HttpForm) Hex(byte: int32) -> int32 {
  if byte >= 48 && byte <= 57 {
    return byte - 48;
  }

  if byte >= 65 && byte <= 70 {
    return byte - 55;
  }

  return byte >= 97 && byte <= 102 ? byte - 87 : -1;
}

static method(HttpForm) Decode(raw: ref string, offset: int32) -> Result<string, HttpError> {
  var decoded = StringBuffer.New();
  var index: int32 = 0;
  var start: int32 = 0;
  while index < raw.length {
    let byte = raw.ByteAt(index);
    if byte == 37 || byte == 43 {
      decoded.Append(raw.View(start, index - start));
      if byte == 37 {
        let high = HttpForm.Hex(raw.ByteAtOr(index + 1, -1));
        let low = HttpForm.Hex(raw.ByteAtOr(index + 2, -1));
        if high < 0 || low < 0 {
          return HttpError{kind: HttpErrorKind.Malformed, offset: (offset as int64) + (index as int64)};
        }

        decoded.Append(string.FromByte((high * 16 + low) as uint8));
        index += 3;
      } else {
        decoded.Append(" ");
        index += 1;
      }

      start = index;
    } else {
      index += 1;
    }
  }

  decoded.Append(raw.View(start, raw.length - start));
  let value = decoded.Take();
  if !Text.IsValidUtf8(value) {
    return HttpError{kind: HttpErrorKind.Malformed, offset: offset as int64};
  }

  return value;
}

pub static method(HttpForm) Parse(text: ref string, limits: ref HttpFormLimits) -> Result<Array<HttpField>, HttpError> {
  let normalized = limits.Normalized();
  if normalized == nil {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  let caps = normalized as HttpFormLimits;
  if text.length > caps.max_bytes {
    return HttpError{kind: HttpErrorKind.LimitExceeded};
  }

  var fields = Array<HttpField>.New();
  var index: int32 = 0;
  while index < text.length {
    let start = index;
    var equals: int32 = -1;
    while index < text.length && text.ByteAt(index) != 38 {
      if equals < 0 && text.ByteAt(index) == 61 {
        equals = index;
      }

      index += 1;
    }

    if index > start {
      if fields.Len() >= caps.max_fields {
        return HttpError{kind: HttpErrorKind.LimitExceeded, offset: start as int64};
      }

      let name_end = equals < 0 ? index : equals;
      let value_start = equals < 0 ? index : equals + 1;
      let name = HttpForm.Decode(text.View(start, name_end - start), start);
      if name.IsErr() {
        return name.get_if<HttpError>() as HttpError;
      }

      let value = HttpForm.Decode(text.View(value_start, index - value_start), value_start);
      if value.IsErr() {
        return value.get_if<HttpError>() as HttpError;
      }

      fields.Push(HttpField{name: name.get_if<string>() as string, value: value.get_if<string>() as string});
    }

    index += 1;
  }

  return move(fields);
}

pub static method(HttpForm) ParseQuery(target: ref string, limits: ref HttpFormLimits) -> Result<Array<HttpField>, HttpError> {
  if target.Contains("#") {
    return HttpError{kind: HttpErrorKind.Malformed};
  }

  let question = target.Find("?");
  let query = question < 0 ? "" : target.View(question + 1, target.length - question - 1);
  return HttpForm.Parse(query, limits);
}

static method(HttpForm) Append(output: ref mut StringBuffer, text: ref string, limit: int32) -> bool {
  var index: int32 = 0;
  while index < text.length {
    let byte = text.ByteAt(index);
    let plain = (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
      || (byte >= 48 && byte <= 57) || byte == 42 || byte == 45 || byte == 46 || byte == 95;
    let size = plain || byte == 32 ? 1 : 3;
    if output.Len() > limit - size {
      return false;
    }

    if plain {
      output.Append(text.View(index, 1));
    } else if byte == 32 {
      output.Append("+");
    } else {
      output.Append("%");
      output.Append(kHttpFormHex.View(byte / 16, 1));
      output.Append(kHttpFormHex.View(byte % 16, 1));
    }

    index += 1;
  }

  return true;
}

pub static method(HttpForm) Encode(fields: ref Array<HttpField>, limits: ref HttpFormLimits) -> Result<string, HttpError> {
  let normalized = limits.Normalized();
  if normalized == nil {
    return HttpError{kind: HttpErrorKind.InvalidArgument};
  }

  let caps = normalized as HttpFormLimits;
  if fields.Len() > caps.max_fields {
    return HttpError{kind: HttpErrorKind.LimitExceeded};
  }

  var output = StringBuffer.New();
  var index: int32 = 0;
  while index < fields.Len() {
    let field = fields.Get(index);
    if !Text.IsValidUtf8(field.name) || !Text.IsValidUtf8(field.value) {
      return HttpError{kind: HttpErrorKind.Malformed};
    }

    let separator = index > 0 ? 1 : 0;
    if output.Len() > caps.max_bytes - separator - 1 {
      return HttpError{kind: HttpErrorKind.LimitExceeded};
    }

    if index > 0 {
      output.Append("&");
    }

    if !HttpForm.Append(output, field.name, caps.max_bytes - 1) {
      return HttpError{kind: HttpErrorKind.LimitExceeded};
    }

    output.Append("=");
    if !HttpForm.Append(output, field.value, caps.max_bytes) {
      return HttpError{kind: HttpErrorKind.LimitExceeded};
    }

    index += 1;
  }

  return output.Take();
}
