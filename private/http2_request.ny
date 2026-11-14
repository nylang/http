// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of Http2ClientProtocol;

pub method(Http2Client) Submit(
  url: ref HttpUrl, verb: ref string, fields: ref <HttpField>[], body: ref ByteBuffer
) -> Result<int32, Http2Error> {
  let cell = self.cell;
  if cell == nil {
    return Http2Error{kind: Http2ErrorKind.Closed};
  }

  let state = cell as arc<Http2State>;
  if !url.IsValid() || state.origin.HostField() != url.HostField() || state.origin.Scheme() != url.Scheme() ||
      verb == "CONNECT" || !HttpLexeme.New(verb).IsToken() || fields.length > 123 {
    return Http2Error{kind: Http2ErrorKind.InvalidArgument};
  }

  // Keep every field owner live until nghttp2 has copied its bytes.
  var headers: <HttpField>[128] = <HttpField>[128]{};
  headers[0] = HttpField{name: ":method", value: copy(verb)};
  headers[1] = HttpField{name: ":scheme", value: url.Scheme()};
  headers[2] = HttpField{name: ":authority", value: url.HostField()};
  headers[3] = HttpField{name: ":path", value: url.Target()};
  headers[4] = HttpField{name: "content-length", value: body.Len().ToString()};
  var i: int32 = 0;
  while i < fields.length {
    let source = fields[i];
    if !HttpLexeme.New(source.name).IsToken() || !HttpLexeme.New(source.value).IsFieldValue() ||
        source.name.length > 32768 || source.value.length > 32768 {
      return Http2Error{kind: Http2ErrorKind.InvalidArgument};
    }

    let name = source.name.ToLowerAscii();
    if name == "host" || name == "content-length" || name == "connection" || name == "upgrade" ||
        name == "transfer-encoding" || name == "keep-alive" || name == "proxy-connection" ||
        name == "expect" || (name == "te" && source.value != "trailers") {
      return Http2Error{kind: Http2ErrorKind.InvalidArgument};
    }

    headers[i + 5] = HttpField{name: name, value: source.value};
    i += 1;
  }

  let count = i + 5;
  var native: <Http2NativeField>[128] = <Http2NativeField>[128]{};
  i = 0;
  while i < count {
    native[i] = Http2NativeField{
      name: headers[i].name.data as *const uint8, value: headers[i].value.data as *const uint8,
      name_size: headers[i].name.length, value_size: headers[i].value.length
    };
    i += 1;
  }

  var id: int32 = 0;
  var detail: int32 = 0;
  let status = state.provider.api.submit(state.handle, &native[0], count, body.Data(), body.Len(), &mut id, &mut detail);
  if status == 0 {
    return id;
  }
  if status == 2 {
    return Http2Error{kind: Http2ErrorKind.LimitExceeded};
  }
  if status == 3 {
    return Http2Error{kind: Http2ErrorKind.ResourceExhausted, code: detail};
  }
  if status == 4 {
    return Http2Error{kind: Http2ErrorKind.Busy};
  }

  return Http2Error{kind: Http2ErrorKind.Protocol, code: detail};
}
