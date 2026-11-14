// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Owns one HTTP/2 client connection and drives the provider over borrowed I/O. */
module Http2ClientProtocol;
part "http2_request.ny";
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http2.ni";
import "interface/http.ni";
import "interface/url.ni";
import "private/grammar.ny";
import "private/url.ny";
import "private/http2_provider.ny";

struct Http2State {
  handle: *mut int8;
  provider: Http2Provider;
  transport: Http2Transport;
  origin: HttpUrl;
}

/** @brief Owns the native session and transport. */
pub struct Http2Client {
  cell: arc<Http2State>?;
}

pub method(Http2Limits) IsValid() -> bool {
  return self.max_streams >= 0 && self.max_streams <= 16 &&
    self.max_body_bytes >= 0 && self.max_body_bytes <= 16777216;
}

pub static method(Http2Client) Adopt(
  transport: Http2Transport, url: ref HttpUrl, provider_file: ref string, limits: ref Http2Limits
) -> Result<Http2Client, Http2Error> {
  if !limits.IsValid() || !url.IsValid() || provider_file.length == 0 {
    transport.Abort();
    return Http2Error{kind: Http2ErrorKind.InvalidArgument};
  }

  var loaded = Http2Provider.Load(provider_file);
  if loaded.IsErr() {
    transport.Abort();
    return loaded.get_if<Http2Error>() as Http2Error;
  }

  var provider = move(loaded.get_if<Http2Provider>() as Http2Provider);
  let slots: int32 = limits.max_streams == 0 ? 8 : limits.max_streams;
  let budget: int32 = limits.max_body_bytes == 0 ? 8388608 : limits.max_body_bytes;
  let native = provider.api.create_session(slots, budget);
  if native == nil {
    transport.Abort();
    return Http2Error{kind: Http2ErrorKind.ResourceExhausted};
  }

  return Http2Client{
    cell: new arc<Http2State>{handle: native, provider: move(provider), transport: transport, origin: url}
  };
}

pub method(Http2Client) operator move() -> Http2Client {
  let cell = self.cell;
  self.cell = nil;

  return Http2Client{cell: cell};
}

pub method(Http2Client) operator drop() -> void {
  self.Close();
}

pub method(Http2Client) Close() -> void {
  let cell = self.cell;
  self.cell = nil;
  if cell != nil {
    var state = cell as arc<Http2State>;
    state.transport.Abort();
    state.provider.api.drop_session(state.handle);
  }
}

pub method(Http2Client) Receive(
  stream_id: int32, options: ref NetOperationOptions
) -> Result<Http2Response, Http2Error> {
  let cell = self.cell;
  if cell == nil {
    return Http2Error{kind: Http2ErrorKind.Closed};
  }

  var state = cell as arc<Http2State>;
  var response = Http2Reply{};
  if !response.Inspect(state.provider.api, state.handle, stream_id) {
    return Http2Error{kind: Http2ErrorKind.InvalidArgument};
  }

  while true {
    let flushed = state.Flush(options);
    if flushed.IsErr() {
      self.Close();
      return flushed.get_if<Http2Error>() as Http2Error;
    }

    response.Inspect(state.provider.api, state.handle, stream_id);
    if response.phase != 0 {
      let done = response.CopyResult(state.provider.api, state.handle, stream_id);
      state.provider.api.release_stream(state.handle, stream_id);
      return done;
    }
    if state.provider.api.wants_input(state.handle) == 0 {
      self.Close();
      return Http2Error{kind: Http2ErrorKind.Protocol};
    }

    let fed = state.Fill(options);
    if fed.IsErr() {
      self.Close();
      return fed.get_if<Http2Error>() as Http2Error;
    }
  }

  return Http2Error{kind: Http2ErrorKind.Protocol};
}

method(Http2State) Flush(options: ref NetOperationOptions) -> Result<Unit, Http2Error> {
  let control = options.Check(Instant.Now().ToDurationSinceEpochish().ToNanoseconds());
  if control.IsErr() {
    return Http2Error{kind: Http2ErrorKind.Network, network: control.get_if<NetError>()};
  }

  while true {
    var data: *const uint8 = nil;
    let size = self.provider.api.output(self.handle, &mut data);
    if size < 0ip {
      return Http2Error{kind: Http2ErrorKind.Protocol, code: size as int32};
    }
    if size == 0ip {
      return UnitValue();
    }

    let bytes = NetBytes.FromRaw(data, size).get_if<NetBytes>() as NetBytes;
    let written = self.transport.WriteAll(bytes, options);
    if written.IsErr() {
      return written;
    }
  }

  return UnitValue();
}

method(Http2State) Fill(options: ref NetOperationOptions) -> Result<Unit, Http2Error> {
  var bytes: <uint8>[16384] = <uint8>[16384]{};
  let buffer = NetMutableBytes.FromRaw(&mut bytes[0], 16384ip).get_if<NetMutableBytes>() as NetMutableBytes;
  let received = self.transport.Read(buffer, options);
  if received.IsErr() {
    return received.get_if<Http2Error>() as Http2Error;
  }

  let size = received.get_if<intptr>() as intptr;
  if size == 0ip {
    return Http2Error{kind: Http2ErrorKind.UnexpectedEof};
  }

  if size < 0ip || size > buffer.Len() {
    return Http2Error{kind: Http2ErrorKind.Protocol};
  }

  let fed = self.provider.api.input(self.handle, &bytes[0], size);
  if fed != size {
    return Http2Error{kind: Http2ErrorKind.Protocol, code: fed as int32};
  }

  return UnitValue();
}

struct Http2Reply {
  phase: int32;
  status: int32;
  code: int32;
  fields: int32;
  body: *const uint8;
  size: int32;
}

method(Http2Reply) Inspect(api: ref Http2ProviderApi, handle: *mut int8, id: int32) -> bool {
  return api.stream(
    handle, id, &mut self.phase, &mut self.status, &mut self.code,
    &mut self.fields, &mut self.body, &mut self.size
  ) == 0;
}

method(Http2Reply) CopyResult(api: ref Http2ProviderApi, handle: *mut int8, id: int32) -> Result<Http2Response, Http2Error> {
  if self.phase == 3 {
    return Http2Error{kind: Http2ErrorKind.LimitExceeded};
  }
  if self.phase != 1 {
    return Http2Error{kind: Http2ErrorKind.StreamReset, code: self.code};
  }

  var body = ByteBuffer.New();
  if body.Write(self.body, self.size as intptr).IsErr() {
    return Http2Error{kind: Http2ErrorKind.ResourceExhausted};
  }

  var fields = Array<HttpField>.New();
  var trailers = Array<HttpField>.New();
  var i: int32 = 0;
  while i < self.fields {
    var native = Http2NativeField{};
    let kind = api.field(handle, id, i, &mut native);
    if kind < 0 {
      return Http2Error{kind: Http2ErrorKind.Protocol};
    }

    let field = HttpField{
      name: copy(string.ViewFrom(native.name as *const int8, native.name_size)),
      value: copy(string.ViewFrom(native.value as *const int8, native.value_size))
    };
    if kind == 0 {
      fields.Push(field);
    } else {
      trailers.Push(field);
    }
    i += 1;
  }

  return Http2Response{status: self.status, fields: fields, trailers: trailers, body: body};
}
