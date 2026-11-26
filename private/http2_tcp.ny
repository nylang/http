// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Adapts net_core TCP to the HTTP/2 connection owner. */
module Http2TcpAdapter;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http2.ni";
import "interface/client.ni";
import "interface/url.ni";
import "private/url.ny";
import "private/url_dial.ny";

struct Http2Tcp implements Http2Transport {
  connection: TcpConnection;
}

@override
method(Http2Tcp) Read(buffer: ref NetMutableBytes, options: ref NetOperationOptions) -> Result<intptr, Http2Error> {
  let result = self.connection.Read(buffer, options);
  if result.IsErr() {
    return Http2Error{kind: Http2ErrorKind.Network, network: result.get_if<NetError>()};
  }

  return result.get_if<intptr>() as intptr;
}

@override
method(Http2Tcp) WriteAll(buffer: ref NetBytes, options: ref NetOperationOptions) -> Result<Unit, Http2Error> {
  var offset: intptr = 0;
  while offset < buffer.Len() {
    let rest = buffer.Slice(offset, buffer.Len() - offset).get_if<NetBytes>() as NetBytes;
    let result = self.connection.Write(rest, options);
    if result.IsErr() {
      return Http2Error{kind: Http2ErrorKind.Network, network: result.get_if<NetError>()};
    }

    let count = result.get_if<intptr>() as intptr;
    if count <= 0ip {
      return Http2Error{kind: Http2ErrorKind.UnexpectedEof};
    }
    offset += count;
  }

  return UnitValue();
}

@override
method(Http2Tcp) Abort() -> void {
  self.connection.Close();
}

/** @brief Dial a cleartext HTTP/2 connection and load the native provider.
 * @returns An owned client or an argument, network or provider error.
 */
pub static method(Http2Client) Open(
  url: ref HttpUrl, provider_file: ref string, resolver: ref mut AsyncResolver, dial: ref HttpDialOptions,
  limits: ref Http2Limits, options: ref NetOperationOptions
) -> Result<Http2Client, Http2Error> {
  if !limits.IsValid() || !url.IsValid() || url.IsSecure() || provider_file.length == 0 {
    return Http2Error{kind: Http2ErrorKind.InvalidArgument};
  }

  var dialed = url.Dial(resolver, dial, options);
  if dialed.IsErr() {
    let failure = dialed.get_if<HttpClientError>() as HttpClientError;
    return Http2Error{kind: Http2ErrorKind.Network, network: failure.transport_error};
  }

  var adapter = Http2Tcp{connection: move(dialed.get_if<TcpConnection>() as TcpConnection)};
  let delay = adapter.connection.SetNoDelay(true);
  if delay.IsErr() {
    return Http2Error{kind: Http2ErrorKind.Network, network: delay.get_if<NetError>()};
  }

  return Http2Client.Adopt(move(adapter), url, provider_file, limits);
}
