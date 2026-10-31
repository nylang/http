// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

module HttpUrlDial;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/client.ni";
import "interface/url.ni";
import "interface/redirect.ni";
import "private/grammar.ny";
import "private/url.ny";
import "private/tcp_client.ny";

/** @brief DNS notifications and sequential TCP dial share the caller's original controls. */

static method(HttpClientError) FromUrlNetwork(error: NetError, stage: HttpClientStage) -> HttpClientError {
  return HttpClientError{transport_error: error, stage: stage};
}

// Keep DNS completion under the original controls. Cancellation does not imply
// that a running worker has released its slot.
method(HttpUrl) ResolveAddresses(
  resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions,
  options: ref NetOperationOptions,
  maximum: int32
) -> Result<NetResolvedAddresses, NetError> {
  var made: Result<NetEventLoop, NetError> = NetEventLoop.New(1);
  if made.IsErr() {
    return (made.get_if<NetError>()) as NetError;
  }

  var driver: NetEventLoop = move((made.get_if<NetEventLoop>()) as NetEventLoop);
  let queued: Result<AsyncFuture<NetResolution>, NetError> = resolver.ResolveAsync(
    self.Host(),
    self.Port(),
    dial.family,
    maximum,
    options
  );
  if queued.IsErr() {
    return (queued.get_if<NetError>()) as NetError;
  }

  let future: AsyncFuture<NetResolution> = (
    queued.get_if<AsyncFuture<NetResolution>>()
  ) as AsyncFuture<NetResolution>;
  while !future.is_completed {
    let polled: Result<int32, NetError> = resolver.Poll();
    if polled.IsErr() {
      return (polled.get_if<NetError>()) as NetError;
    }

    if future.is_completed {
      break;
    }

    let ready: Result<AsyncFuture<Result<Unit, NetError>>, NetError> = resolver.WhenReady(driver, options);
    if ready.IsErr() {
      return (ready.get_if<NetError>()) as NetError;
    }

    let notification: AsyncFuture<Result<Unit, NetError>> = (
      ready.get_if<AsyncFuture<Result<Unit, NetError>>>()
    ) as AsyncFuture<Result<Unit, NetError>>;
    while !notification.is_completed {
      let waited: Result<int32, NetError> = driver.Poll(-1);
      if waited.IsErr() {
        return (waited.get_if<NetError>()) as NetError;
      }
    }

    // Publish query cancellation/expiry before inspecting advisory readiness errors.
    let published: Result<int32, NetError> = resolver.Poll();
    if published.IsErr() {
      return (published.get_if<NetError>()) as NetError;
    }

    if future.is_completed {
      break;
    }

    let notified: Result<Result<Unit, NetError>, AsyncError> = notification.GetResult();
    if notified.IsErr() {
      return NetError{kind: NetErrorKind.System};
    }

    let result: Result<Unit, NetError> = (
      notified.get_if<Result<Unit, NetError>>()
    ) as Result<Unit, NetError>;
    if result.IsErr() {
      return (result.get_if<NetError>()) as NetError;
    }
  }

  let control: Result<Unit, NetError> = options.CheckNow();
  if control.IsErr() {
    return (control.get_if<NetError>()) as NetError;
  }

  let done: Result<NetResolution, AsyncError> = future.GetResult();
  if done.IsErr() {
    return NetError{kind: NetErrorKind.System};
  }

  let resolution: NetResolution = (done.get_if<NetResolution>()) as NetResolution;
  if resolution.error != nil {
    return resolution.error as NetError;
  }

  return resolution.addresses;
}

/**
 * @brief Resolve then connect under one original deadline/token using caller-owned DNS workers.
 * @returns Ok with TcpConnection on success; Err with HttpClientError on the failure paths
 *   described above.
 * @note Numeric IPs bypass DNS. A call-local event loop waits for resolver notifications on this
 *   caller thread. Failed endpoints are dropped before trying the next; return the last error with
 *   Resolve/Connect stage. Controls are checked before publication. No HTTP/TLS bytes are sent. A
 *   timed-out OS DNS job may retain a caller resolver slot until it finishes; no blocking resolver
 *   fallback.
 */
pub method(HttpUrl) Dial(
  resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions,
  options: ref NetOperationOptions
) -> Result<TcpConnection, HttpClientError> {
  let control: Result<Unit, NetError> = options.CheckNow();
  if control.IsErr() {
    return HttpClientError.FromUrlNetwork((control.get_if<NetError>()) as NetError, HttpClientStage.Resolve);
  }

  if !self.IsValid() {
    return HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}};
  }

  var maximum: int32 = dial.max_addresses;
  if maximum == 0 {
    maximum = 16;
  }

  if maximum < 1
    || maximum > 64
    || (dial.family != IpFamily.Unspecified && dial.family != IpFamily.V4 && dial.family != IpFamily.V6) {
    return HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}};
  }

  let parsed: Result<IpAddress, NetError> = IpAddress.Parse(self.Host());
  if parsed.IsOk() {
    let address: IpAddress = (parsed.get_if<IpAddress>()) as IpAddress;
    if dial.family != IpFamily.Unspecified && dial.family != address.Family() {
      return HttpClientError.FromUrlNetwork(NetError{kind: NetErrorKind.UnsupportedFamily}, HttpClientStage.Resolve);
    }

    let endpoint: NetEndpoint = (NetEndpoint.New(address, self.Port()).get_if<NetEndpoint>()) as NetEndpoint;
    var connected: Result<TcpConnection, NetError> = TcpConnection.Dial(endpoint, options);
    let checked: Result<Unit, NetError> = options.CheckNow();
    if checked.IsErr() {
      return HttpClientError.FromUrlNetwork((checked.get_if<NetError>()) as NetError, HttpClientStage.Connect);
    }

    if connected.IsErr() {
      return HttpClientError.FromUrlNetwork((connected.get_if<NetError>()) as NetError, HttpClientStage.Connect);
    }

    return move((connected.get_if<TcpConnection>()) as TcpConnection);
  }

  let resolved: Result<NetResolvedAddresses, NetError> = self.ResolveAddresses(resolver, dial, options, maximum);
  if resolved.IsErr() {
    let checked: Result<Unit, NetError> = options.CheckNow();
    if checked.IsErr() {
      return HttpClientError.FromUrlNetwork((checked.get_if<NetError>()) as NetError, HttpClientStage.Resolve);
    }

    return HttpClientError.FromUrlNetwork((resolved.get_if<NetError>()) as NetError, HttpClientStage.Resolve);
  }

  let addresses: NetResolvedAddresses = (resolved.get_if<NetResolvedAddresses>()) as NetResolvedAddresses;
  var last: NetError = NetError{kind: NetErrorKind.NameNotFound};
  var i: int32 = 0;
  while i < addresses.Len() {
    let checked: Result<Unit, NetError> = options.CheckNow();
    if checked.IsErr() {
      return HttpClientError.FromUrlNetwork((checked.get_if<NetError>()) as NetError, HttpClientStage.Connect);
    }

    let endpoint: NetEndpoint = (addresses.Get(i).get_if<NetEndpoint>()) as NetEndpoint;
    var connected: Result<TcpConnection, NetError> = TcpConnection.Dial(endpoint, options);
    if connected.IsOk() {
      var connection: TcpConnection = move((connected.get_if<TcpConnection>()) as TcpConnection);
      let final_control: Result<Unit, NetError> = options.CheckNow();
      if final_control.IsErr() {
        return HttpClientError.FromUrlNetwork((final_control.get_if<NetError>()) as NetError, HttpClientStage.Connect);
      }

      return move(connection);
    }

    last = (connected.get_if<NetError>()) as NetError;
    i = i + 1;
  }

  let final_control: Result<Unit, NetError> = options.CheckNow();
  if final_control.IsErr() {
    return HttpClientError.FromUrlNetwork((final_control.get_if<NetError>()) as NetError, HttpClientStage.Connect);
  }

  return HttpClientError.FromUrlNetwork(last, HttpClientStage.Connect);
}

/**
 * @brief Validate the complete buffered request, resolve/connect an http URL, then adopt into a
 *   client.
 * @returns Ok with HttpTcpClient on success; Err with HttpClientError on the failure paths
 *   described above.
 * @note Reject https before network I/O; use http_tls.HttpsClient.Open for HTTPS. The
 *   caller-owned resolver is borrowed only during this synchronous call. One original control
 *   budget covers resolution, sequential dial and all later Next calls. No redirect, proxy or
 *   connection reuse.
 */
pub static method(HttpTcpClient) Open(
  url: ref HttpUrl,
  verb: ref string,
  fields: ref <HttpField>[],
  body: ref NetBuffer,
  limits: ref HttpClientLimits,
  resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions,
  options: ref NetOperationOptions
) -> Result<HttpTcpClient, HttpClientError> {
  let control: Result<Unit, NetError> = options.CheckNow();
  if control.IsErr() {
    return HttpClientError.FromUrlNetwork((control.get_if<NetError>()) as NetError, HttpClientStage.Resolve);
  }

  if url.IsSecure() {
    return HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.Unsupported}};
  }

  let head: Result<NetBuffer, HttpError> = url.RequestHead(verb, fields, body.Len() as uint64);
  if head.IsErr() {
    return HttpClientError{protocol_error:(head.get_if<HttpError>()) as HttpError};
  }

  let wire: NetBuffer = (head.get_if<NetBuffer>()) as NetBuffer;
  var validated: Result<HttpClientExchange, HttpError> = HttpClientExchange.New(wire, body, limits);
  if validated.IsErr() {
    return HttpClientError{protocol_error:(validated.get_if<HttpError>()) as HttpError};
  }

  // Retire the validation cursor before dialing; New creates the sole retained exchange.
  validated = HttpError{kind: HttpErrorKind.Closed};
  var connected: Result<TcpConnection, HttpClientError> = url.Dial(resolver, dial, options);
  if connected.IsErr() {
    return (connected.get_if<HttpClientError>()) as HttpClientError;
  }

  var connection: TcpConnection = move((connected.get_if<TcpConnection>()) as TcpConnection);

  return HttpTcpClient.New(connection, wire, body, limits, options);
}

/**
 * @brief Validate a streamed request, then resolve/connect an http URL with the original
 *   controls.
 * @param continue_wait_ms Finite 0..60000 ms fallback after the complete head is sent.
 * @returns Ok with HttpTcpClient on success; Err with HttpClientError on the failure paths
 *   described above.
 * @note Request/limits/continue policy fail before DNS. HTTPS is rejected. The resolver is
 *   borrowed only during OpenStreaming. Next returns NeedBody for SupplyBody/FinishBody; producer
 *   time consumes the original deadline. No replay, redirects, retries or connection reuse.
 */
pub static method(HttpTcpClient) OpenStreaming(
  url: ref HttpUrl,
  verb: ref string,
  fields: ref <HttpField>[],
  plan: ref HttpBodyPlan,
  limits: ref HttpClientLimits,
  resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions,
  options: ref NetOperationOptions,
  continue_wait_ms: int32
) -> Result<HttpTcpClient, HttpClientError> {
  let control: Result<Unit, NetError> = options.CheckNow();
  if control.IsErr() {
    return HttpClientError.FromUrlNetwork((control.get_if<NetError>()) as NetError, HttpClientStage.Resolve);
  }

  if url.IsSecure() {
    return HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.Unsupported}};
  }

  if continue_wait_ms < 0 || continue_wait_ms > 60000 {
    return HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}};
  }

  let head: Result<NetBuffer, HttpError> = url.StreamingRequestHead(verb, fields, plan);
  if head.IsErr() {
    return HttpClientError{protocol_error:(head.get_if<HttpError>()) as HttpError};
  }

  let wire: NetBuffer = (head.get_if<NetBuffer>()) as NetBuffer;
  var validated: Result<HttpClientExchange, HttpError> = HttpClientExchange.NewStreaming(wire, limits);
  if validated.IsErr() {
    return HttpClientError{protocol_error:(validated.get_if<HttpError>()) as HttpError};
  }

  validated = HttpError{kind: HttpErrorKind.Closed};
  var connected: Result<TcpConnection, HttpClientError> = url.Dial(resolver, dial, options);
  if connected.IsErr() {
    return (connected.get_if<HttpClientError>()) as HttpClientError;
  }

  var connection: TcpConnection = move((connected.get_if<TcpConnection>()) as TcpConnection);

  return HttpTcpClient.NewStreaming(connection, wire, limits, options, continue_wait_ms);
}
