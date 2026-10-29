// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

module HttpTcpAdapter;
part "tcp_upload.ny";
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/client.ni";
import "interface/url.ni";
import "interface/redirect.ni";
import "private/grammar.ny";
import "private/exchange.ny";

/** @brief Connected TCP adapter for the shared pull exchange. */

struct HttpTcpData {
  connection: TcpConnection;
  exchange: HttpClientExchange;
  options: NetOperationOptions;
  failure: HttpClientError?;
  published_complete: bool;
  streaming: bool;
  continue_wait_ms: int32;
  continue_started: bool;
  continue_deadline: NetDeadline;
  incoming: <uint8>[16384];
}

/**
 * @brief Single-threaded, move-only connected TCP client for one request; no hidden workers or
 *   reuse.
 */
pub struct HttpTcpClient {
  cell: arc<HttpTcpData>?;
}

func http_tcp_protocol(s: arc<HttpTcpData>, error: HttpError) -> HttpClientError {
  return HttpClientError{protocol_error: error, stage: s.exchange.Stage(), stats: s.exchange.Stats()};
}

func http_tcp_network(s: arc<HttpTcpData>, error: NetError) -> HttpClientError {
  return HttpClientError{transport_error: error, stage: s.exchange.Stage(), stats: s.exchange.Stats()};
}

func http_tcp_fail(state: arc<HttpTcpData>, error: HttpClientError) -> HttpClientError {
  var s: arc<HttpTcpData> = state;
  let ignored: Result<Unit, NetError> = s.connection.Close();
  s.failure = error;
  s.exchange = HttpClientExchange{};

  return error;
}

/**
 * @brief Validate first, then adopt connection on success; failures leave it untouched.
 * @returns Ok with HttpTcpClient on success; Err with HttpClientError on the failure paths
 *   described above.
 * @note One copied absolute deadline/shared cancellation covers every Next call. Dial/DNS are
 *   outside this connected API; pass the original dial options to retain the same overall budget.
 */
pub static method(HttpTcpClient) New(
  connection: ref mut TcpConnection,
  head: ref NetBuffer,
  body: ref NetBuffer,
  limits: ref HttpClientLimits,
  options: ref NetOperationOptions
) -> Result<HttpTcpClient, HttpClientError> {
  let control: Result<Unit, NetError> = options.Check(NetClock.NowNanoseconds());
  if control.IsErr() {
    return HttpClientError{transport_error:(control.get_if<NetError>()) as NetError};
  }

  if !connection.IsOpen() {
    return HttpClientError{transport_error: NetError{kind: NetErrorKind.Closed}};
  }

  var made: Result<HttpClientExchange, HttpError> = HttpClientExchange.New(head, body, limits);
  if made.IsErr() {
    return HttpClientError{protocol_error:(made.get_if<HttpError>()) as HttpError};
  }

  return HttpTcpClient{cell: new arc<HttpTcpData>{
    connection: move(connection),
    exchange: move((made.get_if<HttpClientExchange>()) as HttpClientExchange),
    options: options
  }};
}

/**
 * @brief Transfer the owned connection and exchange.
 * @returns The HttpTcpClient value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpTcpClient) operator move() -> HttpTcpClient {
  let cell: arc<HttpTcpData>? = self.cell;
  self.cell = nil;

  return HttpTcpClient{cell: cell};
}

/** @brief Close the retained connection and release cursor state. */
pub method(HttpTcpClient) operator drop() -> void {
  self.Close();
  self.cell = nil;
}

/**
 * @brief Drive one caller-thread exchange event; streamed clients may return NeedBody.
 * @returns Ok with HttpClientEvent on success; Err with HttpClientError on the failure paths
 *   described above.
 * @note Immutable clients upload before reading. Streamed clients check early responses between
 *   writes.
 * @note Errors retire the connection and preserve committed counts. Successful completion is
 *   durable; later Next returns Complete without I/O until explicit Close. Close/drop after
 *   completion; the socket is not pooled.
 */
pub method(HttpTcpClient) Next() -> Result<HttpClientEvent, HttpClientError> {
  if self.cell == nil {
    return HttpClientError{protocol_error: HttpMakeError(HttpErrorKind.Closed)};
  }

  var s: arc<HttpTcpData> = self.cell as arc<HttpTcpData>;
  if s.failure != nil {
    return s.failure as HttpClientError;
  }

  if s.published_complete {
    return HttpClientEvent{kind: HttpClientEventKind.Complete, complete: true, stats: s.exchange.Stats()};
  }

  if s.streaming {
    return http_tcp_stream_next(s);
  }

  while true {
    let control: Result<Unit, NetError> = s.options.Check(NetClock.NowNanoseconds());
    if control.IsErr() {
      return http_tcp_fail(s, http_tcp_network(s,(control.get_if<NetError>()) as NetError));
    }

    if !s.exchange.RequestComplete() {
      let output: Result<NetBuffer, HttpError> = s.exchange.Output();
      if output.IsErr() {
        return http_tcp_fail(s, http_tcp_protocol(s,(output.get_if<HttpError>()) as HttpError));
      }

      let block: NetBuffer = (output.get_if<NetBuffer>()) as NetBuffer;
      if block.Len() == (0 as intptr) {
        if s.exchange.RequestComplete() {
          continue;
        }

        return http_tcp_fail(s, http_tcp_protocol(s, HttpMakeError(HttpErrorKind.InvalidState)));
      }

      let sent: Result<intptr, NetError> = s.connection.Write(block.Bytes(), s.options);
      if sent.IsErr() {
        return http_tcp_fail(s, http_tcp_network(s,(sent.get_if<NetError>()) as NetError));
      }

      let count: intptr = (sent.get_if<intptr>()) as intptr;
      if count == (0 as intptr) {
        return http_tcp_fail(s, http_tcp_network(s, NetError{kind: NetErrorKind.ConnectionAborted}));
      }

      let acknowledged: Result<Unit, HttpError> = s.exchange.AcknowledgeOutput(count);
      if acknowledged.IsErr() {
        return http_tcp_fail(s, http_tcp_protocol(s,(acknowledged.get_if<HttpError>()) as HttpError));
      }

      continue;
    }

    let advanced: Result<HttpClientEvent, HttpError> = s.exchange.NextResponse();
    if advanced.IsErr() {
      return http_tcp_fail(s, http_tcp_protocol(s,(advanced.get_if<HttpError>()) as HttpError));
    }

    let event: HttpClientEvent = (advanced.get_if<HttpClientEvent>()) as HttpClientEvent;
    if event.kind != HttpClientEventKind.NeedInput {
      let final_control: Result<Unit, NetError> = s.options.Check(NetClock.NowNanoseconds());
      if final_control.IsErr() {
        return http_tcp_fail(s, http_tcp_network(s,(final_control.get_if<NetError>()) as NetError));
      }

      s.published_complete = event.complete;

      return event;
    }

    let range: NetMutableBytes = (NetMutableBytes.FromRaw(
      &mut s.incoming[0],
      16384 as intptr
    ).get_if<NetMutableBytes>()) as NetMutableBytes;
    let read: Result<intptr, NetError> = s.connection.Read(range, s.options);
    if read.IsErr() {
      return http_tcp_fail(s, http_tcp_network(s,(read.get_if<NetError>()) as NetError));
    }

    let count: intptr = (read.get_if<intptr>()) as intptr;
    let bytes: NetBytes = (range.AsReadOnly().Slice(0 as intptr, count).get_if<NetBytes>()) as NetBytes;
    let copied: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(bytes);
    if copied.IsErr() {
      var error: HttpClientError = http_tcp_network(s,(copied.get_if<NetError>()) as NetError);
      error.stats.response_bytes_received = error.stats.response_bytes_received + (count as uint64);

      return http_tcp_fail(s, error);
    }

    let buffer: NetBuffer = (copied.get_if<NetBuffer>()) as NetBuffer;
    let received: Result<Unit, HttpError> = s.exchange.Receive(buffer, count == (0 as intptr));
    if received.IsErr() {
      return http_tcp_fail(s, http_tcp_protocol(s,(received.get_if<HttpError>()) as HttpError));
    }
  }
}

/**
 * @brief Completed response trailer count, or typed protocol failure.
 * @returns Ok with int32 on success; Err with HttpClientError on the failure paths described
 *   above.
 */
pub method(HttpTcpClient) TrailerCount() -> Result<int32, HttpClientError> {
  if self.cell == nil {
    return HttpClientError{protocol_error: HttpMakeError(HttpErrorKind.Closed)};
  }

  let s: arc<HttpTcpData> = self.cell as arc<HttpTcpData>;
  if s.failure != nil {
    return s.failure as HttpClientError;
  }

  let result: Result<int32, HttpError> = s.exchange.TrailerCount();
  if result.IsErr() {
    return http_tcp_protocol(s,(result.get_if<HttpError>()) as HttpError);
  }

  return (result.get_if<int32>()) as int32;
}

/**
 * @brief Owned response trailer field, or typed protocol failure.
 * @returns Ok with HttpField on success; Err with HttpClientError on the failure paths described
 *   above.
 */
pub method(HttpTcpClient) TrailerAt(index: int32) -> Result<HttpField, HttpClientError> {
  if self.cell == nil {
    return HttpClientError{protocol_error: HttpMakeError(HttpErrorKind.Closed)};
  }

  let s: arc<HttpTcpData> = self.cell as arc<HttpTcpData>;
  if s.failure != nil {
    return s.failure as HttpClientError;
  }

  let result: Result<HttpField, HttpError> = s.exchange.TrailerAt(index);
  if result.IsErr() {
    return http_tcp_protocol(s,(result.get_if<HttpError>()) as HttpError);
  }

  return (result.get_if<HttpField>()) as HttpField;
}

/** @brief Retire the socket without erasing the first failure's progress. */
pub method(HttpTcpClient) Close() -> void {
  if self.cell == nil {
    return;
  }

  let s: arc<HttpTcpData> = self.cell as arc<HttpTcpData>;
  if s.failure == nil {
    let ignored: HttpClientError = http_tcp_fail(
      s,
      http_tcp_protocol(s, HttpMakeError(HttpErrorKind.Closed))
    );
  }
}
