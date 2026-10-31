// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of HttpTcpAdapter;

/** @brief Caller-thread streamed TCP scheduling with response-first nonblocking I/O. */

/**
 * @brief Validate and adopt a TCP connection for bounded producer-driven upload.
 * @param continue_wait_ms Finite 0..60000 ms fallback measured once after head acknowledgement;
 *   zero releases immediately after draining any available response. Only used with Expect.
 * @returns Ok with HttpTcpClient on success; Err with HttpClientError on the failure paths
 *   described above.
 * @note Next emits NeedBody when one block or FinishBody is required. It probes available
 *   response input before requesting/sending body and waits for either readability or writability
 *   under upload backpressure. Parsed partial heads pause upload; final heads revoke unsent bytes.
 *   Actual socket acceptance is acknowledged before response parsing. A response racing a write
 *   may arrive after that write commits; accepted bytes cannot be revoked. No retry or replay.
 *   Caller time between methods remains inside the original absolute control budget.
 */
pub static method(HttpTcpClient) NewStreaming(
  connection: ref mut TcpConnection,
  head: ref NetBuffer,
  limits: ref HttpClientLimits,
  options: ref NetOperationOptions,
  continue_wait_ms: int32
) -> Result<HttpTcpClient, HttpClientError> {
  let control: Result<Unit, NetError> = options.CheckNow();
  if control.IsErr() {
    return HttpClientError{transport_error:(control.get_if<NetError>()) as NetError};
  }

  if continue_wait_ms < 0 || continue_wait_ms > 60000 {
    return HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidArgument}};
  }

  if !connection.IsOpen() {
    return HttpClientError{transport_error: NetError{kind: NetErrorKind.Closed}};
  }

  var made: Result<HttpClientExchange, HttpError> = HttpClientExchange.NewStreaming(head, limits);
  if made.IsErr() {
    return HttpClientError{protocol_error:(made.get_if<HttpError>()) as HttpError};
  }

  return HttpTcpClient{cell: new arc<HttpTcpData>{
    connection: move(connection),
    exchange: move((made.get_if<HttpClientExchange>()) as HttpClientExchange),
    options: options,
    streaming: true,
    continue_wait_ms: continue_wait_ms
  }};
}

method(HttpTcpData) ControlError() -> HttpClientError? {
  if self.failure != nil {
    return self.failure;
  }

  let checked: Result<Unit, NetError> = self.options.CheckNow();
  if checked.IsErr() {
    return self.Fail(self.NetworkError((checked.get_if<NetError>()) as NetError));
  }

  return nil;
}

// Each wait owns at most two readiness-only registrations. Retire both before any

// socket access or event publication; no pending I/O or duplicate survives this call.
method(HttpTcpData) WaitForDirection(
  readable: bool,
  writable: bool,
  gate: bool
) -> Result<Unit, NetError> {
  var made: Result<NetEventLoop, NetError> = NetEventLoop.New(2);
  if made.IsErr() {
    return (made.get_if<NetError>()) as NetError;
  }

  var driver: NetEventLoop = move((made.get_if<NetEventLoop>()) as NetEventLoop);
  var reading: AsyncFuture<Result<Unit, NetError>>? = nil;
  var writing: AsyncFuture<Result<Unit, NetError>>? = nil;
  if readable {
    let registered: Result<AsyncFuture<Result<Unit, NetError>>, NetError> = self.connection.WhenReadable(
      driver,
      self.options
    );
    if registered.IsErr() {
      return (registered.get_if<NetError>()) as NetError;
    }

    reading = (
      registered.get_if<AsyncFuture<Result<Unit, NetError>>>()
    ) as AsyncFuture<Result<Unit, NetError>>;
  }

  if writable {
    let registered: Result<AsyncFuture<Result<Unit, NetError>>, NetError> = self.connection.WhenWritable(
      driver,
      self.options
    );
    if registered.IsErr() {
      return (registered.get_if<NetError>()) as NetError;
    }

    writing = (
      registered.get_if<AsyncFuture<Result<Unit, NetError>>>()
    ) as AsyncFuture<Result<Unit, NetError>>;
  }

  while true {
    let checked: Result<Unit, NetError> = self.options.CheckNow();
    if checked.IsErr() {
      return (checked.get_if<NetError>()) as NetError;
    }

    // Capture natural completions before Close marks the losing registration Closed.
    if reading != nil && ((reading as AsyncFuture<Result<Unit, NetError>>).is_completed) {
      let result: Result<Result<Unit, NetError>, AsyncError> = (
        reading as AsyncFuture<Result<Unit, NetError>>
      ).GetResult();
      if result.IsErr() {
        return NetError{kind: NetErrorKind.Closed};
      }

      return (result.get_if<Result<Unit, NetError>>()) as Result<Unit, NetError>;
    }

    if writing != nil && ((writing as AsyncFuture<Result<Unit, NetError>>).is_completed) {
      let result: Result<Result<Unit, NetError>, AsyncError> = (
        writing as AsyncFuture<Result<Unit, NetError>>
      ).GetResult();
      if result.IsErr() {
        return NetError{kind: NetErrorKind.Closed};
      }

      return (result.get_if<Result<Unit, NetError>>()) as Result<Unit, NetError>;
    }

    var wait_ms: int32 = -1;
    if gate {
      if self.continue_deadline.IsExpired(Instant.Now().ToDurationSinceEpochish().ToNanoseconds()) {
        return Unit{};
      }

      wait_ms = self.continue_deadline.PollMilliseconds(Instant.Now().ToDurationSinceEpochish().ToNanoseconds());
    }

    let polled: Result<int32, NetError> = driver.Poll(wait_ms);
    let after: Result<Unit, NetError> = self.options.CheckNow();
    if after.IsErr() {
      return (after.get_if<NetError>()) as NetError;
    }

    if polled.IsErr() {
      return (polled.get_if<NetError>()) as NetError;
    }
  }

  return Unit{};
}

method(HttpTcpData) ReadForExchange() -> Result<bool, HttpClientError> {
  let range: NetMutableBytes = (NetMutableBytes.FromRaw(
    &mut self.incoming[0],
    16384ip
  ).get_if<NetMutableBytes>()) as NetMutableBytes;
  let read: Result<intptr, NetError> = self.connection.TryRead(range);
  if read.IsErr() {
    let error: NetError = (read.get_if<NetError>()) as NetError;
    let control: HttpClientError? = self.ControlError();
    if control != nil {
      return control as HttpClientError;
    }

    if error.kind == NetErrorKind.WouldBlock {
      return false;
    }

    return self.Fail(self.NetworkError(error));
  }

  let count: intptr = (read.get_if<intptr>()) as intptr;
  let bytes: NetBytes = (range.AsReadOnly().Slice(0ip, count).get_if<NetBytes>()) as NetBytes;
  let copied: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(bytes);
  if copied.IsErr() {
    var error: HttpClientError = self.NetworkError((copied.get_if<NetError>()) as NetError);
    error.stats.response_bytes_received = error.stats.response_bytes_received + (count as uint64);

    return self.Fail(error);
  }

  let buffer: NetBuffer = (copied.get_if<NetBuffer>()) as NetBuffer;
  let received: Result<Unit, HttpError> = self.exchange.Receive(buffer, count == (0ip));
  if received.IsErr() {
    return self.Fail(self.ProtocolError((received.get_if<HttpError>()) as HttpError));
  }

  return true;
}

// Probe response progress before admitting more upload bytes; an early final response must suppress unsent body output.
method(HttpTcpData) NextStreamEvent() -> Result<HttpClientEvent, HttpClientError> {
  while true {
    let control: HttpClientError? = self.ControlError();
    if control != nil {
      return control as HttpClientError;
    }

    let queried: Result<HttpUploadState, HttpError> = self.exchange.UploadState();
    if queried.IsErr() {
      return self.Fail(self.ProtocolError((queried.get_if<HttpError>()) as HttpError));
    }

    var upload: HttpUploadState = (queried.get_if<HttpUploadState>()) as HttpUploadState;
    if upload != HttpUploadState.SendingHead {
      if !self.continue_started {
        self.continue_deadline = NetDeadline.After(
          Instant.Now().ToDurationSinceEpochish().ToNanoseconds(),
          (self.continue_wait_ms as uint64) * 1000000u64
        );
        self.continue_started = true;
      }

      let advanced: Result<HttpClientEvent, HttpError> = self.exchange.NextResponse();
      if advanced.IsErr() {
        return self.Fail(self.ProtocolError((advanced.get_if<HttpError>()) as HttpError));
      }

      let event: HttpClientEvent = (advanced.get_if<HttpClientEvent>()) as HttpClientEvent;
      if event.kind != HttpClientEventKind.NeedInput {
        let final_control: HttpClientError? = self.ControlError();
        if final_control != nil {
          return final_control as HttpClientError;
        }

        self.published_complete = event.complete;

        return event;
      }

      let read: Result<bool, HttpClientError> = self.ReadForExchange();
      if read.IsErr() {
        return (read.get_if<HttpClientError>()) as HttpClientError;
      }

      if (read.get_if<bool>()) as bool {
        continue;
      }

      upload = (self.exchange.UploadState().get_if<HttpUploadState>()) as HttpUploadState;
      if upload == HttpUploadState.WaitingContinue
        && self.continue_deadline.IsExpired(Instant.Now().ToDurationSinceEpochish().ToNanoseconds()) {
        let released: Result<Unit, HttpError> = self.exchange.ContinueUpload();
        if released.IsErr() {
          return self.Fail(self.ProtocolError((released.get_if<HttpError>()) as HttpError));
        }

        continue;
      }

      if upload == HttpUploadState.NeedBody {
        let final_control: HttpClientError? = self.ControlError();
        if final_control != nil {
          return final_control as HttpClientError;
        }

        return HttpClientEvent{kind: HttpClientEventKind.NeedBody, stats: self.exchange.Stats()};
      }
    }

    let output: Result<NetBuffer, HttpError> = self.exchange.Output();
    if output.IsErr() {
      return self.Fail(self.ProtocolError((output.get_if<HttpError>()) as HttpError));
    }

    let block: NetBuffer = (output.get_if<NetBuffer>()) as NetBuffer;
    var writable: bool = false;
    if block.Len() != (0ip) {
      let sent: Result<intptr, NetError> = self.connection.TryWrite(block.Bytes());
      if sent.IsOk() {
        let count: intptr = (sent.get_if<intptr>()) as intptr;
        if count == (0ip) {
          return self.Fail(self.NetworkError(NetError{kind: NetErrorKind.ConnectionAborted}));
        }

        let acknowledged: Result<Unit, HttpError> = self.exchange.AcknowledgeOutput(count);
        if acknowledged.IsErr() {
          return self.Fail(self.ProtocolError((acknowledged.get_if<HttpError>()) as HttpError));
        }

        continue;
      }

      let control_after: HttpClientError? = self.ControlError();
      if control_after != nil {
        return control_after as HttpClientError;
      }

      let error: NetError = (sent.get_if<NetError>()) as NetError;
      if error.kind != NetErrorKind.WouldBlock {
        return self.Fail(self.NetworkError(error));
      }

      writable = true;
    } else {
      let next_state: HttpUploadState = (
        self.exchange.UploadState().get_if<HttpUploadState>()
      ) as HttpUploadState;
      if next_state != upload {
        continue;
      }
    }

    let waited: Result<Unit, NetError> = self.WaitForDirection(upload != HttpUploadState.SendingHead,
      writable,
      upload == HttpUploadState.WaitingContinue);
    if waited.IsErr() {
      return self.Fail(self.NetworkError((waited.get_if<NetError>()) as NetError));
    }
  }

  return HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.InvalidState}};
}

/**
 * @brief Streamed producer state, with preserved typed error/progress; immutable clients return
 *   InvalidState.
 * @returns Ok with HttpUploadState on success; Err with HttpClientError on the failure paths
 *   described above.
 */
pub method(HttpTcpClient) UploadState() -> Result<HttpUploadState, HttpClientError> {
  if self.cell == nil {
    return HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.Closed}};
  }

  let s: arc<HttpTcpData> = self.cell as arc<HttpTcpData>;
  if s.failure != nil {
    return s.failure as HttpClientError;
  }

  let result: Result<HttpUploadState, HttpError> = s.exchange.UploadState();
  if result.IsErr() {
    return (s).ProtocolError((result.get_if<HttpError>()) as HttpError);
  }

  return (result.get_if<HttpUploadState>()) as HttpUploadState;
}

/**
 * @brief Supply one bounded immutable producer owner after NeedBody; rejected admission is
 *   nonterminal.
 * @returns Ok with Unit on success; Err with HttpClientError on the failure paths described
 *   above.
 * @note No I/O or hidden queue. A later Next checks responses before writing this block.
 */
pub method(HttpTcpClient) SupplyBody(buffer: ref NetBuffer) -> Result<Unit, HttpClientError> {
  if self.cell == nil {
    return HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.Closed}};
  }

  let s: arc<HttpTcpData> = self.cell as arc<HttpTcpData>;
  let control: HttpClientError? = (s).ControlError();
  if control != nil {
    return control as HttpClientError;
  }

  let supplied: Result<Unit, HttpError> = s.exchange.SupplyBody(buffer);
  if supplied.IsErr() {
    return (s).ProtocolError((supplied.get_if<HttpError>()) as HttpError);
  }

  return Unit{};
}

/**
 * @brief Finish a drained producer and queue final framing/trailers; shortages retire the
 *   connection.
 * @returns Ok with Unit on success; Err with HttpClientError on the failure paths described
 *   above.
 * @note No I/O, deadline refresh or replay. Drive Next until response completion, then
 *   Close/drop.
 */
pub method(HttpTcpClient) FinishBody(trailers: ref <HttpField>[]) -> Result<Unit, HttpClientError> {
  if self.cell == nil {
    return HttpClientError{protocol_error: HttpError{kind: HttpErrorKind.Closed}};
  }

  let s: arc<HttpTcpData> = self.cell as arc<HttpTcpData>;
  let control: HttpClientError? = (s).ControlError();
  if control != nil {
    return control as HttpClientError;
  }

  let finished: Result<Unit, HttpError> = s.exchange.FinishBody(trailers);
  if finished.IsErr() {
    let error: HttpClientError = (s).ProtocolError((finished.get_if<HttpError>()) as HttpError);
    if s.streaming && s.exchange.UploadState().IsErr() {
      return (s).Fail(error);
    }

    return error;
  }

  return Unit{};
}
