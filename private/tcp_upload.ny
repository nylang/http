/** @brief Caller-thread streamed TCP scheduling with response-first nonblocking I/O. */
part of HttpClientCore;
/** @brief Validate the entire head and finite continue policy before socket adoption. */
pub static method(HttpTcpClient) NewStreaming(connection: ref mut TcpConnection, head: ref NetBuffer, limits: ref HttpClientLimits, options: ref NetOperationOptions, continue_wait_ms: int32) -> Result<HttpTcpClient, HttpClientError> {
  let control: Result<Unit, NetError> = options.Check(NetClock.NowNanoseconds());
  if control.IsErr() { return HttpClientError{transport_error: (control.get_if<NetError>()) as NetError}; }
  if continue_wait_ms < 0 || continue_wait_ms > 60000 { return HttpClientError{protocol_error: http_client_error(HttpErrorKind.InvalidArgument)}; }
  if !connection.IsOpen() { return HttpClientError{transport_error: NetError{kind: NetErrorKind.Closed}}; }
  var made: Result<HttpClientExchange, HttpError> = HttpClientExchange.NewStreaming(head, limits);
  if made.IsErr() { return HttpClientError{protocol_error: (made.get_if<HttpError>()) as HttpError}; }
  return HttpTcpClient{cell: new arc<HttpTcpData>{connection: move(connection), exchange: move((made.get_if<HttpClientExchange>()) as HttpClientExchange), options: options, streaming: true, continue_wait_ms: continue_wait_ms}};
}
func http_tcp_stream_control(s: arc<HttpTcpData>) -> HttpClientError? {
  if s.failure != nil { return s.failure; }
  let checked: Result<Unit, NetError> = s.options.Check(NetClock.NowNanoseconds());
  if checked.IsErr() { return http_tcp_fail(s, http_tcp_network(s, (checked.get_if<NetError>()) as NetError)); }
  return nil;
}
// Each wait owns at most two readiness-only registrations. Retire both before any
// socket access or event publication; no pending I/O or duplicate survives this call.
func http_tcp_stream_wait(s: arc<HttpTcpData>, readable: bool, writable: bool, gate: bool) -> Result<Unit, NetError> {
  var made: Result<NetEventLoop, NetError> = NetEventLoop.New(2);
  if made.IsErr() { return (made.get_if<NetError>()) as NetError; }
  var driver: NetEventLoop = move((made.get_if<NetEventLoop>()) as NetEventLoop);
  var reading: AsyncFuture<Result<Unit, NetError>>? = nil;
  var writing: AsyncFuture<Result<Unit, NetError>>? = nil;
  if readable {
    let registered: Result<AsyncFuture<Result<Unit, NetError>>, NetError> = s.connection.WhenReadable(driver, s.options);
    if registered.IsErr() { return (registered.get_if<NetError>()) as NetError; }
    reading = (registered.get_if<AsyncFuture<Result<Unit, NetError>>>()) as AsyncFuture<Result<Unit, NetError>>;
  }
  if writable {
    let registered: Result<AsyncFuture<Result<Unit, NetError>>, NetError> = s.connection.WhenWritable(driver, s.options);
    if registered.IsErr() { return (registered.get_if<NetError>()) as NetError; }
    writing = (registered.get_if<AsyncFuture<Result<Unit, NetError>>>()) as AsyncFuture<Result<Unit, NetError>>;
  }
  while true {
    let checked: Result<Unit, NetError> = s.options.Check(NetClock.NowNanoseconds());
    if checked.IsErr() { return (checked.get_if<NetError>()) as NetError; }
    // Capture natural completions before Close marks the losing registration Closed.
    if reading != nil && ((reading as AsyncFuture<Result<Unit, NetError>>).is_completed) {
      let result: Result<Result<Unit, NetError>, AsyncError> = (reading as AsyncFuture<Result<Unit, NetError>>).GetResult();
      if result.IsErr() { return NetError{kind: NetErrorKind.Closed}; }
      return (result.get_if<Result<Unit, NetError>>()) as Result<Unit, NetError>;
    }
    if writing != nil && ((writing as AsyncFuture<Result<Unit, NetError>>).is_completed) {
      let result: Result<Result<Unit, NetError>, AsyncError> = (writing as AsyncFuture<Result<Unit, NetError>>).GetResult();
      if result.IsErr() { return NetError{kind: NetErrorKind.Closed}; }
      return (result.get_if<Result<Unit, NetError>>()) as Result<Unit, NetError>;
    }
    var wait_ms: int32 = -1;
    if gate {
      if s.continue_deadline.IsExpired(NetClock.NowNanoseconds()) { return Unit{}; }
      wait_ms = s.continue_deadline.PollMilliseconds(NetClock.NowNanoseconds());
    }
    let polled: Result<int32, NetError> = driver.Poll(wait_ms);
    let after: Result<Unit, NetError> = s.options.Check(NetClock.NowNanoseconds());
    if after.IsErr() { return (after.get_if<NetError>()) as NetError; }
    if polled.IsErr() { return (polled.get_if<NetError>()) as NetError; }
  }
  return Unit{};
}
func http_tcp_stream_read(state: arc<HttpTcpData>) -> Result<bool, HttpClientError> {
  var s: arc<HttpTcpData> = state;
  let range: NetMutableBytes = (NetMutableBytes.FromRaw(&mut s.incoming[0], 16384 as intptr).get_if<NetMutableBytes>()) as NetMutableBytes;
  let read: Result<intptr, NetError> = s.connection.TryRead(range);
  if read.IsErr() {
    let error: NetError = (read.get_if<NetError>()) as NetError;
    let control: HttpClientError? = http_tcp_stream_control(s); if control != nil { return control as HttpClientError; }
    if error.kind == NetErrorKind.WouldBlock { return false; }
    return http_tcp_fail(s, http_tcp_network(s, error));
  }
  let count: intptr = (read.get_if<intptr>()) as intptr;
  let bytes: NetBytes = (range.AsReadOnly().Slice(0 as intptr, count).get_if<NetBytes>()) as NetBytes;
  let copied: Result<NetBuffer, NetError> = NetBuffer.CopyFrom(bytes);
  if copied.IsErr() {
    var error: HttpClientError = http_tcp_network(s, (copied.get_if<NetError>()) as NetError);
    error.stats.response_bytes_received = error.stats.response_bytes_received+(count as uint64);
    return http_tcp_fail(s, error);
  }
  let buffer: NetBuffer = (copied.get_if<NetBuffer>()) as NetBuffer;
  let received: Result<Unit, HttpError> = s.exchange.Receive(buffer, count == (0 as intptr));
  if received.IsErr() { return http_tcp_fail(s, http_tcp_protocol(s, (received.get_if<HttpError>()) as HttpError)); }
  return true;
}
func http_tcp_stream_next(state: arc<HttpTcpData>) -> Result<HttpClientEvent, HttpClientError> {
  var s: arc<HttpTcpData> = state;
  while true {
    let control: HttpClientError? = http_tcp_stream_control(s); if control != nil { return control as HttpClientError; }
    let queried: Result<HttpUploadState, HttpError> = s.exchange.UploadState();
    if queried.IsErr() { return http_tcp_fail(s, http_tcp_protocol(s, (queried.get_if<HttpError>()) as HttpError)); }
    var upload: HttpUploadState = (queried.get_if<HttpUploadState>()) as HttpUploadState;
    if upload != HttpUploadState.SendingHead {
      if !s.continue_started {
        s.continue_deadline = NetDeadline.After(NetClock.NowNanoseconds(), (s.continue_wait_ms as uint64)*1000000u64);
        s.continue_started = true;
      }
      let advanced: Result<HttpClientEvent, HttpError> = s.exchange.NextResponse();
      if advanced.IsErr() { return http_tcp_fail(s, http_tcp_protocol(s, (advanced.get_if<HttpError>()) as HttpError)); }
      let event: HttpClientEvent = (advanced.get_if<HttpClientEvent>()) as HttpClientEvent;
      if event.kind != HttpClientEventKind.NeedInput {
        let final_control: HttpClientError? = http_tcp_stream_control(s); if final_control != nil { return final_control as HttpClientError; }
        s.published_complete = event.complete; return event;
      }
      let read: Result<bool, HttpClientError> = http_tcp_stream_read(s);
      if read.IsErr() { return (read.get_if<HttpClientError>()) as HttpClientError; }
      if (read.get_if<bool>()) as bool { continue; }
      upload = (s.exchange.UploadState().get_if<HttpUploadState>()) as HttpUploadState;
      if upload == HttpUploadState.WaitingContinue && s.continue_deadline.IsExpired(NetClock.NowNanoseconds()) {
        let released: Result<Unit, HttpError> = s.exchange.ContinueUpload();
        if released.IsErr() { return http_tcp_fail(s, http_tcp_protocol(s, (released.get_if<HttpError>()) as HttpError)); }
        continue;
      }
      if upload == HttpUploadState.NeedBody {
        let final_control: HttpClientError? = http_tcp_stream_control(s); if final_control != nil { return final_control as HttpClientError; }
        return HttpClientEvent{kind: HttpClientEventKind.NeedBody, stats: s.exchange.Stats()};
      }
    }
    let output: Result<NetBuffer, HttpError> = s.exchange.Output();
    if output.IsErr() { return http_tcp_fail(s, http_tcp_protocol(s, (output.get_if<HttpError>()) as HttpError)); }
    let block: NetBuffer = (output.get_if<NetBuffer>()) as NetBuffer;
    var writable: bool = false;
    if block.Len() != (0 as intptr) {
      let sent: Result<intptr, NetError> = s.connection.TryWrite(block.Bytes());
      if sent.IsOk() {
        let count: intptr = (sent.get_if<intptr>()) as intptr;
        if count == (0 as intptr) { return http_tcp_fail(s, http_tcp_network(s, NetError{kind: NetErrorKind.ConnectionAborted})); }
        let acknowledged: Result<Unit, HttpError> = s.exchange.AcknowledgeOutput(count);
        if acknowledged.IsErr() { return http_tcp_fail(s, http_tcp_protocol(s, (acknowledged.get_if<HttpError>()) as HttpError)); }
        continue;
      }
      let control_after: HttpClientError? = http_tcp_stream_control(s); if control_after != nil { return control_after as HttpClientError; }
      let error: NetError = (sent.get_if<NetError>()) as NetError;
      if error.kind != NetErrorKind.WouldBlock { return http_tcp_fail(s, http_tcp_network(s, error)); }
      writable = true;
    } else {
      let next_state: HttpUploadState = (s.exchange.UploadState().get_if<HttpUploadState>()) as HttpUploadState;
      if next_state != upload { continue; }
    }
    let waited: Result<Unit, NetError> = http_tcp_stream_wait(s, upload != HttpUploadState.SendingHead, writable, upload == HttpUploadState.WaitingContinue);
    if waited.IsErr() { return http_tcp_fail(s, http_tcp_network(s, (waited.get_if<NetError>()) as NetError)); }
  }
  return HttpClientError{protocol_error: http_client_error(HttpErrorKind.InvalidState)};
}
/** @brief Observe the streamed producer state without I/O or deadline renewal. */
pub method(HttpTcpClient) UploadState() -> Result<HttpUploadState, HttpClientError> {
  if self.cell == nil { return HttpClientError{protocol_error: http_client_error(HttpErrorKind.Closed)}; }
  let s: arc<HttpTcpData> = self.cell as arc<HttpTcpData>;
  if s.failure != nil { return s.failure as HttpClientError; }
  let result: Result<HttpUploadState, HttpError> = s.exchange.UploadState();
  if result.IsErr() { return http_tcp_protocol(s, (result.get_if<HttpError>()) as HttpError); }
  return (result.get_if<HttpUploadState>()) as HttpUploadState;
}
/** @brief Admit one body owner without starting transport I/O. */
pub method(HttpTcpClient) SupplyBody(buffer: ref NetBuffer) -> Result<Unit, HttpClientError> {
  if self.cell == nil { return HttpClientError{protocol_error: http_client_error(HttpErrorKind.Closed)}; }
  let s: arc<HttpTcpData> = self.cell as arc<HttpTcpData>;
  let control: HttpClientError? = http_tcp_stream_control(s); if control != nil { return control as HttpClientError; }
  let supplied: Result<Unit, HttpError> = s.exchange.SupplyBody(buffer);
  if supplied.IsErr() { return http_tcp_protocol(s, (supplied.get_if<HttpError>()) as HttpError); }
  return Unit{};
}
/** @brief Finish a drained producer; retire immediately on terminal framing failure. */
pub method(HttpTcpClient) FinishBody(trailers: ref <HttpField>[]) -> Result<Unit, HttpClientError> {
  if self.cell == nil { return HttpClientError{protocol_error: http_client_error(HttpErrorKind.Closed)}; }
  let s: arc<HttpTcpData> = self.cell as arc<HttpTcpData>;
  let control: HttpClientError? = http_tcp_stream_control(s); if control != nil { return control as HttpClientError; }
  let finished: Result<Unit, HttpError> = s.exchange.FinishBody(trailers);
  if finished.IsErr() {
    let error: HttpClientError = http_tcp_protocol(s, (finished.get_if<HttpError>()) as HttpError);
    if s.streaming && s.exchange.UploadState().IsErr() { return http_tcp_fail(s, error); }
    return error;
  }
  return Unit{};
}
