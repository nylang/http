/** @brief Producer admission and continue gating for streamed exchanges. */
part of HttpClientCore;
/** @brief Describe the next permitted producer/output/response action. */
pub method(HttpClientExchange) UploadState() -> Result<HttpUploadState, HttpError> {
  if self.cell == nil { return http_client_error(HttpErrorKind.Closed); } let s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.failure != nil { return s.failure as HttpError; } if !s.streaming { return http_client_error(HttpErrorKind.InvalidState); }
  if s.stopped { return HttpUploadState.Stopped; }
  if !http_exchange_head_sent(s) { return HttpUploadState.SendingHead; }
  if self.RequestComplete() { return HttpUploadState.Finished; }
  if http_exchange_reading(s) { return HttpUploadState.ReadingResponse; }
  if s.await_continue { return HttpUploadState.WaitingContinue; }
  if s.pending_cursor < s.pending.Len() || s.body_cursor < s.body_length || s.finish_queued { return HttpUploadState.SendingBody; }
  return HttpUploadState.NeedBody;
}
/** @brief Admit a bounded immutable producer block without changing rejected admissions. */
pub method(HttpClientExchange) SupplyBody(buffer: ref NetBuffer) -> Result<Unit, HttpError> {
  let status: Result<HttpUploadState, HttpError> = self.UploadState(); if status.IsErr() { return (status.get_if<HttpError>()) as HttpError; }
  if ((status.get_if<HttpUploadState>()) as HttpUploadState) != HttpUploadState.NeedBody { return http_client_error(HttpErrorKind.InvalidState); }
  var s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if buffer.Len() <= (0 as intptr) { return http_client_error(HttpErrorKind.InvalidArgument); }
  let budget: intptr = s.limits.max_retained_request_bytes as intptr;
  if buffer.RetainedBytes() > (16384 as intptr) || buffer.RetainedBytes() > budget-s.head_wire.RetainedBytes() { return http_client_error(HttpErrorKind.LimitExceeded); }
  var limit: uint64 = s.limits.body.max_body_bytes; if limit == 0u64 { limit = 16777216u64; }
  let count: uint64 = buffer.Len() as uint64;
  if s.supplied > limit || count > limit-s.supplied { return http_client_error(HttpErrorKind.LimitExceeded); }
  let plan: HttpBodyPlan = (s.request.BodyPlan().get_if<HttpBodyPlan>()) as HttpBodyPlan;
  if plan.kind == HttpBodyKind.None || (plan.kind == HttpBodyKind.ContentLength && (s.supplied > plan.length || count > plan.length-s.supplied)) { return http_client_error(HttpErrorKind.InvalidFraming); }
  s.body = buffer; s.body_cursor = 0 as intptr; s.body_length = buffer.Len(); s.supplied = s.supplied+count; return Unit{};
}
/** @brief Close the drained producer and queue bounded final framing. */
pub method(HttpClientExchange) FinishBody(trailers: ref <HttpField>[]) -> Result<Unit, HttpError> {
  if self.cell == nil { return http_client_error(HttpErrorKind.Closed); } var s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.failure != nil { return s.failure as HttpError; }
  if !s.streaming || s.stopped || !http_exchange_head_sent(s) || s.await_continue || http_exchange_reading(s) || s.body_cursor < s.body_length || s.pending_cursor < s.pending.Len() { return http_client_error(HttpErrorKind.InvalidState); }
  let plan: HttpBodyPlan = (s.request.BodyPlan().get_if<HttpBodyPlan>()) as HttpBodyPlan;
  if !s.finish_queued && plan.kind == HttpBodyKind.ContentLength && s.supplied != plan.length { return http_exchange_fail(s, http_client_error(HttpErrorKind.UnexpectedEof)); }
  if !s.finish_queued && s.supplied == 0u64 && http_upload_expected(s.request) { return http_exchange_fail(s, http_client_error(HttpErrorKind.InvalidFraming)); }
  let finished: Result<bool, HttpError> = s.writer.Finish(trailers);
  if finished.IsErr() { return http_exchange_fail(s, (finished.get_if<HttpError>()) as HttpError); }
  s.finish_queued = true; return Unit{};
}
func http_upload_expected(request: ref HttpHead) -> bool {
  var i: int32 = 0; while i < request.FieldCount() { let field: HttpField = (request.FieldAt(i).get_if<HttpField>()) as HttpField; if http_client_equal(field.name, "Expect") { return true; } i = i+1; } return false;
}
/** @brief Release a continue gate explicitly without resetting any transport control budget. */
pub method(HttpClientExchange) ContinueUpload() -> Result<Unit, HttpError> {
  let status: Result<HttpUploadState, HttpError> = self.UploadState(); if status.IsErr() { return (status.get_if<HttpError>()) as HttpError; }
  if ((status.get_if<HttpUploadState>()) as HttpUploadState) != HttpUploadState.WaitingContinue { return http_client_error(HttpErrorKind.InvalidState); }
  var s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>; s.await_continue = false; return Unit{};
}
