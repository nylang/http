// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

part of HttpExchange;

/** @brief Producer admission and continue gating for streamed exchanges. */

/**
 * @brief Scheduling state for a streamed cursor, or Closed/InvalidState for a default/immutable
 *   cursor.
 * @returns Ok with HttpUploadState on success; Err with HttpError on the failure paths described
 *   above.
 */
pub method(HttpClientExchange) UploadState() -> Result<HttpUploadState, HttpError> {
  if self.cell == nil {
    return HttpMakeError(HttpErrorKind.Closed);
  }

  let s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.failure != nil {
    return s.failure as HttpError;
  }

  if !s.streaming {
    return HttpMakeError(HttpErrorKind.InvalidState);
  }

  if s.stopped {
    return HttpUploadState.Stopped;
  }

  if !http_exchange_head_sent(s) {
    return HttpUploadState.SendingHead;
  }

  if self.RequestComplete() {
    return HttpUploadState.Finished;
  }

  if http_exchange_reading(s) {
    return HttpUploadState.ReadingResponse;
  }

  if s.await_continue {
    return HttpUploadState.WaitingContinue;
  }

  if s.pending_cursor < s.pending.Len() || s.body_cursor < s.body_length || s.finish_queued {
    return HttpUploadState.SendingBody;
  }

  return HttpUploadState.NeedBody;
}

/**
 * @brief Admit one nonempty immutable body block when NeedBody; failures do not change producer
 *   state.
 * @returns Ok with Unit on success; Err with HttpError on the failure paths described above.
 * @note Empty, oversized/backing-heavy, over-length or over-budget input fails before adoption.
 *   Keep calling Output/AcknowledgeOutput to drain it. No producer callback, hidden queue or
 *   replay.
 */
pub method(HttpClientExchange) SupplyBody(buffer: ref NetBuffer) -> Result<Unit, HttpError> {
  let status: Result<HttpUploadState, HttpError> = self.UploadState();
  if status.IsErr() {
    return (status.get_if<HttpError>()) as HttpError;
  }

  if ((status.get_if<HttpUploadState>()) as HttpUploadState) != HttpUploadState.NeedBody {
    return HttpMakeError(HttpErrorKind.InvalidState);
  }

  var s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if buffer.Len() <= (0 as intptr) {
    return HttpMakeError(HttpErrorKind.InvalidArgument);
  }

  let budget: intptr = s.limits.max_retained_request_bytes as intptr;
  if buffer.RetainedBytes() >(16384 as intptr)
    || buffer.RetainedBytes() > budget - s.head_wire.RetainedBytes() {
    return HttpMakeError(HttpErrorKind.LimitExceeded);
  }

  var limit: uint64 = s.limits.body.max_body_bytes;
  if limit == 0u64 {
    limit = 16777216u64;
  }

  let count: uint64 = buffer.Len() as uint64;
  if s.supplied > limit || count > limit - s.supplied {
    return HttpMakeError(HttpErrorKind.LimitExceeded);
  }

  let plan: HttpBodyPlan = (s.request.BodyPlan().get_if<HttpBodyPlan>()) as HttpBodyPlan;
  if plan.kind == HttpBodyKind.None
    || (
      plan.kind == HttpBodyKind.ContentLength && (
        s.supplied > plan.length || count > plan.length - s.supplied
      )
    ) {
    return HttpMakeError(HttpErrorKind.InvalidFraming);
  }

  s.body = buffer;
  s.body_cursor = 0 as intptr;
  s.body_length = buffer.Len();
  s.supplied = s.supplied + count;

  return Unit{};
}

/**
 * @brief Close the producer after its last block drains, and queue validated chunk trailers.
 * @returns Ok with Unit on success; Err with HttpError on the failure paths described above.
 * @note A fixed-length shortage or invalid trailer makes the exchange fail. Empty chunked
 *   content with Expect is InvalidFraming. Repeated finish accepts only an empty trailer list.
 *   Drain final framing with Output/AcknowledgeOutput; Finish alone never means wire delivery.
 */
pub method(HttpClientExchange) FinishBody(trailers: ref <HttpField>[]) -> Result<Unit, HttpError> {
  if self.cell == nil {
    return HttpMakeError(HttpErrorKind.Closed);
  }

  var s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  if s.failure != nil {
    return s.failure as HttpError;
  }

  if !s.streaming
    || s.stopped
    || !http_exchange_head_sent(s)
    || s.await_continue
    || http_exchange_reading(s)
    || s.body_cursor < s.body_length
    || s.pending_cursor < s.pending.Len() {
    return HttpMakeError(HttpErrorKind.InvalidState);
  }

  let plan: HttpBodyPlan = (s.request.BodyPlan().get_if<HttpBodyPlan>()) as HttpBodyPlan;
  if !s.finish_queued && plan.kind == HttpBodyKind.ContentLength && s.supplied != plan.length {
    return http_exchange_fail(s, HttpMakeError(HttpErrorKind.UnexpectedEof));
  }

  if !s.finish_queued && s.supplied == 0u64 && http_upload_expected(s.request) {
    return http_exchange_fail(s, HttpMakeError(HttpErrorKind.InvalidFraming));
  }

  let finished: Result<bool, HttpError> = s.writer.Finish(trailers);
  if finished.IsErr() {
    return http_exchange_fail(s,(finished.get_if<HttpError>()) as HttpError);
  }

  s.finish_queued = true;

  return Unit{};
}

func http_upload_expected(request: ref HttpHead) -> bool {
  var i: int32 = 0;
  while i < request.FieldCount() {
    let field: HttpField = (request.FieldAt(i).get_if<HttpField>()) as HttpField;
    if HttpEqual(field.name, "Expect") {
      return true;
    }

    i = i + 1;
  }

  return false;
}

/**
 * @brief Explicitly release a pending 100-continue gate after a caller-bounded wait.
 * @returns Ok with Unit on success; Err with HttpError on the failure paths described above.
 * @note No I/O, clock or deadline refresh. The caller must not wait indefinitely, must first
 *   drain received informational/final heads, and retains its original absolute control budget. A
 *   parsed 100 releases the same gate automatically; an early final response never permits
 *   resuming.
 */
pub method(HttpClientExchange) ContinueUpload() -> Result<Unit, HttpError> {
  let status: Result<HttpUploadState, HttpError> = self.UploadState();
  if status.IsErr() {
    return (status.get_if<HttpError>()) as HttpError;
  }

  if ((status.get_if<HttpUploadState>()) as HttpUploadState) != HttpUploadState.WaitingContinue {
    return HttpMakeError(HttpErrorKind.InvalidState);
  }

  var s: arc<HttpExchangeData> = self.cell as arc<HttpExchangeData>;
  s.await_continue = false;

  return Unit{};
}
