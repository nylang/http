// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

module HttpBodyEncoder;
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/client.ni";
import "interface/url.ni";
import "interface/redirect.ni";
import "private/grammar.ny";
import "private/framing_rules.ny";
import "private/http.ny";

/** @brief Payload streaming and bounded canonical chunk/trailer output. */

enum HttpWritePhase {
  Ready,
  Frame,
  Data,
  Done
}

struct HttpWriteData {
  head: HttpHead;
  limits: HttpBodyLimits;
  kind: HttpBodyKind;
  phase: HttpWritePhase;
  after_frame: HttpWritePhase;
  remaining: uint64;
  decoded: uint64;
  total: int64;
  framing_reserved: int32;
  pending: string;
  pending_pos: int32;
  final_wire: string;
  finishing: bool;
  failure: HttpError?;
}

/**
 * @brief Move-only streaming body encoder using caller-owned output, with no retained payload
 *   pointer.
 */
pub struct HttpBodyWriter {
  cell: arc<HttpWriteData>?;
}

method(HttpWriteData) Fail(kind: HttpErrorKind) -> HttpError {
  let error: HttpError = HttpError{kind: kind, offset: self.total};
  self.failure = error;

  return error;
}

method(HttpHead) ValidateBodyPlan(kind: HttpBodyKind) -> HttpErrorKind? {
  var f: int32 = 0;
  while f < self.FieldCount() {
    let field: HttpField = (self.FieldAt(f).get_if<HttpField>()) as HttpField;
    if (field.name).EqualAsciiIgnoreCase("Trailer") {
      if kind != HttpBodyKind.Chunked {
        return HttpErrorKind.InvalidFraming;
      }

      var i: int32 = 0;
      while true {
        let start: int32 = i;
        while i < field.value.length && (field.value).ByteAtOr(i, 0) != 44 {
          i = i + 1;
        }

        let name: string = HttpLexeme.New(field.value.Substring(start, i - start)).TrimWhitespace();
        if !HttpLexeme.New(name).IsToken() || self.ForbidsTrailer(name) {
          return HttpErrorKind.InvalidFraming;
        }

        if i == field.value.length {
          break;
        }

        i = i + 1;
      }
    }

    f = f + 1;
  }

  return nil;
}

method(HttpHead) DeclaresTrailer(name: ref string) -> bool {
  var f: int32 = 0;
  while f < self.FieldCount() {
    let field: HttpField = (self.FieldAt(f).get_if<HttpField>()) as HttpField;
    if (field.name).EqualAsciiIgnoreCase("Trailer") {
      var i: int32 = 0;
      while i < field.value.length {
        let start: int32 = i;
        while i < field.value.length && (field.value).ByteAtOr(i, 0) != 44 {
          i = i + 1;
        }

        if (HttpLexeme.New(field.value.Substring(start, i - start)).TrimWhitespace()).EqualAsciiIgnoreCase(name) {
          return true;
        }

        i = i + 1;
      }
    }

    f = f + 1;
  }

  return false;
}

// A positive admitted chunk size determines one hexadecimal framing header.
struct HttpChunkHeader {
  readonly size: int32;
}

method(HttpChunkHeader) Encode() -> string {
  let size: int32 = self.size;
  var digits: <int8>[8] = <int8>[8] {
  };
  var cursor: int32 = 8;
  var value: int32 = size;
  while value > 0 {
    let digit: int32 = value % 16;
    cursor = cursor - 1;
    if digit < 10 {
      digits[cursor] = (48 + digit) as int8;
    } else {
      digits[cursor] = (87 + digit) as int8;
    }

    value = value / 16;
  }

  return string.ViewFrom(&digits[cursor], 8 - cursor).Concat("\r\n");
}

/**
 * @brief Build from a validated head and body limits; reject Upgrade/Tunnel and oversized fixed
 *   lengths.
 * @returns Ok with HttpBodyWriter on success; Err with HttpError on the failure paths described
 *   above.
 * @note Trailer declarations must contain safe token names and require chunked framing.
 */
pub static method(HttpBodyWriter) New(
  head: ref HttpHead,
  limits: ref HttpBodyLimits
) -> Result<HttpBodyWriter, HttpError> {
  let planned: Result<HttpBodyPlan, HttpError> = head.BodyPlan();
  if planned.IsErr() {
    return (planned.get_if<HttpError>()) as HttpError;
  }

  let plan: HttpBodyPlan = (planned.get_if<HttpBodyPlan>()) as HttpBodyPlan;
  let checked: Result<HttpBodyLimits, HttpError> = (limits).Normalize();
  if checked.IsErr() {
    return (checked.get_if<HttpError>()) as HttpError;
  }

  let caps: HttpBodyLimits = (checked.get_if<HttpBodyLimits>()) as HttpBodyLimits;
  if plan.kind == HttpBodyKind.Upgrade || plan.kind == HttpBodyKind.Tunnel {
    return HttpError{kind: HttpErrorKind.Unsupported};
  }

  if plan.kind == HttpBodyKind.ContentLength && plan.length > caps.max_body_bytes {
    return HttpError{kind: HttpErrorKind.LimitExceeded};
  }

  let declaration: HttpErrorKind? = (head).ValidateBodyPlan(plan.kind);
  if declaration != nil {
    return HttpError{kind: declaration as HttpErrorKind};
  }

  var phase: HttpWritePhase = HttpWritePhase.Data;
  if plan.kind == HttpBodyKind.Chunked {
    phase = HttpWritePhase.Ready;
  } else if plan.kind == HttpBodyKind.None
    || (plan.kind == HttpBodyKind.ContentLength && plan.length == 0u64) {
    phase = HttpWritePhase.Done;
  }

  return HttpBodyWriter{cell: new arc<HttpWriteData>{
    head: head,
    limits: caps,
    kind: plan.kind,
    remaining: plan.length,
    phase: phase
  }};
}

/**
 * @brief Transfer pending framing and payload progress, invalidating the source.
 * @returns The HttpBodyWriter value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpBodyWriter) operator move() -> HttpBodyWriter {
  let cell: arc<HttpWriteData>? = self.cell;
  self.cell = nil;

  return HttpBodyWriter{cell: cell};
}

/** @brief Release retained bounded metadata. */
pub method(HttpBodyWriter) operator drop() -> void {
  self.cell = nil;
}

/**
 * @brief Encode one framing or payload span, reporting exact accepted payload and generated wire
 *   bytes.
 * @returns Ok with HttpBodyProgress on success; Err with HttpError on the failure paths
 *   described above.
 * @note Input/output must not overlap. Retain the unconsumed payload suffix across calls;
 *   metadata may produce output with zero input consumed. No borrowed pointer survives the call.
 *   Offer only this body's bytes: excess fixed-length/no-body input is an error, not a
 *   next-message handoff. Errors are sticky, write no output in that call, and require discarding
 *   the connection. Generated output must be fully sent before generating more; transport
 *   acceptance is separate.
 */
pub method(HttpBodyWriter) Push(
  bytes: ref NetBytes,
  output: ref NetMutableBytes
) -> Result<HttpBodyProgress, HttpError> {
  if self.cell == nil {
    return HttpError{kind: HttpErrorKind.Closed};
  }

  var state: arc<HttpWriteData> = self.cell as arc<HttpWriteData>;
  if state.failure != nil {
    return state.failure as HttpError;
  }

  if state.finishing && bytes.Len() != (0ip) {
    return (state).Fail(HttpErrorKind.InvalidState);
  }

  if (state.kind == HttpBodyKind.None && bytes.Len() != (0ip))
    || (state.kind == HttpBodyKind.ContentLength && (bytes.Len() as uint64) > state.remaining) {
    return (state).Fail(HttpErrorKind.InvalidFraming);
  }

  if (bytes.Len() as uint64) > state.limits.max_body_bytes - state.decoded {
    return (state).Fail(HttpErrorKind.LimitExceeded);
  }

  if state.phase == HttpWritePhase.Done {
    return HttpBodyProgress{state: HttpBodyState.Complete};
  }

  if state.phase == HttpWritePhase.Ready {
    if bytes.Len() == (0ip) {
      return HttpBodyProgress{state: HttpBodyState.NeedInput};
    }

    if output.Len() == (0ip) {
      return HttpBodyProgress{state: HttpBodyState.NeedOutput};
    }

    var count: int32 = 16384;
    if bytes.Len() < count as intptr {
      count = bytes.Len() as int32;
    }

    let header: string = HttpChunkHeader{size: count}.Encode();
    if header.length - 2 > state.limits.max_line_bytes
      || header.length + 2 > state.limits.max_framing_bytes - state.framing_reserved {
      return (state).Fail(HttpErrorKind.LimitExceeded);
    }

    state.framing_reserved = state.framing_reserved + header.length + 2;
    state.remaining = count as uint64;
    state.pending = header;
    state.pending_pos = 0;
    state.phase = HttpWritePhase.Frame;
    state.after_frame = HttpWritePhase.Data;
  }

  if state.phase == HttpWritePhase.Frame {
    var count: int32 = state.pending.length - state.pending_pos;
    if output.Len() < count as intptr {
      count = output.Len() as int32;
    }

    if count == 0 {
      return HttpBodyProgress{state: HttpBodyState.NeedOutput};
    }

    let input: NetBytes = (NetBytes.FromString(state.pending).Slice(
      state.pending_pos as intptr,
      count as intptr
    ).get_if<NetBytes>()) as NetBytes;
    unsafe {
      memcpy(output.Data(), input.Data(), count as uintptr);
    }

    state.pending_pos = state.pending_pos + count;
    state.total = state.total + (count as int64);
    if state.pending_pos == state.pending.length {
      state.phase = state.after_frame;
      state.pending = "";
      state.pending_pos = 0;
      if state.phase == HttpWritePhase.Ready && state.finishing {
        state.pending = state.final_wire;
        state.final_wire = "";
        state.phase = HttpWritePhase.Frame;
        state.after_frame = HttpWritePhase.Done;
      }
    }

    var next: HttpBodyState = HttpBodyState.Progress;
    if state.phase == HttpWritePhase.Done {
      next = HttpBodyState.Complete;
    } else if state.phase == HttpWritePhase.Frame {
      next = HttpBodyState.NeedOutput;
    } else if bytes.Len() == (0ip) {
      next = HttpBodyState.NeedInput;
    } else if count as intptr == output.Len() {
      next = HttpBodyState.NeedOutput;
    }

    return HttpBodyProgress{produced: count as intptr, state: next};
  }

  if bytes.Len() == (0ip) {
    return HttpBodyProgress{state: HttpBodyState.NeedInput};
  }

  if output.Len() == (0ip) {
    return HttpBodyProgress{state: HttpBodyState.NeedOutput};
  }

  var count: intptr = bytes.Len();
  if count > output.Len() {
    count = output.Len();
  }

  if count >(2147483647ip) {
    count = 2147483647ip;
  }

  if state.kind != HttpBodyKind.UntilEof && (count as uint64) > state.remaining {
    count = state.remaining as intptr;
  }

  unsafe {
    memcpy(output.Data(), bytes.Data(), count as uintptr);
  }

  state.decoded = state.decoded + (count as uint64);
  state.total = state.total + (count as int64);
  if state.kind != HttpBodyKind.UntilEof {
    state.remaining = state.remaining - (count as uint64);
    if state.remaining == 0u64 {
      if state.kind == HttpBodyKind.ContentLength {
        state.phase = HttpWritePhase.Done;
      } else {
        state.pending = "\r\n";
        state.pending_pos = 0;
        state.after_frame = HttpWritePhase.Ready;
        state.phase = HttpWritePhase.Frame;
      }
    }
  }

  var next: HttpBodyState = HttpBodyState.Progress;
  if state.phase == HttpWritePhase.Done {
    next = HttpBodyState.Complete;
  } else if state.phase == HttpWritePhase.Frame {
    next = HttpBodyState.NeedOutput;
  } else if count == bytes.Len() {
    next = HttpBodyState.NeedInput;
  } else if count == output.Len() {
    next = HttpBodyState.NeedOutput;
  }

  return HttpBodyProgress{consumed: count, produced: count, state: next};
}

/**
 * @brief Close input and queue bounded chunk trailers; return whether all output is already
 *   generated.
 * @returns Ok with bool on success; Err with HttpError on the failure paths described above.
 * @note Fixed/chunk-announced payload shortage is terminal UnexpectedEof. Trailers require
 *   chunked framing, safe fields and matching Trailer declarations. Repeat only with an empty
 *   trailer list. Drain pending framing with Push(empty, output) until Complete. After UntilEof
 *   output drains, the caller must close the transport to delimit the message. No transport
 *   operation occurs here.
 */
pub method(HttpBodyWriter) Finish(trailers: ref <HttpField>[]) -> Result<bool, HttpError> {
  if self.cell == nil {
    return HttpError{kind: HttpErrorKind.Closed};
  }

  var state: arc<HttpWriteData> = self.cell as arc<HttpWriteData>;
  if state.failure != nil {
    return state.failure as HttpError;
  }

  if state.finishing {
    if trailers.length != 0 {
      return (state).Fail(HttpErrorKind.InvalidState);
    }

    return state.phase == HttpWritePhase.Done;
  }

  if (state.kind == HttpBodyKind.ContentLength || state.kind == HttpBodyKind.Chunked)
    && state.remaining != 0u64 {
    return (state).Fail(HttpErrorKind.UnexpectedEof);
  }

  if state.kind != HttpBodyKind.Chunked {
    if trailers.length != 0 {
      return (state).Fail(HttpErrorKind.InvalidFraming);
    }

    state.finishing = true;
    state.phase = HttpWritePhase.Done;

    return true;
  }

  if trailers.length > state.limits.max_trailers {
    return (state).Fail(HttpErrorKind.LimitExceeded);
  }

  var size: int32 = 5;
  var i: int32 = 0;
  while i < trailers.length {
    let field: HttpField = trailers[i];
    if !HttpLexeme.New(field.name).IsToken() || !HttpLexeme.New(field.value).IsFieldValue() {
      return (state).Fail(HttpErrorKind.Malformed);
    }

    if (state.head).ForbidsTrailer(field.name) || !(state.head).DeclaresTrailer(field.name) {
      return (state).Fail(HttpErrorKind.InvalidFraming);
    }

    if field.name.length > state.limits.max_line_bytes
      || field.value.length > state.limits.max_line_bytes - field.name.length - 2 {
      return (state).Fail(HttpErrorKind.LimitExceeded);
    }

    size = size + field.name.length + field.value.length + 4;
    i = i + 1;
  }

  if size > state.limits.max_framing_bytes - state.framing_reserved {
    return (state).Fail(HttpErrorKind.LimitExceeded);
  }

  var wire: StringBuffer = StringBuffer.NewWithCapacity(size);
  wire.Append("0\r\n");
  i = 0;
  while i < trailers.length {
    wire.Append(trailers[i].name);
    wire.Append(": ");
    wire.Append(trailers[i].value);
    wire.Append("\r\n");
    i = i + 1;
  }

  wire.Append("\r\n");
  state.final_wire = wire.Take();
  state.framing_reserved = state.framing_reserved + size;
  state.finishing = true;
  if state.phase == HttpWritePhase.Ready {
    state.pending = state.final_wire;
    state.final_wire = "";
    state.pending_pos = 0;
    state.phase = HttpWritePhase.Frame;
    state.after_frame = HttpWritePhase.Done;
  }

  return false;
}

/**
 * @brief Whether all wire bytes have been generated; this does not confirm transport delivery.
 * @returns Whether all wire bytes have been generated; this does not confirm transport delivery.
 */
pub method(HttpBodyWriter) IsComplete() -> bool {
  if self.cell == nil {
    return false;
  }

  let state: arc<HttpWriteData> = self.cell as arc<HttpWriteData>;

  return state.phase == HttpWritePhase.Done && state.failure == nil;
}
