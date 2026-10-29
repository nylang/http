// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Explicit bounded redirect decisions and owned request snapshots shared by TCP/HTTPS. */
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/client.ni";
import "interface/url.ni";

/**
 * @brief Resolve an ASCII URI-reference against this absolute URL using literal dot-segment
 *   removal.
 * @returns Ok with HttpUrl on success; Err with HttpError on the failure paths described above.
 * @note Validates before normalization, never percent-decodes; fragments are validated then
 *   omitted. Empty/query/fragment references retain the appropriate base path/query. Strict URL
 *   host/port rules still apply; non-HTTP schemes, userinfo, IDNA and scoped IPv6 remain
 *   unsupported.
 */
pub method(HttpUrl) Resolve(reference: ref string) -> Result<HttpUrl, HttpError>;

/**
 * @brief Compare canonical scheme, host and effective port; invalid URLs never match.
 * @returns Compare canonical scheme, host and effective port; invalid URLs never match.
 */
pub method(HttpUrl) SameOrigin(other: ref HttpUrl) -> bool;

/**
 * @brief Zero hop limit selects 5; hard cap 32. Following requires constructing a chain
 *   explicitly.
 * @note HTTPS downgrade is always rejected. Cross-origin follow defaults off; when enabled only
 *   Accept, Accept-Encoding, Accept-Language and User-Agent survive, plus Content-Type/Encoding
 *   for a preserved body. Credentials, cookies, Origin/Referer and arbitrary application fields
 *   are removed permanently. Origin includes scheme and effective port. Preserved bodies or
 *   methods other than GET/HEAD/OPTIONS require allow_unsafe_replay.
 */
pub struct HttpRedirectPolicy {
  max_redirects: int32;
  allow_cross_origin: bool;
  allow_unsafe_replay: bool;
}

/** @brief Copyable immutable request metadata; retained snapshots outlive chain changes/drop. */
pub struct HttpRedirectRequest;

/**
 * @brief Validated URL for routing and certificate/SNI identity; invalid default returns an
 *   invalid URL.
 * @returns The HttpUrl value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpRedirectRequest) Url() -> HttpUrl;

/**
 * @brief Owned case-sensitive method, or empty for a default snapshot.
 * @returns Owned case-sensitive method, or empty for a default snapshot.
 */
pub method(HttpRedirectRequest) Verb() -> string;

/**
 * @brief Owned validated HTTP/1.1 head including generated URL routing/framing; default is
 *   empty.
 * @returns The NetBuffer value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpRedirectRequest) Head() -> NetBuffer;

/**
 * @brief Retain immutable buffered body storage; empty for streamed/default/GET-rewritten
 *   snapshots.
 * @returns The NetBuffer value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpRedirectRequest) Body() -> NetBuffer;

/**
 * @brief Additional field count excluding generated Host/framing.
 * @returns Additional field count excluding generated Host/framing.
 */
pub method(HttpRedirectRequest) FieldCount() -> int32;

/**
 * @brief Owned additional field, or InvalidArgument for a bad index/default snapshot.
 * @returns Ok with HttpField on success; Err with HttpError on the failure paths described
 *   above.
 */
pub method(HttpRedirectRequest) FieldAt(index: int32) -> Result<HttpField, HttpError>;

/**
 * @brief Copied original message/retention limits; default selects ordinary defaults.
 * @returns The HttpClientLimits value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpRedirectRequest) Limits() -> HttpClientLimits;

/**
 * @brief Copied original absolute deadline/shared token; modifying the copy never resets this
 *   snapshot.
 * @returns The NetOperationOptions value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpRedirectRequest) Options() -> NetOperationOptions;

/**
 * @brief Open an http snapshot using its original controls; reject https and streamed snapshots
 *   without network I/O.
 * @returns Ok with HttpTcpClient on success; Err with HttpClientError on the failure paths
 *   described above.
 */
pub method(HttpRedirectRequest) OpenTcp(
  resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions
) -> Result<HttpTcpClient, HttpClientError>;

/**
 * @brief Move-only single-caller decision cursor; no automatic network I/O, cookie jar or socket
 *   reuse.
 */
pub struct HttpRedirectChain;

/** @brief Redirect cursors cannot be copied. */
pub method(HttpRedirectChain) operator copy() -> HttpRedirectChain = delete;

/**
 * @brief Transfer current request, controls and decision state.
 * @returns The HttpRedirectChain value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpRedirectChain) operator move() -> HttpRedirectChain;

/** @brief Release retained request/metadata owners. */
pub method(HttpRedirectChain) operator drop() -> void;

/**
 * @brief Validate and own one request plus policy before any network operation.
 * @returns Ok with HttpRedirectChain on success; Err with HttpClientError on the failure paths
 *   described above.
 * @note Copies borrowed method/field strings; retains immutable body owners under request
 *   backing limits. Fixed metadata is bounded by head limits. Caller-retained snapshots are
 *   outside chain budgets. One original absolute control budget applies to every hop; no deadline
 *   refresh.
 */
pub static method(HttpRedirectChain) New(
  url: ref HttpUrl,
  verb: ref string,
  fields: ref <HttpField>[],
  body: ref NetBuffer,
  limits: ref HttpClientLimits,
  policy: ref HttpRedirectPolicy,
  options: ref NetOperationOptions
) -> Result<HttpRedirectChain, HttpClientError>;

/**
 * @brief Retain current request, or original failure/InvalidState after a terminal response.
 * @returns Ok with HttpRedirectRequest on success; Err with HttpClientError on the failure paths
 *   described above.
 * @note A snapshot may be explicitly replayed by its owner; the chain does not authorize I/O
 *   itself.
 */
pub method(HttpRedirectChain) Request() -> Result<HttpRedirectRequest, HttpClientError>;

/**
 * @brief Decide from the current request's validated final response head, before any new I/O.
 * @returns True commits a new request; false finishes on nonredirect or missing Location; errors
 *   stick.
 * @note Follow only 301/302/303/307/308. 301/302 rewrite POST to GET; 303 rewrites except HEAD.
 *   Rewrites remove body and Content-* metadata. Preserved unsafe method/body requires opt-in.
 *   Duplicate Location is InvalidFraming; malformed Location never falls back to another field.
 *   HTTPS downgrade, disallowed cross-origin and unsafe replay use distinct protocol categories.
 *   Check original controls before decision/publication. Caller must associate the response with
 *   this hop, Close its old client on true/error, then open the new snapshot; do not drain or
 *   reuse its body/connection. On false, keep reading the terminal response normally. This API
 *   accepts heads, not body-completion attestation; transport errors are never interpreted as
 *   redirects.
 */
pub method(HttpRedirectChain) Follow(response: ref HttpHead) -> Result<bool, HttpClientError>;

/**
 * @brief Number of committed redirects, excluding the initial request and rejected decisions.
 * @returns Number of committed redirects, excluding the initial request and rejected decisions.
 */
pub method(HttpRedirectChain) Count() -> int32;

/**
 * @brief Reject preserved-body replay by default, or require explicit caller-managed identical
 *   payload replay.
 * @note Neither value permits unsafe replay by itself: HttpRedirectPolicy.allow_unsafe_replay is
 *   also required for nonempty/chunked bodies and unsafe methods. No payload is buffered for
 *   replay.
 */
pub enum HttpBodyReplayPolicy {
  Never,
  Explicit
}

/**
 * @brief Own a streamed URL request's metadata and bounded redirect/replay policy without I/O.
 * @returns Ok with HttpRedirectChain on success; Err with HttpClientError on the failure paths
 *   described above.
 * @note Framing/limits match HttpUrl.StreamingRequestHead and the streamed exchange. Original
 *   controls apply to every decision/hop. Follow rejects preserved nonempty/chunked bodies under
 *   Never, even if no body bytes were sent. Explicit is an application promise to reproduce the
 *   same payload; manual callers must rewind before opening each accepted preserved-body snapshot.
 *   GET rewrites clear producer framing, Expect, Trailer and Content-* metadata without replay.
 *   Same-origin preserved streams retain Trailer. A Connection-nominated Trailer or cross-origin
 *   stream declaring trailers is ReplayRejected instead of silently losing their declaration.
 *   Other filtering, unsafe-method, downgrade and hop policies match immutable New.
 */
pub static method(HttpRedirectChain) NewStreaming(
  url: ref HttpUrl,
  verb: ref string,
  fields: ref <HttpField>[],
  plan: ref HttpBodyPlan,
  limits: ref HttpClientLimits,
  policy: ref HttpRedirectPolicy,
  replay: HttpBodyReplayPolicy,
  options: ref NetOperationOptions
) -> Result<HttpRedirectChain, HttpClientError>;

/**
 * @brief Whether this snapshot requires a producer; Body is empty even for a nonempty stream.
 * @returns Whether this snapshot requires a producer; Body is empty even for a nonempty stream.
 */
pub method(HttpRedirectRequest) IsStreaming() -> bool;

/**
 * @brief Streamed producer plan, or an empty plan for immutable/default snapshots.
 * @returns The HttpBodyPlan value described above, retaining the documented ownership and
 *   default-state semantics.
 */
pub method(HttpRedirectRequest) UploadPlan() -> HttpBodyPlan;

/**
 * @brief Open only a streamed http snapshot with its retained original controls.
 * @returns Ok with HttpTcpClient on success; Err with HttpClientError on the failure paths
 *   described above.
 * @note Caller prepares a fresh producer before every preserved-body replay. No implicit rewind.
 */
pub method(HttpRedirectRequest) OpenStreamingTcp(
  resolver: ref mut AsyncResolver,
  dial: ref HttpDialOptions,
  continue_wait_ms: int32
) -> Result<HttpTcpClient, HttpClientError>;
