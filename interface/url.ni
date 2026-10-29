// Copyright (c) 2026 tangxiangjiang
// SPDX-License-Identifier: MIT

/** @brief Strict absolute HTTP(S) URLs and deadline-aware connection orchestration. */
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/client.ni";

/** @brief Immutable owned validated URL; default is invalid and copies retain its storage. */
pub struct HttpUrl;

/**
 * @brief Parse at most 8192 ASCII bytes; only absolute http/https, LDH DNS and strict IP
 *   literals.
 * @note Reject userinfo, empty/zero ports, trailing-dot DNS, IDNA, zone IDs, legacy numeric IP,
 *   backslash and raw non-ASCII/control/space. Validate percent triplets; never decode them.
 *   Normalize scheme/host/IP/default port, default empty path to /, omit validated fragment.
 *   Preserve path/query octets, percent spelling, dot segments and an empty query delimiter.
 * @returns Owned URL or HttpError with an input byte offset when available.
 */
pub static method(HttpUrl) Parse(text: ref string) -> Result<HttpUrl, HttpError>;

/**
 * @brief Whether Parse created this value successfully.
 * @returns Whether Parse created this value successfully.
 */
pub method(HttpUrl) IsValid() -> bool;

/**
 * @brief Lowercase http/https, or empty for an invalid default.
 * @returns Lowercase http/https, or empty for an invalid default.
 */
pub method(HttpUrl) Scheme() -> string;

/**
 * @brief Canonical unbracketed DNS/IP host for resolution and certificate identity, or empty.
 * @returns Canonical unbracketed DNS/IP host for resolution and certificate identity, or empty.
 */
pub method(HttpUrl) Host() -> string;

/**
 * @brief Effective port, including default 80/443; zero for an invalid default.
 * @returns Effective port, including default 80/443; zero for an invalid default.
 */
pub method(HttpUrl) Port() -> int32;

/**
 * @brief Whether this URL requires verified TLS.
 * @returns Whether this URL requires verified TLS.
 */
pub method(HttpUrl) IsSecure() -> bool;

/**
 * @brief Canonical Host field, brackets for IPv6 and port only when nondefault; empty if
 *   invalid.
 * @returns Canonical Host field, brackets for IPv6 and port only when nondefault; empty if
 *   invalid.
 */
pub method(HttpUrl) HostField() -> string;

/**
 * @brief Origin-form path and optional query, without fragment; empty if invalid.
 * @returns Origin-form path and optional query, without fragment; empty if invalid.
 */
pub method(HttpUrl) Target() -> string;

/**
 * @brief Canonical absolute URL without fragment; empty if invalid.
 * @returns Canonical absolute URL without fragment; empty if invalid.
 */
pub method(HttpUrl) ToString() -> string;

/**
 * @brief Serialize one HTTP/1.1 request with generated Host and Content-Length.
 * @returns Ok with NetBuffer on success; Err with HttpError on the failure paths described
 *   above.
 * @note Additional fields must not supply Host, Content-Length or Transfer-Encoding. The
 *   connected profile rejects CONNECT/Expect/Upgrade before network I/O. Body length is plaintext
 *   bytes.
 */
pub method(HttpUrl) RequestHead(
  verb: ref string,
  fields: ref <HttpField>[],
  body_length: uint64
) -> Result<NetBuffer, HttpError>;

/**
 * @brief Zero max_addresses selects 16; hard cap 64. Dial returned addresses sequentially, in OS
 *   order.
 * @note Family defaults to Unspecified; no Happy Eyeballs, address sorting or per-address time
 *   reset.
 */
pub struct HttpDialOptions {
  family: IpFamily;
  max_addresses: int32;
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
) -> Result<TcpConnection, HttpClientError>;

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
) -> Result<HttpTcpClient, HttpClientError>;

/**
 * @brief Build an owned streamed HTTP/1.1 head with URL-derived Host and target.
 * @param plan None (zero length), ContentLength, or Chunked (zero length); close_connection must
 *   be false.
 * @returns Ok with NetBuffer on success; Err with HttpError on the failure paths described
 *   above.
 * @note None generates Content-Length: 0. Additional fields cannot override Host/framing or
 *   Upgrade. One case-insensitive Expect: 100-continue is allowed for nonempty fixed or chunked
 *   producers. Shared writer/exchange validation rejects unsupported negotiation before I/O. No
 *   body retained.
 */
pub method(HttpUrl) StreamingRequestHead(
  verb: ref string,
  fields: ref <HttpField>[],
  plan: ref HttpBodyPlan
) -> Result<NetBuffer, HttpError>;

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
) -> Result<HttpTcpClient, HttpClientError>;
