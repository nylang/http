/** @brief Explicit bounded redirect decisions and immutable replay requests shared by TCP/HTTPS. */
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
import "interface/client.ni";
import "interface/url.ni";
/** @brief Resolve an ASCII URI-reference against this absolute URL using literal dot-segment removal.
 * @note Validates before normalization, never percent-decodes; fragments are validated then omitted.
 *       Empty/query/fragment references retain the appropriate base path/query. Strict URL host/port
 *       rules still apply; non-HTTP schemes, userinfo, IDNA and scoped IPv6 remain unsupported.
 */
pub method(HttpUrl) Resolve(reference: ref string) -> Result<HttpUrl, HttpError>;
/** @brief Compare canonical scheme, host and effective port; invalid URLs never match. */
pub method(HttpUrl) SameOrigin(other: ref HttpUrl) -> bool;
/** @brief Zero hop limit selects 5; hard cap 32. Following requires constructing a chain explicitly.
 * @note HTTPS downgrade is always rejected. Cross-origin follow defaults off; when enabled only
 *       Accept, Accept-Encoding, Accept-Language and User-Agent survive, plus Content-Type/Encoding
 *       for a preserved body. Credentials, cookies, Origin/Referer and arbitrary application fields
 *       are removed permanently. Origin includes scheme and effective port.
 *       Preserved bodies or methods other than GET/HEAD/OPTIONS require allow_unsafe_replay.
 */
pub struct HttpRedirectPolicy { max_redirects: int32; allow_cross_origin: bool; allow_unsafe_replay: bool; }
/** @brief Copyable immutable owned request snapshot; retained snapshots outlive chain changes/drop. */
pub struct HttpRedirectRequest;
/** @brief Validated URL for routing and certificate/SNI identity; invalid default returns an invalid URL. */
pub method(HttpRedirectRequest) Url() -> HttpUrl;
/** @brief Owned case-sensitive method, or empty for a default snapshot. */
pub method(HttpRedirectRequest) Verb() -> string;
/** @brief Owned validated HTTP/1.1 head including generated Host/Content-Length; default is empty. */
pub method(HttpRedirectRequest) Head() -> NetBuffer;
/** @brief Retain immutable request body storage; empty after a GET rewrite or on a default snapshot. */
pub method(HttpRedirectRequest) Body() -> NetBuffer;
/** @brief Additional field count excluding generated Host/Content-Length. */
pub method(HttpRedirectRequest) FieldCount() -> int32;
/** @brief Owned additional field, or InvalidArgument for a bad index/default snapshot. */
pub method(HttpRedirectRequest) FieldAt(index: int32) -> Result<HttpField, HttpError>;
/** @brief Copied original message/retention limits; default selects ordinary defaults. */
pub method(HttpRedirectRequest) Limits() -> HttpClientLimits;
/** @brief Copied original absolute deadline/shared token; modifying the copy never resets this snapshot. */
pub method(HttpRedirectRequest) Options() -> NetOperationOptions;
/** @brief Open an http snapshot using its original controls; reject https without network I/O. */
pub method(HttpRedirectRequest) OpenTcp(resolver: ref mut AsyncResolver, dial: ref HttpDialOptions) -> Result<HttpTcpClient, HttpClientError>;
/** @brief Move-only single-caller decision cursor; no automatic network I/O, cookie jar or socket reuse. */
pub struct HttpRedirectChain;
/** @brief Redirect cursors cannot be copied. */
pub method(HttpRedirectChain) operator copy() -> HttpRedirectChain = delete;
/** @brief Transfer current request, controls and decision state. */
pub method(HttpRedirectChain) operator move() -> HttpRedirectChain;
/** @brief Release retained request/metadata owners. */
pub method(HttpRedirectChain) operator drop() -> void;
/** @brief Validate and own one request plus policy before any network operation.
 * @note Copies borrowed method/field strings; retains immutable body owners under request backing
 *       limits. Fixed metadata is bounded by head limits. Caller-retained snapshots are outside chain
 *       budgets. One original absolute control budget applies to every hop; no deadline refresh.
 */
pub static method(HttpRedirectChain) New(url: ref HttpUrl, verb: ref string, fields: ref <HttpField>[], body: ref NetBuffer, limits: ref HttpClientLimits, policy: ref HttpRedirectPolicy, options: ref NetOperationOptions) -> Result<HttpRedirectChain, HttpClientError>;
/** @brief Retain current request, or original failure/InvalidState after a terminal response.
 * @note A snapshot may be explicitly replayed by its owner; the chain does not authorize I/O itself.
 */
pub method(HttpRedirectChain) Request() -> Result<HttpRedirectRequest, HttpClientError>;
/** @brief Decide from the current request's validated final response head, before any new I/O.
 * @returns True commits a new request; false finishes on nonredirect or missing Location; errors stick.
 * @note Follow only 301/302/303/307/308. 301/302 rewrite POST to GET; 303 rewrites except HEAD.
 *       Rewrites remove body and Content-* metadata. Preserved unsafe method/body requires opt-in.
 *       Duplicate Location is InvalidFraming; malformed Location never falls back to another field.
 *       HTTPS downgrade, disallowed cross-origin and unsafe replay use distinct protocol categories.
 *       Check original controls before decision/publication. Caller must associate the response with
 *       this hop, Close its old client on true/error, then open the new snapshot; do not drain or reuse
 *       its body/connection. On false, keep reading the terminal response normally. This API accepts
 *       heads, not body-completion attestation; transport errors are never interpreted as redirects.
 */
pub method(HttpRedirectChain) Follow(response: ref HttpHead) -> Result<bool, HttpClientError>;
/** @brief Number of committed redirects, excluding the initial request and rejected decisions. */
pub method(HttpRedirectChain) Count() -> int32;
