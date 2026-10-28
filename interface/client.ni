/** @brief Transport-independent single-exchange driver and connected TCP convenience client. */
import "stdlib:stdlib.ny";
import "net_core:net_core.ny";
import "interface/http.ni";
/** @brief Request/response framing limits; zero retained request budget selects 16 MiB, hard cap 1 GiB. */
pub struct HttpClientLimits { request_head: HttpHeadLimits; response: HttpResponseLimits; body: HttpBodyLimits; max_retained_request_bytes: int32; }
/** @brief Cursor stage identifying the origin of a protocol error offset. */
pub enum HttpClientStage { Request, ResponseHead, ResponseBody, Resolve, Connect }
/** @brief Pull events; NeedInput asks the transport for bytes, Complete never requests more I/O.
 * @note NeedBody is emitted by streamed connected TCP/HTTPS clients; supply one producer block or finish.
 *       NeedReplay is emitted only by optional streamed automatic-follow clients before opening a hop.
 */
pub enum HttpClientEventKind { NeedInput, Informational, Head, Body, Complete, NeedBody, NeedReplay }
/** @brief Committed plaintext HTTP wire counts, including head/framing bytes and unconsumed read suffixes. */
pub struct HttpClientStats { request_bytes_sent: uint64; response_bytes_received: uint64; }
/** @brief Owned head/body event; body chunks are at most 16 KiB and may be retained after client drop.
 * @note complete also applies to the last Body or a no-body Head. It means HTTP framing completion,
 *       not transport closure. Consumer-held event buffers are outside internal retention limits.
 */
pub struct HttpClientEvent { kind: HttpClientEventKind; head: HttpHead; buffer: NetBuffer; complete: bool; stats: HttpClientStats; }
/** @brief Move-only, single-caller exchange with bounded incoming/outgoing blocks and no transport operations. */
pub struct HttpClientExchange;
/** @brief Exchange cursors cannot be duplicated. */
pub method(HttpClientExchange) operator copy() -> HttpClientExchange = delete;
/** @brief Transfer the cursor, retained request and pending blocks. */
pub method(HttpClientExchange) operator move() -> HttpClientExchange;
/** @brief Release all retained request/framing storage. */
pub method(HttpClientExchange) operator drop() -> void;
/** @brief Validate and retain one HTTP/1.1 request head and immutable body before transport adoption.
 * @note Head must contain exactly one head, fixed length must match body, and no-body must be empty.
 *       Expect, Upgrade and CONNECT are unsupported. Request backing charges entire head/body owners,
 *       including slices; fixed parser storage and at most two 16 KiB blocks are outside that budget.
 *       Request upload precedes response reading; no early-final/100-continue upload gating is supplied.
 */
pub static method(HttpClientExchange) New(head: ref NetBuffer, body: ref NetBuffer, limits: ref HttpClientLimits) -> Result<HttpClientExchange, HttpError>;
/** @brief Owned unacknowledged wire suffix, at most 16 KiB; repeated calls preserve bytes until acknowledged.
 * @note Streaming output pauses for continue/response parsing or producer input; consult UploadState.
 *       An early final head revokes any unsent suffix. A previously retained output owner stays valid
 *       as data but must never be sent after revocation. No implicit transport cancellation occurs.
 */
pub method(HttpClientExchange) Output() -> Result<NetBuffer, HttpError>;
/** @brief Acknowledge only actual transport acceptance; invalid counts do not change the cursor.
 * @note Report every completed write before admitting/parsing a response. Do not leave unreported
 *       in-flight writes when parsing an early final response. Retire the transport after completion.
 */
pub method(HttpClientExchange) AcknowledgeOutput(count: intptr) -> Result<Unit, HttpError>;
/** @brief All request framing has been generated and acknowledged, not peer-acknowledged.
 * @note Streamed producers also finish explicitly. An early-stopped upload never reports success.
 */
pub method(HttpClientExchange) RequestComplete() -> bool;
/** @brief Admit one owned incoming block with visible and backing size at most 16 KiB; never overwrite unread input.
 * @note eof must mean ordinary TCP EOF or authenticated TLS close_notify, never a TLS failure.
 *       Streaming cursors admit responses once the entire head has been acknowledged, while the
 *       producer is still open. Drain received heads before further output; final heads stop upload.
 *       Admission failures leave pending input unchanged. Empty non-EOF input is a no-op.
 */
pub method(HttpClientExchange) Receive(buffer: ref NetBuffer, eof: bool) -> Result<Unit, HttpError>;
/** @brief Pull one informational/head/body/completion event or NeedInput.
 * @note Immutable requests require completed upload; streamed requests permit early responses after
 *       head acknowledgement. Only 100 releases Expect; drain buffered heads before writing again.
 * @note Protocol failures are sticky. Upgrade/tunnel responses are Unsupported. This exchange is never
 *       reusable: extra received bytes remain quarantined until drop. No pool/request queue is implemented.
 */
pub method(HttpClientExchange) NextResponse() -> Result<HttpClientEvent, HttpError>;
/** @brief Immutable validated request head, or Closed for a default cursor. */
pub method(HttpClientExchange) RequestHead() -> Result<HttpHead, HttpError>;
/** @brief Owned unbracketed request Host without port, or validation/closed failure. */
pub method(HttpClientExchange) AuthorityHost() -> Result<string, HttpError>;
/** @brief Current framing stage; default is Request. */
pub method(HttpClientExchange) Stage() -> HttpClientStage;
/** @brief Committed transport counts, including progress before failure. */
pub method(HttpClientExchange) Stats() -> HttpClientStats;
/** @brief Whether the response framing completed successfully. */
pub method(HttpClientExchange) IsComplete() -> bool;
/** @brief Completed response trailer count, pending InvalidState or terminal error. */
pub method(HttpClientExchange) TrailerCount() -> Result<int32, HttpError>;
/** @brief Owned response trailer after completion; no header merging. */
pub method(HttpClientExchange) TrailerAt(index: int32) -> Result<HttpField, HttpError>;
/** @brief Exactly one protocol/network error plus preserved stage and committed wire progress. */
pub struct HttpClientError { protocol_error: HttpError?; transport_error: NetError?; stage: HttpClientStage; stats: HttpClientStats; }
/** @brief Single-threaded, move-only connected TCP client for one request; no hidden workers or reuse. */
pub struct HttpTcpClient;
/** @brief Socket-owning clients cannot be copied. */
pub method(HttpTcpClient) operator copy() -> HttpTcpClient = delete;
/** @brief Transfer the owned connection and exchange. */
pub method(HttpTcpClient) operator move() -> HttpTcpClient;
/** @brief Close the connection and release retained request state. */
pub method(HttpTcpClient) operator drop() -> void;
/** @brief Validate first, then adopt connection on success; failures leave it untouched.
 * @note One copied absolute deadline/shared cancellation covers every Next call. Dial/DNS are outside
 *       this connected API; pass the original dial options to retain the same overall budget.
 */
pub static method(HttpTcpClient) New(connection: ref mut TcpConnection, head: ref NetBuffer, body: ref NetBuffer, limits: ref HttpClientLimits, options: ref NetOperationOptions) -> Result<HttpTcpClient, HttpClientError>;
/** @brief Drive one caller-thread exchange event; streamed clients may return NeedBody.
 * @note Immutable clients upload before reading. Streamed clients check early responses between writes.
 * @note Errors retire the connection and preserve committed counts. Successful completion is durable;
 *       later Next returns Complete without I/O until explicit Close. Close/drop after completion; the socket is not pooled.
 */
pub method(HttpTcpClient) Next() -> Result<HttpClientEvent, HttpClientError>;
/** @brief Completed response trailer count, or typed protocol failure. */
pub method(HttpTcpClient) TrailerCount() -> Result<int32, HttpClientError>;
/** @brief Owned response trailer field, or typed protocol failure. */
pub method(HttpTcpClient) TrailerAt(index: int32) -> Result<HttpField, HttpClientError>;
/** @brief Close once; prior failures and their committed progress remain stable. */
pub method(HttpTcpClient) Close() -> void;

/** @brief Streamed upload scheduling; response parsing takes priority over further request output.
 * @note NeedBody permits one bounded producer block or FinishBody; SendingBody may include framing.
 *       Finished means all request wire was acknowledged. Stopped means an early final response
 *       permanently suppressed the remaining upload, without claiming a completed request.
 */
pub enum HttpUploadState { SendingHead, ReadingResponse, WaitingContinue, NeedBody, SendingBody, Finished, Stopped }
/** @brief Construct a transport-independent streamed request, retaining no complete body.
 * @note Supports fixed/chunked framing and one strict case-insensitive Expect: 100-continue field.
 *       Expect requires a nonempty fixed body or chunked producer. Other expectations are Unsupported.
 *       Each supplied immutable owner is at most 16 KiB including its backing allocation. Head and
 *       current payload obey max_retained_request_bytes; body limits count cumulative supplied bytes.
 *       Callers drive reads and writes, retain original controls and never reuse the connection.
 *       Existing immutable clients and automatic redirect snapshots do not use this constructor.
 */
pub static method(HttpClientExchange) NewStreaming(head: ref NetBuffer, limits: ref HttpClientLimits) -> Result<HttpClientExchange, HttpError>;
/** @brief Scheduling state for a streamed cursor, or Closed/InvalidState for a default/immutable cursor. */
pub method(HttpClientExchange) UploadState() -> Result<HttpUploadState, HttpError>;
/** @brief Admit one nonempty immutable body block when NeedBody; failures do not change producer state.
 * @note Empty, oversized/backing-heavy, over-length or over-budget input fails before adoption. Keep
 *       calling Output/AcknowledgeOutput to drain it. No producer callback, hidden queue or replay.
 */
pub method(HttpClientExchange) SupplyBody(buffer: ref NetBuffer) -> Result<Unit, HttpError>;
/** @brief Close the producer after its last block drains, and queue validated chunk trailers.
 * @note A fixed-length shortage or invalid trailer makes the exchange fail. Empty chunked content
 *       with Expect is InvalidFraming. Repeated finish accepts only an empty trailer list. Drain final
 *       framing with Output/AcknowledgeOutput; Finish alone never means wire delivery.
 */
pub method(HttpClientExchange) FinishBody(trailers: ref <HttpField>[]) -> Result<Unit, HttpError>;
/** @brief Explicitly release a pending 100-continue gate after a caller-bounded wait.
 * @note No I/O, clock or deadline refresh. The caller must not wait indefinitely, must first drain
 *       received informational/final heads, and retains its original absolute control budget. A parsed
 *       100 releases the same gate automatically; an early final response never permits resuming.
 */
pub method(HttpClientExchange) ContinueUpload() -> Result<Unit, HttpError>;

/** @brief Validate and adopt a TCP connection for bounded producer-driven upload.
 * @param continue_wait_ms Finite 0..60000 ms fallback measured once after head acknowledgement;
 *        zero releases immediately after draining any available response. Only used with Expect.
 * @note Next emits NeedBody when one block or FinishBody is required. It probes available response
 *       input before requesting/sending body and waits for either readability or writability under
 *       upload backpressure. Parsed partial heads pause upload; final heads revoke unsent bytes.
 *       Actual socket acceptance is acknowledged before response parsing. A response racing a write
 *       may arrive after that write commits; accepted bytes cannot be revoked. No retry or replay.
 *       Caller time between methods remains inside the original absolute control budget.
 */
pub static method(HttpTcpClient) NewStreaming(connection: ref mut TcpConnection, head: ref NetBuffer, limits: ref HttpClientLimits, options: ref NetOperationOptions, continue_wait_ms: int32) -> Result<HttpTcpClient, HttpClientError>;
/** @brief Streamed producer state, with preserved typed error/progress; immutable clients return InvalidState. */
pub method(HttpTcpClient) UploadState() -> Result<HttpUploadState, HttpClientError>;
/** @brief Supply one bounded immutable producer owner after NeedBody; rejected admission is nonterminal.
 * @note No I/O or hidden queue. A later Next checks responses before writing this block.
 */
pub method(HttpTcpClient) SupplyBody(buffer: ref NetBuffer) -> Result<Unit, HttpClientError>;
/** @brief Finish a drained producer and queue final framing/trailers; shortages retire the connection.
 * @note No I/O, deadline refresh or replay. Drive Next until response completion, then Close/drop.
 */
pub method(HttpTcpClient) FinishBody(trailers: ref <HttpField>[]) -> Result<Unit, HttpClientError>;
