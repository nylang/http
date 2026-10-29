# http

Independent MIT-licensed Nyra HTTP package. The protocol core consumes public
net_core byte ranges, writes heads into owned NetBuffers and decodes bodies into
caller-owned output. The protocol core has no transport operations or TLS
dependency. Its connected TCP client and the optional sibling
[http_tls](https://github.com/nylang/http_tls/blob/main/README.md) HTTPS adapter share one exchange engine.

## Implemented foundation

- HTTP/1.0 and HTTP/1.1 request/response head parsing across arbitrary fragments.
- Byte-oriented CRLF handling, token/field validation and opaque obs-text values.
- Default limits: 32 KiB total head, 8 KiB per line, 100 fields; configurable
  hard ceilings: 1 MiB, 64 KiB, 128 fields. No body is allocated from a length field.
- Immutable owned metadata, ordered duplicate ordinary fields, move-only parser.
- Exact consumed-prefix counts: body, pipeline, upgrade and tunnel bytes remain
  with the caller. Incomplete EOF and protocol errors are terminal.
- Framing plans for fixed length, chunked, close-delimited, no-body, upgrade and
  CONNECT success, including case-sensitive HEAD request context and persistence.
- Validated HTTP/1.1 request/response head writing into independent owned buffers.
- Fixed-length, chunked and EOF-delimited body decoding, with no whole-body buffering.
- Exact consumed/produced counts, explicit output backpressure, sticky truncation/errors.
- Overflow-safe chunk sizes, validated ignored extensions, separate owned ordered trailers.
- Streaming body writing into borrowed caller output, with exact payload acceptance,
  at most 16 KiB per generated chunk, partial framing and one terminal chunk.
- Bounded informational response events followed by one final/101 head, retaining
  originating request-method context and exact body/tunnel suffix ownership.
- Default body limits: 16 MiB decoded bytes, 1 MiB cumulative framing bytes, 8 KiB
  per size/trailer line and 100 trailers. Hard caps: 9223372036837998591 decoded
  bytes, 16 MiB framing, 64 KiB per line and 128 trailers. Framing includes every
  size line, data CRLF and trailer line, preventing unbounded extension overhead.

This is a strict profile based on [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html):
reject duplicate Content-Length (even identical), comma-separated lengths,
Transfer-Encoding/Content-Length conflicts, duplicate Transfer-Encoding, obsolete
folding, whitespace before a field colon, bare LF and forbidden control bytes.
Only a single `chunked` transfer coding is recognized. Framing fields on 1xx/204
and successful CONNECT are rejected. Other transfer codings are Unsupported.

Request targets currently support origin-form and `OPTIONS *`, not proxy absolute
or CONNECT authority forms. Host validation accepts an ASCII reg-name subset or
bracketed IPv6 with an optional 0..65535 port; zone IDs, userinfo, whitespace,
percent-encoded hosts and other URI-host forms are unsupported. A Host is mandatory
exactly once for HTTP/1.1 requests. These are deliberate first-phase limits, not a
claim of complete URI or HTTP conformance.

`HttpBodyDecoder` accepts a validated head, rejects oversized fixed lengths before
payload processing and handles raw payload octets without decompression. Trailers
never merge into the head and remain unavailable until the final empty line.
Known framing/routing/control, authentication, representation and cookie fields
are rejected, as are Connection-nominated names. Unknown trailer fields are raw
untrusted metadata requiring application-specific interpretation. No declaration
in the Trailer head field makes a protected trailer safe.

Body writing uses the same decoded/framing/line/trailer budgets. Generated
chunk-size lines are canonical lowercase hex without extensions. Trailer output
requires safe field names declared in the head's Trailer fields; this is a strict
sender profile. Supplied fixed-length/no-body excess is rejected, not silently
left as a next-message suffix. A short fixed body or an abandoned announced chunk
fails with UnexpectedEof. Unknown-length streaming never retains the payload.

Response sequencing follows [RFC 9110 informational semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2):
every 100..199 except 101 is an observable intermediate head, including unknown
1xx codes. A 101 ends HTTP head sequencing as an explicit handoff, without claiming
that upgrade negotiation succeeded. Zero response limits select 16 informational
heads and 1 MiB cumulative head bytes; hard caps are 64 heads and 16 MiB. Per-head
limits remain active, and aggregate bytes include the final head. EOF before a
final/101 head is terminal even after complete informational responses.

Automatic redirect following is available through the optional
[http_tls facade](https://github.com/nylang/http_tls/blob/main/README.md#automatic-redirects). IDNA, connection
pooling, HTTP/2 and HTTP/3 remain future work. Strict URL orchestration and
explicit redirect decisions are described below.
Upgrade/Tunnel is an explicit handoff; body construction rejects these plans.
Content-Length metadata can span uint64; decoder construction applies its own
budget and does not allocate that length.

## Connected single-request clients

`HttpClientExchange` drives one validated HTTP/1.1 request and response without
transport operations. Supply an immutable head buffer containing exactly one
head and a bounded immutable body. Fixed Content-Length must match that body;
chunked upload is framed by the shared writer. The default retained request
budget is 16 MiB (hard cap 1 GiB), charging entire buffer owners even for slices.
The immutable connected API buffers request bodies; response bodies stream in owned chunks
of at most 16 KiB. The separate streamed constructor is described below.

Drain `Output()` and acknowledge only actual transport acceptance using
`AcknowledgeOutput()`. The unacknowledged suffix stays stable. After
`RequestComplete()`, feed `Receive()` blocks with visible and backing lengths
at most 16 KiB, then call `NextResponse()` until `NeedInput` or completion.
Events carry owned informational/final heads or body chunks. `complete` may be
set on a no-body Head or the last Body. Only signal EOF after ordinary TCP EOF
or authenticated TLS close_notify. Protocol failures are sticky; invalid input
admission and acknowledgement counts leave cursors unchanged.

`HttpTcpClient.New(connection, head, body, limits, options)` validates before
adopting an already connected socket on success. `Next()` uploads the request,
then synchronously pulls one response event on the caller thread. One copied
absolute deadline and shared cancellation cover all calls; pass the original
dial options to retain an overall budget. Controls are checked even for buffered
response bytes before publication. Errors close the connection and retain the
original typed cause, framing stage and committed wire counts. Counts describe
HTTP plaintext acceptance/receive progress, not peer acknowledgement. Response
trailers are available separately after completion.

Completion remains observable without new I/O until explicit `Close()` or drop.
Connections are never reused or pooled; any received suffix is quarantined.
The immutable constructor rejects Expect/100-continue. CONNECT
and Upgrade requests are unsupported. A 101/tunnel response fails rather than
transferring the live socket. Close/drop after consuming the response. HTTPS
adds verified identity, ALPN and explicit graceful shutdown in the sibling
adapter while keeping plain HTTP free of TLS link inputs.

## Absolute URLs and opening connections

`HttpUrl.Parse(text)` returns an immutable owned absolute HTTP/HTTPS URL. It
accepts at most 8192 ASCII bytes, strict IPv4/bracketed IPv6 or LDH DNS labels,
and ports 1..65535. Scheme and DNS case are normalized, IP text is canonical,
default ports disappear from Host, and an empty path becomes `/`. Validated
fragments are omitted. Path/query octets, percent spelling, dot segments and an
empty query delimiter are preserved; escapes are validated but never decoded.
This follows the component boundaries of
[RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html) and the
[HTTP URL schemes](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2),
with a deliberately strict profile. Userinfo, trailing-dot DNS, zone IDs, IDNA,
legacy/ambiguous numeric IP spelling, raw spaces/controls/backslash/non-ASCII,
empty/zero ports and malformed escapes fail explicitly. `HttpUrl.Resolve` separately implements strict relative-reference resolution;
no general percent/dot-segment equivalence comparison is provided.

`Host()`, `Port()`, `HostField()` and `Target()` derive resolution, request
routing and HTTPS verification from one validated value. `RequestHead(verb,
fields, body_length)` generates Host and Content-Length and rejects caller Host,
Content-Length, Transfer-Encoding, Expect and Upgrade overrides. CONNECT and
header/method injection fail before network use.

Create a caller-owned `AsyncResolver.New(worker_count, max_pending)` and pass
it to `HttpTcpClient.Open(url, verb, fields, body, limits, resolver, dial,
options)` for an http URL. The complete buffered request is validated before
DNS/connect. An https URL is rejected; use `HttpsClient.Open` from http_tls.
`HttpUrl.Dial(resolver, dial, options)` is also available for callers assembling
the connected flow themselves; it sends no HTTP or TLS bytes.

`HttpDialOptions` selects an IP family and maximum results (zero selects 16,
hard cap 64). Numeric IPs bypass DNS; family mismatch fails. DNS uses the explicit
resolver pool and a call-local event loop waiting for notifications, with no busy
loop or blocking synchronous DNS fallback. Returned addresses are tried in OS
order, sequentially, under the same original absolute deadline/cancellation used
by later client operations. There is no per-attempt time reset, Happy Eyeballs or
address sorting. Failures retain Resolve/Connect stage and the original network
cause; a final control check precedes success/error publication.

The resolver remains caller-owned. A control error can return while the OS
lookup is still blocked: its bounded resolver slot remains charged until the
worker finishes and the caller polls it. Cancellation does not forcibly interrupt
OS DNS. Close the resolver when finished, or keep polling it before reusing its
capacity. No hidden DNS pool is allocated per request. All pool/Future/client
methods run on one caller thread; only shared cancellation may cross threads.

## Explicit redirects and replay requests

`HttpUrl.Resolve(reference)` resolves absolute/network-path, relative-path,
rooted, query-only, empty and fragment-only references using
[RFC 3986 resolution](https://www.rfc-editor.org/rfc/rfc3986.html#section-5.2).
It validates raw components before removing literal dot segments, preserves
percent escapes without decoding, and omits validated fragments. Empty-path
references keep the base path/query as appropriate, including any existing dot
segments. Strict HTTP URL authority/port rules still apply. `SameOrigin` compares
canonical scheme, host and effective port, independently of the selected address.

Construct `HttpRedirectChain.New(url, verb, fields, body, limits, policy, options)`
to opt into redirect decisions. It validates before I/O, copies borrowed method
and field strings, and retains a bounded immutable body. `Request()` yields a
copyable `HttpRedirectRequest`: URL, method, generated head, body, additional
fields, original limits and original absolute controls are immutable snapshots.
Snapshots can outlive chain mutation/drop; consumer-held snapshots are outside
chain retention budgets. Retaining a snapshot does not authorize automatic I/O.

Open the snapshot using `request.OpenTcp(resolver, dial)` or the sibling
`HttpsClient.OpenRequest(request, config, resolver, dial)`. Pull ordinary client
events. On its final Head, call `chain.Follow(head)` exactly once for this hop:

- True commits the next request. Close the old client immediately, without
  draining or reusing its response body/connection, then open the next snapshot.
- False means a terminal response. Continue reading that client's body normally.
  A redirect status with no Location is observable as a terminal response.
- An error retires the chain. Close the old client; the original failure stays
  available and no new request may be obtained from that cursor.

This is a caller-driven coordinator, not an automatic-follow client or a socket
pool. Callers associate the head with the correct hop, select TCP/HTTPS from the
next URL and preserve old event progress. Policy errors have zero transport
counts: the decision cursor performs no transfers. Each client event/error keeps
its own hop's actual wire progress. Network/TLS errors are never interpreted as
redirects or retried by this API. A redirect body above the connected decoder's
head-time body cap can fail before the coordinator sees that head.

Only 301/302/303/307/308 are followed. The strict sender policy follows
[HTTP redirect semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4):
301/302 POST becomes GET; 303 becomes GET except HEAD. Rewrites drop the body,
Content-* fields and legacy Digest/Want-Digest, then regenerate Content-Length.
Preserving a nonempty body or any method other than GET/HEAD/OPTIONS requires
`allow_unsafe_replay`; 307/308 never silently turn POST into GET. Method matching
is case-sensitive. No external body producer, cookie jar or credential callback
is replayed.

`HttpRedirectPolicy.max_redirects` defaults to five with a hard cap of 32; cycles,
empty Location and fragment-only self redirects consume that budget. Duplicate
Location fails with InvalidFraming; malformed references are terminal. HTTPS to
HTTP always fails with InsecureRedirect. Cross-origin follow defaults off and
fails with CrossOriginRedirect. If enabled, only Accept, Accept-Encoding,
Accept-Language and User-Agent survive, plus Content-Type/Encoding for preserved
bodies. Authorization, cookies, Origin/Referer and all arbitrary application
headers are removed permanently, even when returning to the initial origin.
Connection/hop fields and all Connection-nominated fields are removed on every
hop. A preserving replay without permission fails with ReplayRejected; exhausted
hop budgets use RedirectLimit. Original cancellation/expiry is checked before
decisions and publication, and no hop refreshes the deadline.

[Redirect acceptance](docs/redirect-acceptance-2026-10-27.json) records 76 core
cases/replays per desktop host, including the URI-reference example matrix,
status/method policy matrix, ownership, controls and credential filtering. Twelve
TCP and thirteen HTTPS multi-hop scenarios use ordinary native inputs and verify
exact request headers/body bytes, old-socket retirement without draining the
advertised body, explicit replay, cross-port filtering, rejection paths and
normal terminal body/shutdown. The previous 82 network/control scenarios also run.

## Use and verification

Import `http:http.ny`, `net_core:net_core.ny` for its public byte types, and stdlib.
Create `HttpHeadParser.NewRequest(HttpHeadLimits{})` or
`NewResponse("GET", HttpHeadLimits{})`, move the successful Result value, then
call `Push(bytes)`. Use its consumed count to retain the remaining suffix.
`Head()` publishes metadata only after `IsComplete()`. A pending `Head()` query
returns InvalidState without terminating parsing. `EndInput()` marks truncated
heads as UnexpectedEof. Discard the connection on parser failure.

Create `HttpBodyDecoder.New(head, HttpBodyLimits{})` and move the successful
Result value. Call `Push(input, output)` with non-overlapping borrowed ranges.
Each call returns `HttpBodyProgress`: retain the unconsumed input suffix and only
read the produced output prefix. A call copies at most one contiguous payload
span; `Progress` requests another call, `NeedInput` requests more input,
`NeedOutput` requests output capacity, and `Complete` preserves the next message.
Empty output permits framing-only progress. An error writes no output during
that call; discard the connection, and treat earlier body output as incomplete.
Call `EndInput()` only after feeding all received bytes: it completes EOF bodies
and rejects other incomplete framing. Neither borrowed pointer survives a call.

For output, create `HttpBodyWriter.New(head, limits)` before sending the head.
`Push(payload, output)` reports accepted payload bytes and generated wire bytes;
metadata-only output can consume zero payload. Retain the unconsumed payload
suffix, and fully send generated output before generating more. `Finish(trailers)`
closes input and queues terminal framing; then drain with `Push(empty, output)`.
Only empty trailer lists are permitted on repeated Finish calls. `IsComplete()`
means all wire bytes were generated, not delivered. EOF-delimited output requires
actual transport closure after draining. Writer errors generate no output in the
failing call; discard the connection, preserving earlier accepted-byte progress.

For a response sequence, create `HttpResponseParser.New(method, limits)`, then
loop over `Push` using its consumed count. At Informational/Final, `Head()` returns
an owned event head. Retain it before the next nonempty Push; starting a new head
clears stale event publication. Empty input preserves the most recent event.
`IsComplete()` means the final/101 head completed, not its body. Transfer the
remaining input to `HttpBodyDecoder`, or to the explicit upgrade/tunnel owner.
No request queue, deadline handling or connection-pool policy is supplied here.

Run the supplied SDK acceptance with outputs outside this package:

```sh
python3 scripts/accept.py --sdk /path/to/sdk --compiler /path/to/native-candidate \
  --net-core ../net_core --out-dir /external/cache/http-acceptance
```

The acceptance runner disables runtime source fallback, runs all discovered cases
and isolated replays, builds an independent imported consumer, and precompiles
production code while rejecting test/TLS undefined symbols. No OpenSSL inputs are
linked. See [tests](tests/README.md), [framing acceptance](docs/framing-acceptance-2026-10-27.json)
and [roadmap](ROADMAP.md). The source repository is public; no versioned
package/binary release or SDK promotion is established by these results.
The NyraLang parent records this independent repository as a submodule.

Connected-client acceptance also builds independent TCP/HTTPS consumers and
controlled loopback peers. Supply the pinned OpenSSL static build only for HTTPS:

```sh
python3 scripts/accept_clients.py --sdk /path/to/sdk --compiler /path/to/native-candidate \
  --http-tls ../http_tls --tls ../tls --openssl-root /path/to/openssl-3.5.9 \
  --out-dir /external/cache/http-clients
```

Omit the three TLS arguments for TCP-only acceptance. `--openssl-cli` optionally
selects the certificate fixture generator; its identity is recorded separately
from the pinned client libraries. See [client acceptance](docs/client-acceptance-2026-10-27.json).

The subsequent [URL/DNS acceptance](docs/url-acceptance-2026-10-27.json) records
67 core cases/replays, 27 TCP and 35 HTTPS live scenarios, plus 9 TCP and 11 HTTPS
controlled URL/DNS failure cases per accepted desktop host.

Run the complete redirect increment, including the preceding acceptance suites:

```sh
python3 scripts/accept_redirects.py --sdk /path/to/sdk --compiler /path/to/native-candidate \
  --http-tls ../http_tls --tls ../tls --openssl-root /path/to/openssl-3.5.9 \
  --out-dir /external/cache/http-redirects
```


Automatic-follow acceptance composes those same protocol and explicit-redirect
suites with TCP/HTTPS routing through the optional adapter:

```sh
python3 scripts/accept_follow.py --sdk /path/to/sdk-1.0.2 --compiler /path/to/sdk-1.0.2/hosts/HOST/bin/nyrac \
  --openssl-root /path/to/openssl-3.5.9 --out-dir /external/cache/http-follow
```

`HttpFollowClient` owns its chain and current connection, retains the original
control budget, and borrows the caller's resolver in each `Next`. It retires old
connections without draining their bodies, follows accepted snapshots, and
publishes terminal heads/body/trailers. Plain http remains independent of TLS.
See the [facade contract](https://github.com/nylang/http_tls/blob/main/interface/follow.ni) for event, error and
shutdown ownership.


[Four-host automatic-follow acceptance](docs/follow-acceptance-2026-10-28.json)
passes against exact public SDK 1.0.2 compilers/runtimes on macOS arm64, Linux
x86_64, Windows x86_64 and physical Intel macOS x86_64. Each host passes 76 core
cases and 76 isolated replays plus 133 network/control scenarios, including the
26 automatic-follow scenarios. Sources match across hosts; compilers and 346
native runtime files per host match their pinned SDK manifests. Linux executes
inside Ubuntu 24.04.5/glibc 2.39 container userspace. Mobile support, broader fault
matrices, streaming request producers, pooling and independent publication remain
separate work under the roadmap.

## Streamed exchange and early responses

`HttpClientExchange.NewStreaming(head, limits)` validates a request head without
retaining a complete body. This is an explicit transport-driver API. The existing
Immutable TCP/HTTPS constructors and automatic redirect snapshots keep their
immutable request contract; they do not call this constructor.

After `Output` and exact `AcknowledgeOutput` calls send the head, inspect
`UploadState`. At `NeedBody`, supply one nonempty immutable `NetBuffer` with
`SupplyBody`. Its entire backing allocation must be at most 16 KiB and fit the
request retention budget. Drain output before supplying another block. The body
limit counts cumulative payload, so it cannot be bypassed by splitting input.
`FinishBody(trailers)` closes a drained producer and queues final chunk framing;
fixed-length producers must supply the declared total. Call Output/Acknowledge
until RequestComplete. No-body requests finish after head acknowledgement
without an artificial producer callback. Generated or queued bytes never count
as sent.

The streaming profile accepts one case-insensitive `Expect: 100-continue` field
with nonempty fixed content or a chunked producer. After sending the head,
`WaitingContinue` suppresses body admission/output. Informational responses remain
observable; only status 100 releases the gate. A driver can instead call
`ContinueUpload` after its own bounded wait. The exchange has no clock and never
refreshes a deadline: keep one original absolute control budget across that wait
and every transport operation. See [RFC 9110 Expect](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.1).
Unknown/duplicate expectations and expectations on a known-empty body are rejected.
An Expect chunked producer cannot finish with zero content.

A streamed cursor admits response input once the entire head is acknowledged,
including during upload. Drain buffered heads before producing more output;
`ReadingResponse` also pauses output while a response head is incomplete. This
prevents a buffered final response behind 100 from being ignored. Every parsed
final response stops unfinished upload, discards its queued unsent suffix, and
leaves its response body/trailers readable. `Stopped` never reports
RequestComplete, even if IsComplete says the response finished. A 417 response is
observable and never triggers a hidden retry or producer replay.

The driver must report all completed writes before admitting/parsing a response
and must not leave unreported writes in flight. Previously returned output owners
remain valid data after suppression or drop, but revoked bytes must not be sent.
Stats retain actual acknowledged per-request wire counts. The driver must retire
the connection after this exchange; no reuse or upgrade ownership is added.
Only ordinary TCP EOF or authenticated TLS close_notify can be passed as EOF.

`scripts/accept_upload.py` repeats existing protocol and client acceptance, then
runs explicit TCP and verified TLS test drivers over the public exchange. Those
drivers demonstrate transport composition; they are not a new convenience client
or a duplex TLS API. The connected TCP/HTTPS facades and explicit streamed
redirect replay described below were added after that raw-exchange snapshot.
No implicit producer rewind callback is supplied.


The [H3e acceptance](docs/upload-acceptance-2026-10-28.json) passes on macOS arm64,
physical Intel macOS x86_64, Linux x86_64 and Windows x86_64 using matching public
SDK 1.0.2: 88 core cases, 88 isolated replays and 151 network/control scenarios
per host, including 18 streamed-driver scenarios. Source inventories match across
hosts; compilers and all 346 native-host runtime files match each SDK manifest.
The Windows record retains an initial unconfirmed automatic-follow timeout and
the corrected intentional-abort fixture history. No cases or timing budgets were
relaxed. These historical receipts establish H3e, not the later TCP facade.
Broader fault matrices and package publication remain separate work.


## Producer-driven connected TCP upload

`HttpTcpClient.NewStreaming(connection, head, limits, options, continue_wait_ms)`
validates a streamed exchange and a finite 0..60000 ms continue fallback before
adopting the socket. It retains one original absolute deadline/cancellation token.
It has no hidden worker, producer callback, retry, replay or connection reuse.

Call `Next()` until an event arrives. `NeedBody` asks the caller to either supply
one nonempty immutable owner using `SupplyBody(buffer)` or finish the drained
producer using `FinishBody(trailers)`. Fixed lengths must match exactly; chunked
uploads can carry declared safe trailers. The existing exchange's 16 KiB owner
bound, backing-allocation charge, retained budget and cumulative body limit apply.
Rejected producer admission leaves the slot unchanged. A terminal framing failure
such as a fixed-length shortage closes the connection and preserves progress.
`UploadState()` distinguishes completed request framing from an early-stopped
upload; response completion alone does not assert complete request delivery.
For fixed lengths, a final response can also race the explicit producer finish
just after the last payload byte: the unfinished producer then reports Stopped
while stats still include the entire accepted payload.

The facade drains buffered response events and probes readable input before each
producer demand or body write. When a write would block, it registers both read
and write readiness. Each wait owns at most two registrations and retires both
before socket access or event publication. No unreported asynchronous write is
left in flight. A final response suppresses unsent body bytes; bytes already
accepted by TCP remain counted and cannot be revoked. Response/write races can
therefore commit a prefix before the response is observed.

With Expect, the fallback clock starts once after complete head acknowledgement.
Only 100 releases the gate automatically; 103 does not restart the timer. At
fallback expiry, available input is checked before upload resumes. A partial
response head pauses output even beyond the continue fallback, under the original
overall deadline. Caller time spent producing data also consumes that deadline.
There is no I/O while the caller owns control between method calls. Completion
remains durable without I/O, even if the original control later expires.

This increment is the connected plain TCP facade. URL convenience constructors
and automatic redirect snapshots still use immutable bodies. The optional
[HTTPS adapter](../http_tls/README.md#local-development-streamed-connected-https)
now adds a separate connected streamed path. The published TLS stream retains
its one-pending-operation contract; the new optional channel and explicit
producer replay policy remain separate from those immutable APIs.


[Connected TCP facade acceptance](docs/tcp-upload-acceptance-2026-10-28.json)
records matching public SDK 1.0.2 on macOS arm64, native Intel macOS x86_64,
Linux x86_64 and Windows x86_64. Each passes 88 core cases, 88 isolated replays
and 165 network/control scenarios, including the 14 new facade scenarios and
all 151 prior TCP/TLS/DNS/redirect scenarios. Each compiler and 346 native runtime
files match its pinned SDK manifest. The final fixture handles the documented
fixed-length producer-finish race; both initial and final full matrices passed
with unchanged product sources and timing budgets. This is local source
acceptance for that earlier TCP increment. Later HTTPS acceptance is recorded
separately; independent package release remains open.

## Portable source dependencies

Repository: <https://github.com/nylang/http>. The source manifest uses implicit
SDK stdlib and public HTTPS Git dependencies pinned to exact commits. A private
NyraLang checkout and sibling dependency directory names are not required.
Native networking adapters and, for HTTPS, the pinned TLS/OpenSSL libraries
still require the documented platform build/link setup. Fetching Nyra package
sources does not build or link those native libraries.

```yaml
dependencies:
  http:
    git: https://github.com/nylang/http.git
    rev: main
```

Native `nyra` 1.0.3 or later handles explicit dependency acquisition. Use
`nyra lock ./app` to pin the initial branch selector, commit `nyra.lock`, then
`nyra fetch ./app --frozen` for repeatable preparation. Normal compilation and
analysis never fetch. The native manager's public SDK delivery is separate;
published SDK 1.0.2 does not include it. SDK 1.0.3 v2 locked SDK-runtime loading
requires the `buglist.sdk_portable_lock` compiler follow-up; the unchanged
accepted bootstrap does not include that follow-up.

For local development, map these package names to editable entries in a common
`workspace.yaml`. Keep public Git declarations in package manifests; workspace
registration alone does not add dependency edges. Source publication does not
create a tagged release or extend historical platform acceptance.


## Local development: connected streamed HTTPS

The optional `http_tls.HttpsClient.NewStreaming` shares the same exchange and
producer APIs with the TCP facade. It composes an additive `tls.TlsChannel`,
without changing the published TlsStream's single-pending-operation contract or
adding TLS imports to plain HTTP. See the [adapter contract](../http_tls/README.md#local-development-streamed-connected-https).

[Current HTTPS/channel acceptance](docs/https-upload-acceptance-2026-10-28.json)
records macOS arm64, Linux x86_64 and Windows x86_64 using checksum-pinned public
SDK 1.0.2. Per host: 88 core cases/replays, 181 network/control scenarios
(the previous 165 plus 16 streamed HTTPS cases), 39 TLS cases/replays and 73 native
TLS cases. All compiler and 346 native runtime file identities are verified.
Native bridge/harness cases use ASan/UBSan on macOS/Linux and are unsanitized on
Windows. The complete provider archive is not claimed to be sanitizer-instrumented.

Intel macOS qualification is pending restoration of its authorized SSH session;
these records do not substitute Rosetta execution or historical evidence for a
new native run. Windows' first final-snapshot attempt failed in an existing TCP
POST/307 redirect snapshot open. The same binary passed three isolated case-2
replays plus a case-1 comparison, then the complete unchanged HTTP suite passed.
The native cause remains unconfirmed, alongside the earlier H3e Windows follow
timeout; the per-host receipt preserves both failure and retry identities.
No case selection or operation deadline was relaxed. This is local development,
not a new HTTP/TLS release. URL streaming was added after this connected-only
snapshot; see the separate URL and streamed-follow qualification below.

## Local development: URL streaming

`HttpUrl.StreamingRequestHead` generates owned routing and framing metadata from
one URL. Pass `HttpBodyPlan{kind: HttpBodyKind.ContentLength, length: ...}` for a
known payload size, `HttpBodyPlan{kind: HttpBodyKind.Chunked}` for a producer with
trailers, or the default plan for an empty request. Other body kinds, nonzero
unused lengths and `close_connection` are rejected. Shared exchange validation
applies the existing bounded producer profile. Callers cannot override Host,
Content-Length or Transfer-Encoding; one valid `Expect: 100-continue` is allowed
for a nonempty fixed or chunked producer.

`HttpTcpClient.OpenStreaming(url, verb, fields, plan, limits, resolver, dial,
options, continue_wait_ms)` validates the request, limits and finite continue
policy before DNS, then uses the existing sequential URL dialer. For HTTPS use
`http_tls.HttpsClient.OpenStreaming` with explicit CA configuration. The HTTPS
URL supplies peer/SNI identity; a conflicting identity or unsupported ALPN fails
before DNS. Provider/trust resources are checked after dial and before HTTP output.

DNS workers stay caller-owned and are borrowed only during OpenStreaming.
Numeric URLs bypass even a closed resolver. After open, the resolver can close;
Next/SupplyBody/FinishBody retain the connected streaming contract and the same
absolute deadline/token, including producer time. There is no automatic replay
or redirect of streamed bodies. Existing immutable URL and redirect APIs keep
their previous behavior. No new package release is implied.

[URL streaming acceptance](docs/url-upload-acceptance-2026-10-28.json) records
macOS arm64, Linux x86_64 and Windows x86_64: 91 core cases and isolated replays,
231 network/control scenarios per host, including 30 URL uploads and 20 controlled
DNS cases. Each public SDK 1.0.2 compiler and all 346 native runtime files match
their pinned identities. Native Intel remains pending SSH restoration. Historical
Windows redirect/follow timeouts remain unresolved; this candidate passed the
complete suite without changing fixture budgets or selecting cases. TLS standalone
and native harness suites were not rerun for these URL-only changes; their
[previous qualification](docs/https-upload-acceptance-2026-10-28.json) is separate.

## Local development: streamed redirect replay

`HttpRedirectChain.NewStreaming` retains owned request metadata and an upload
plan, with no payload buffer. `HttpBodyReplayPolicy.Never` rejects redirects
that preserve nonempty fixed or chunked producers, even when an early final
response arrived before any payload was sent. `Explicit` is the application's
promise that it can reproduce the same payload and trailers from the beginning.
The existing `allow_unsafe_replay` policy is separately required for preserved
bodies and unsafe methods. Neither permission implies that bytes reached the
peer or that replay is safe for a particular application.

A streamed `HttpRedirectRequest` exposes `IsStreaming` and `UploadPlan`; its
`Body` is empty. Open it through `OpenStreamingTcp` or the optional HTTPS
`OpenStreamingRequest`, after preparing the producer. Immutable snapshot open
methods reject streamed snapshots, preventing an empty body from being mistaken
for a complete replay payload. Retained snapshots remain immutable and owned.

The shared decision rules still govern status rewrites, hop limits, cross-origin
filtering and HTTPS downgrade rejection. POST 301/302 and eligible 303 rewrites
remove producer framing, Expect, Trailer and representation metadata. Same-origin
preserved chunked streams keep their Trailer declaration. Cross-origin or
Connection-nominated Trailer declarations are rejected for preserved streams,
rather than silently changing a promised producer representation. Cross-origin
fixed streams retain only the existing safe field allowlist; removed credentials
never return on a later hop back to the original origin.

The optional `http_tls.HttpFollowClient.NewStreaming` adds automatic connection
orchestration with an explicit `NeedReplay`/`ReplayBody` boundary. Its contract
and producer loop are documented in the [adapter](../http_tls/README.md#local-development-streamed-automatic-redirects).
Transport errors are terminal and never trigger a replay. This remains local,
unreleased development.

[Streamed follow acceptance](docs/stream-follow-acceptance-2026-10-28.json) records
96 core cases and isolated replays plus 276 network/control scenarios on each of
macOS arm64, Linux x86_64 and Windows x86_64 with matching public SDK 1.0.2 and
346 verified runtime files. It preserves the first Linux partial-head fixture
failure, old/new binary TCP_NODELAY comparisons and a fresh complete final matrix
with unchanged protocol budgets and production sources. Native Intel remains
pending SSH restoration; historical Windows connection timeout causes remain open.

## Published 0.1.0

[http 0.1.0](https://github.com/nylang/http/releases/tag/v0.1.0) is a source-only release. Its package.yaml
retains immutable public Git dependencies; the source assets preserve the
original declarations without relative sibling rewrites. Corrected Nyra 1.0.4
tools are required for locked Git consumption; that SDK is not yet publicly
released. A clean Git consumer has passed lock/fetch, relocation/offline,
semantic checking, native linking and execution with the source tool candidate.
Protocol qualification with public SDK 1.0.2 is recorded separately.

See the [publication receipt](docs/publication-0.1.0.json) for exact
sources, assets and native desktop qualification. Historical development
receipts retain their original pending/partial state and are not rewritten.


## Published 0.1.1

[http 0.1.1](https://github.com/nylang/http/releases/tag/v0.1.1) supersedes the
first 0.1.0 source release with corrected publication tooling and IPv4-specific
URL continue/producer deadline fixtures. Production behavior and APIs, the
160/800 ms deadlines and the remaining default-family URL cases are unchanged.
See the [fixture investigation](docs/windows-url-deadline-fixture-2026-10-28.json),
[publication receipt](docs/publication-0.1.1.json) and
[real Git consumer](docs/git-consumer-0.1.1.json). The four desktop jobs and
publisher passed; original tags/assets and failed fixture attempts are retained.
Source archives preserve package.yaml byte for byte with immutable public Git
edges. Corrected source 1.0.4 tools pass lock/fetch, offline relocation, checking,
linking and execution; delivery of the 1.0.4 SDK remains separate.

## Module architecture

See [module responsibilities, ownership and dependency boundaries](ARCHITECTURE.md).
