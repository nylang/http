# HTTP protocol acceptance

The first increment contains 18 controlled Nyra cases, each also replayed in its
own invocation. They exercise every split of a representative head and every
incomplete EOF prefix, reused byte storage and lifetime after parser drop,
malformed CRLF/field controls, framing ambiguity and uint64 overflow, Host syntax,
response context and persistence, ordinary duplicate fields, exact limits,
request-target/version scope, canonical writer roundtrips, injection rejection,
writer bounds, NUL/DEL rejection and opaque non-UTF-8 field octets.

The runner uses a supplied SDK's precompiled runtime and an explicit compatible
native compiler candidate. It records both identities, disables source fallback,
links only net_core's ordinary native adapter and the SDK platform runtime,
precompiles production HTTP and rejects fixture/TLS undefined symbols. An external
consumer imports the public barrel and verifies head/body suffix ownership and
fixed-length framing without any TLS/OpenSSL dependency.

The body increment adds 12 cases (30 combined): fixed/chunked split boundaries,
caller output backpressure, preserved pipeline suffixes, every truncated chunk
prefix, EOF-delimited completion, decoded/framing/line/trailer caps, overflow and
extension grammar, protected/connection-nominated trailers, ownership after move
and drop, opaque binary payloads, NUL/DEL rejection and quoted obs-text. Every case
also runs in isolation. The imported consumer exercises public body construction,
partial output and exact completion across translation units.

The framing increment adds 22 cases (52 combined): fixed/no-body/EOF output,
short/excess bodies, chunk sizes and canonical 16 KiB chunk bounds, one-byte output,
zero-capacity backpressure, Finish behind pending delimiters, trailer declaration/
count/line/framing restrictions, owned trailers through mutation/move/drop, binary
payloads, and writer-to-decoder roundtrips. Response cases exercise every split
and every incomplete EOF prefix of informational/final sequences, unknown 1xx,
count and aggregate/per-head caps, HEAD/CONNECT/101 suffixes, sticky aggregate
offsets, owned events and borrowed method-context mutation.

The imported consumer uses both body directions plus response sequencing across
translation units, including bounded output and captured chunk trailers after
caller mutation. Every discovered test also runs in isolation. Production
precompilation excludes test/provider symbols and links no TLS/OpenSSL inputs.

The connected-client increment adds seven core cases (59 combined), including
one-byte acknowledgements, stable output owners, chunked upload, incoming
backpressure, trusted EOF after buffered bytes, sticky truncation, unsupported
upgrade, request validation and full-backing retention limits. Each runs alone.

`accept_clients.py` runs all core acceptance, builds a fresh ordinary native TLS
bridge when requested, precompiles the optional HTTPS adapter with fixture symbol
checks and links independent consumers. A test-only C shim passes fixture ports,
case IDs and CA paths; it adds no product or provider API. Python loopback peers
verify exact request bytes, including canonical 20 KiB chunked upload and absence
of duplicated trailing bytes. They fragment response heads/chunks and exercise
40 KiB streamed responses. The 21 TCP and 29 HTTPS scenarios cover informational
responses, trailers, fixed/EOF completion, truncation/conflicting framing, 101,
body/informational caps, constructor non-adoption, cancellation/expiry on buffered
bytes, retained original options, actual waiting timeout and durable completion.
HTTPS adds identity mismatch before adoption, DNS/IP SAN validation, explicit
trust failures, ALPN restrictions/absence and authenticated versus raw EOF.
Ordinary HTTPS completion also performs bidirectional close_notify.

The [consumer template](data/client_consumer.ny.in) and
[peer runner](../scripts/accept_clients.py) are hashed acceptance inputs. Each
host records exact compiler, SDK runtime, package sources, client static libraries,
fixture CLI and Python TLS provider identities. Plain clients have no TLS link
inputs or imports. Source fallback remains disabled. This is controlled desktop
source-candidate evidence; actual forced TCP send backpressure, arbitrary network
faults, streaming request producers, redirects, pooling,
mobile execution, fuzzing/sanitizer coverage and published SDK delivery remain
open. No package or SDK is published by these tests. See the [head receipt](../docs/head-acceptance-2026-10-27.json),
[decoder receipt](../docs/body-acceptance-2026-10-27.json),
[framing receipt](../docs/framing-acceptance-2026-10-27.json),
[client receipt](../docs/client-acceptance-2026-10-27.json) and
[maintained roadmap](../ROADMAP.md). Test output and compiler intermediates stay
in external ignored cache directories, never in this package.

## URL and DNS increment

Eight additional core cases bring the total to 67 with matching isolated replays.
They cover scheme/DNS/IP/default-port normalization, empty paths/queries,
preserved percent escapes/dot segments, validated omitted fragments, authority
ambiguity, legacy numeric IP rejection, injection and exact URL/port bounds,
owned borrowed-source bytes, generated uint64 Content-Length, reserved fields,
family mismatch and preflight controls/downgrade rejection.

Six new live scenarios per transport cover DNS Open, numeric bypass with a
closed resolver, Unspecified family, escaped query/fragment routing, native-wait
deadline and retained original controls. The expanded ordinary suite therefore
contains 27 TCP and 35 HTTPS cases, and still uses production native adapters.

A separate external consumer links a test-only net_core DNS adapter and its
existing getaddrinfo gate fixture. Nine TCP and eleven HTTPS scenarios cover
NameNotFound, blocked-running DNS timeout/cancel, expiry before DNS, a closed
pool, Host/scheme/request-budget/address-cap admission and HTTPS peer/ALPN
rejection. Running DNS remains blocked after return; tests assert the charged
slot and worker, release the gate, retire the slot and resolve again using the
same pool. Only the cancellation token crosses a worker thread. Fixture symbols
remain absent from production archives and ordinary live consumers.

[URL acceptance](../docs/url-acceptance-2026-10-27.json) records the exact native
source-candidate/SDK-runtime identities and matching package source hashes across
three desktop hosts. localhost address order is OS-dependent; the Unspecified
case does not establish that a failed first address was observed. Deterministic
fallback ordering, DNS notification allocation/native faults, hard interruption
of OS DNS and exhaustive scheduler/resource interleavings remain unclaimed.

## Redirect increment

Nine additional core cases bring the total to 76 plus 76 isolated replays. They
cover normal/abnormal URI-reference examples, literal dot-segment removal and
escaped dots/slashes, empty-path base preservation, validate-before-normalize,
origin comparison, all followed status/method combinations, POST rewrites,
GET-body/unsafe replay opt-in, duplicate/missing Location, exact default/custom
hop caps, sticky invalid input/cancellation, owned borrowed-source credentials,
same-origin hop-field stripping and permanent cross-origin filtering.

`accept_redirects.py` runs all preceding core/live/control acceptance, then builds
independent imported snapshot consumers. Twelve TCP and thirteen HTTPS multi-hop
scenarios verify exact method/Host/Content-Length/header/body bytes, 302/303
rewrites, 307 replay opt-in/rejection, cross-port credential/custom-field removal,
cross-origin rejection, cycles, duplicate/malformed Location, cancellation and
the original deadline before Follow, a terminal 302 without Location and HTTPS
downgrade rejection. Redirect responses advertise 1,000,000 body bytes that are
never sent: the peer requires closure before the next connection, proving the
coordinator usage does not drain or reuse that response. Terminal HTTPS responses
perform close_notify normally. All use ordinary native/provider inputs; the
inherited blocked-DNS suite retains its separate test-only adapter.

The [receipt](../docs/redirect-acceptance-2026-10-27.json) binds matching source
hashes to desktop source candidates and public SDK runtimes. This does not
establish an automatic-follow facade, mixed HTTP-to-HTTPS dispatcher, arbitrary
body producer replay, cookies/auth refresh, pooled connections, all scheduler
interleavings, fuzzer/resource/mobile acceptance or package publication.


## Automatic follow increment

`scripts/accept_follow.py` repeats core, connected-client, controlled DNS and
explicit-redirect acceptance, then exercises the optional `HttpFollowClient`.
It checks exact TCP/HTTPS rewrite/replay/filtering requests, rejected policies,
old-connection closure without draining, cancellation/deadline continuity,
terminal body/trailer queries, cursor moves, sticky failures and completion.
A separate plain TCP to verified TLS hop checks cross-scheme transport selection
and credential filtering. No HTTPS downgrade or transport retry is allowed.

Use the matching public SDK compiler and runtime. On macOS, the scripts derive
the deployment target from that SDK's stdlib manifest; historical receipts retain
their original compiler/runtime identities. A local run does not establish the
remaining host matrix, mobile support or publication.


The [2026-10-28 macOS arm64 receipt](../docs/follow-acceptance-2026-10-28-darwin-arm64.json)
records exact public SDK 1.0.2 compiler/runtime acceptance: 76 core cases plus
76 isolated replays, 62 ordinary network scenarios, 20 URL/DNS controls,
25 explicit redirects and 26 automatic-follow scenarios. It also retains source
hashes, OpenSSL library identities and production/plain import boundaries.
The subsequent [four-host acceptance](../docs/follow-acceptance-2026-10-28.json)
repeats the same complete scope with matching public SDK 1.0.2 on Linux x86_64,
Windows x86_64 and physical Intel macOS x86_64. All host source inventories match,
as do the compiler and 346 native runtime files against each pinned SDK manifest.
Intel execution is native, without Rosetta. Linux uses Ubuntu 24.04.5/glibc 2.39
container userspace; the receipt distinguishes it from the host kernel. These
results do not establish mobile support or package publication.

## Streamed exchange increment

The 12 new `test_http_upload_*` core cases cover fixed/chunked producer admission,
partial acknowledgement, request trailers, cumulative limits under small retained
budgets, backing-heavy slices, strict Expect validation, split informational
heads, coalesced 100/final responses, explicit continue release, pending-output
revocation, retained owners, final response bodies and sticky shortage/EOF errors.
The prior 76 core cases remain unchanged.

`scripts/accept_upload.py` repeats the prior suites before nine TCP and nine TLS
scenarios driven by an external consumer of `NewStreaming`. Exact wire checks
cover fixed/chunked producers and trailers, body withholding across 103 until
100, immediate 417, a final response after a prefix with another unsent block
queued, a caller-bounded continue release, 100/final sequencing, cancellation
before producing bytes and fixed-length shortage. Test drivers pass original
controls to each operation and never manufacture authenticated EOF or retry.
They do not establish automatic duplex scheduling in the convenience clients.

The intentional cancellation/shortage peers first acknowledge the observed head
or prefix with 103. This makes abort timing causal: a successful transport write
alone does not guarantee peer receipt before an immediate close, especially on
Windows. Exact header/body assertions and the original control budgets remain
active; a reset before the checkpoint is still a failure.


[Final H3e acceptance](../docs/upload-acceptance-2026-10-28.json) records all four
desktop hosts with matching public SDK 1.0.2, 88/88 core/replay results and
151 network/control scenarios each. All final source inventories match. The
Windows receipt preserves the first automatic-follow timeout, its successful
isolated rerun, and the subsequent cancellation fixture correction. That initial
timeout's root cause is unconfirmed; broader timing/fault investigation remains
open. Production sources, test selection and control budgets were unchanged by
the fixture correction. These receipts establish the streamed exchange and its
explicit test drivers, not automatic streamed convenience clients or publication.


## Connected TCP streamed facade increment

`scripts/accept_tcp_upload.py --sdk <sdk> --out-dir <new-external-directory>`
accepts the production `HttpTcpClient.NewStreaming` facade. It first repeats the
88 core cases/replays, production precompilation, imported consumer and plain
TLS/test-symbol isolation checks. `--baseline <completed-core-directory>` reuses
a completed core receipt only if its source inventories, compiler and SDK hashes
match exactly. The consumer is an imported application fixture (`.ny.in`), never
a package test module or a production dependency.

Fourteen network scenarios cover validate-before-adopt and cursor moves, rejected
producer admissions, fixed/chunked payloads/trailers, 103/100 gating, finite continue
fallback, coalesced 100/final, early finals, cancellation after a peer-observed
head, fixed shortage after a peer-observed prefix, partial final heads extending
past the continue fallback, original deadlines during continue/producer pauses,
response truncation, sticky error progress and completion after cancellation.

The large-upload case advertises 64 MiB, uses 16 KiB producers, constrains the
peer receive window and suspends peer reads for 300 ms before sending 413. The
consumer requires partial committed upload, at least two produced blocks, an
unfinished/stopped request and a Next call blocked for at least 100 ms. It must
return the final response within the original budget. The peer records the
observed accepted suffix; kernel acceptance is not equated with peer delivery,
and reset can discard a previously accepted suffix. This exercises response
readiness during upload backpressure without exposing socket handles, adding
product test hooks, changing socket ownership or buffering the whole body.

The full desktop qualification also repeats `accept_upload.py` (151 existing
network/control scenarios) before these 14 connected TCP scenarios. HTTPS and
redirect clients remain immutable; this suite does not claim a duplex TLS API,
streaming replay, mobile support or package publication.


Successful fixed-length peers may respond after their last body byte and before
the caller closes the producer. The fixture accepts Finished or Stopped in that
specific fully supplied race, while requiring the exact full wire count and
response. Chunked success must be Finished because its terminal wire framing can
only follow explicit producer finish. Non-success early-final cases still require
Stopped and exact suppression counts. This reflects the producer/response contract
without assuming a scheduling order between two independent processes.


The [four-host final receipt](../docs/tcp-upload-acceptance-2026-10-28.json)
records 88 core/replay cases and 165 network/control scenarios per host using
matching SDK 1.0.2 compiler/runtime inputs. All source inventories match the final
snapshot; each native runtime inventory verifies 346 files. Per-host receipts
retain the initial passed matrix hashes and the one-fixture correction. The
complete matrix was repeated after that correction, preserving product code,
case selection and timing budgets. Intel macOS evidence is native Intel hardware,
not Rosetta. The earlier H3e Windows follow timeout remains unconfirmed and is
linked as a broader timing/fault follow-up rather than silently closed.


## Connected HTTPS streamed facade increment

`scripts/accept_https_upload.py --sdk <sdk> --openssl-root <pinned-build>
--out-dir <new-external-directory>` repeats the complete 151 existing scenarios,
the 14 streamed TCP facade scenarios, then 16 new verified HTTPS scenarios.
Optional baseline directories are accepted only with matching source/compiler/SDK
inventories. Plain production archives remain TLS-free; HTTPS production retains
no fixture inputs. The optional channel/probe has its own 39/39/73 TLS acceptance.

The new consumer verifies constructor rollback for wrong peer/ALPN/trust/BIO
capacity, bounded fixed/chunked producers/trailers, 103/100 gating, finite continue
fallback, coalesced 100/final, peer-observed cancellation/shortage checkpoints,
partial heads, original deadlines during continue/producer time, and early 413
while a 64 MiB upload is blocked. Fixed-length success still permits the documented
full-payload-before-explicit-finish race. Chunked completion tests graceful
close_notify; early 413 tests abortive Shutdown without flushing pending upload.
Authenticated closure before a fixed HTTP body finishes yields HTTP UnexpectedEof;
raw TLS truncation stays a TLS failure. Untrusted CA fails before any HTTP output.

[Current receipts](../docs/https-upload-acceptance-2026-10-28.json) cover three hosts,
with native Intel macOS pending restored SSH access. Windows' first final-snapshot
attempt failed opening an old explicit TCP POST/307 redirect snapshot. The unchanged
binary passed case 2 three times and case 1 once, followed by a complete unchanged
181-scenario pass. Source/receipt/binary hashes are retained; the cause remains
unconfirmed and no timeout, case selection or production source was changed to
obtain the retry. Broader Windows timing/fault investigation remains open.

`accept_url_upload.py` runs the complete connected HTTPS upload baseline, then
30 imported URL streaming scenarios (14 TCP and 16 HTTPS) and 20 controlled DNS
scenarios. It reuses the peer protocol assertions with canonical URL-derived
Host/escaped targets. Numeric URLs work with a closed resolver; DNS-backed
clients continue after their resolver closes. HTTPS derives verification from an
empty peer-name configuration, including the numeric IP certificate case.
Gated native DNS proves cancellation/expiry returns while the OS job retains its
slot, retirement/recovery of the same pool, and rejection before DNS with exact
worker counters. Fixed/chunked/trailer framing, continue gates, producer waits,
early finals, constrained-window backpressure, authenticated truncation and
untrusted peers retain the connected fixture deadlines and assertions.

[URL streaming receipt](../docs/url-upload-acceptance-2026-10-28.json): matching
public SDK 1.0.2 compilers and 346 native runtime files, 91 core cases/replays and
231 network/control cases on macOS arm64, Linux x86_64 and Windows x86_64.
Native Intel is pending; previous Windows connection timeout causes remain open.

`accept_stream_follow.py` runs the complete URL upload baseline, then 22 streamed
follow scenarios on TCP, the same 22 on verified HTTPS, and one three-hop
TCP-to-HTTPS transition. They verify fixed/chunked replay, trailer preservation,
POST/303 rewrites, explicit replay and unsafe-method permissions, conservative
rejection of unsent gated bodies, partial-prefix restart from zero, permanent
cross-origin filtering, downgrade/ambiguous Location/hop errors, durable per-hop
failures, producer shortages, empty GET/HEAD, and no retry after transport failure.
Repeated NeedReplay calls use a closed DNS pool and a peer-side no-connection
checkpoint before acknowledgement. Original cancellation and expiry remain
active during rewind. Redirect responses advertise a large unfinished body;
only the terminal response is published and old connections are closed without
draining it. Intentional-shortage and partial-prefix fixtures stop their producer
at the first block until the peer's 103 checkpoint/final response is observed.

The first streamed-follow matrix exposed a Nagle-sensitive existing HTTPS
partial-head fixture on Linux. The previous URL binary reproduced 6 failures in
12 runs; the streamed-follow binary reproduced 7 in 12. With TCP_NODELAY set on
the controlled TLS peer, both unchanged binaries passed 12/12. The final fixture
sets that option only for partial-head case 11, isolating the continue timer from
peer-side buffering of TLS traffic. Its 40 ms fallback, 160 ms partial-head pause,
original operation budgets and all production sources remain unchanged. The
final acceptance requires a fresh complete matrix after this fixture correction;
passing isolated reruns alone is not qualification. Exact binary hashes and all
48 replay outcomes are retained with the streamed-follow receipt.

[Streamed follow receipt](../docs/stream-follow-acceptance-2026-10-28.json) records
a fresh complete passing matrix on macOS arm64, Linux x86_64 and Windows x86_64:
96 core cases/replays and 276 network/control scenarios per host, matching public
SDK 1.0.2 compiler and 346 native runtime files. Native Intel remains pending;
historical Windows connection timeout causes remain open. Standalone TLS/native
harness qualification remains separate from this HTTP-only increment.
