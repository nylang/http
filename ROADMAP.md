# HTTP implementation roadmap

The user requested the independent HTTP package on 2026-10-27. net_core owns
transport/control primitives; tls owns cryptography and verified TLS streams.
Neither imports HTTP. The shared HTTP protocol engine stays independent of the
transport so plain consumers need not link TLS. Compiler language contracts stay
unchanged. This is the maintained package schedule. The public source repository
is https://github.com/nylang/http; tagged package/binary release remains separate.

## H1 — Bounded head parser and writer

- [x] Independent local package, MIT license and public type-owned API.
- [x] Incremental HTTP/1.x heads with CRLF, line/head/field limits and exact consumption.
- [x] Owned immutable metadata, original field order and ordinary duplicates.
- [x] Strict framing conflict rejection, overflow-safe Content-Length and Host checks.
- [x] HEAD/status/CONNECT framing plans and connection persistence decisions.
- [x] HTTP/1.1 head writer with start-line/field injection and framing validation.
- [x] Split-boundary, byte reuse, EOF, limits, binary octets and writer acceptance.
- [x] Native SDK-runtime tests, isolated replays, imported consumer and production
      test/TLS isolation on macOS arm64, Linux x86_64 and Windows x86_64.

[Head acceptance](docs/head-acceptance-2026-10-27.json) records exact tested source
and compiler/runtime identities. H1 is not a streaming body decoder or HTTP client.

## H2 — Shared streaming message framing

- [x] Fixed-length, chunked and close-delimited body decoding with exact consumed
      prefixes, pending output/backpressure, decoded byte budgets and terminal EOF.
- [x] Chunk-size overflow, bounded extensions/trailers, forbidden trailer fields,
      truncated chunks and body delimiters. Decoder evidence is recorded in
      [body acceptance](docs/body-acceptance-2026-10-27.json).
- [x] Multiple informational response events and final/101 association, preserving
      request method and body/tunnel suffixes with count and aggregate-head caps.
- [x] Body writing/framing invariants and incremental streaming without buffering
      entire payloads; preserve accepted-byte progress and owner lifetimes.
      [Framing acceptance](docs/framing-acceptance-2026-10-27.json) records 52 cases
      and 52 isolated replays on three desktop hosts, plus production/imported consumers.
      This closes the H2 protocol increment; transport/client integration remains H3.

## H3 — HTTP and HTTPS clients

- [x] H3a connected single-request exchange and TCP client; optional sibling
      http_tls adapter shares H1/H2 without adding TLS inputs to plain consumers.
      Requests are bounded immutable buffers; responses stream in owned chunks.
- [x] Validate before adoption, retain one absolute control budget, expose typed
      errors/progress and distinguish authenticated TLS closure from truncation.
      Host/peer DNS/IP matching and HTTP/1.1 ALPN checks precede HTTP output.
      No reuse, Expect gating, early-final upload handling or upgrade/tunnel handoff.
- [x] Source-candidate desktop loopback acceptance: 59 core cases/replays plus
      21 TCP and 29 HTTPS scenarios per host. See [client acceptance](docs/client-acceptance-2026-10-27.json).
- [x] H3b strict owned absolute HTTP(S) URLs, canonical authority/default ports,
      preserved escaped origin targets and generated Host/Content-Length association.
      Explicit DNS pool, bounded result count/family, numeric bypass and sequential
      dial preserve one deadline/token through later TCP/TLS/body operations.
- [x] URL/DNS source-candidate desktop acceptance: 67 core cases/replays, 27 TCP
      and 35 HTTPS live cases, plus 9 TCP and 11 HTTPS controlled failure cases per
      host. Blocked DNS cancel/expiry retains its slot until worker retirement,
      then the same pool recovers. See [URL acceptance](docs/url-acceptance-2026-10-27.json).
- [x] H3c strict URI-reference resolution and explicit move-only redirect coordinator
      with owned replay snapshots, exact hop bounds and original absolute controls.
      301/302 POST and 303 rewrites drop bodies; preserved unsafe method/body replays
      require opt-in. Cross-origin follows require opt-in and permanently filter
      credentials/custom fields. HTTPS downgrade is always rejected.
- [x] Source-candidate desktop redirect acceptance: 76 core cases/replays, the prior
      82 network/control cases, plus 12 TCP and 13 HTTPS multi-hop scenarios per host.
      See [redirect acceptance](docs/redirect-acceptance-2026-10-27.json).
- [x] H3d optional `http_tls.HttpFollowClient` composes automatic redirects and
      TCP/TLS transition orchestration over the existing coordinator. It retains
      original controls, closes old connections without body draining, suppresses
      followed heads/bodies and preserves typed per-hop failures. Plain http keeps
      its TLS-free dependency graph.
- [x] H3d [macOS arm64 public SDK 1.0.2 acceptance](docs/follow-acceptance-2026-10-28-darwin-arm64.json): 76 core
      cases and 76 isolated replays, 82 baseline network/control scenarios,
      25 explicit redirect scenarios and 26 automatic-follow scenarios. Production
      HTTPS has no fixture inputs; plain HTTP retains TLS isolation.
- [x] H3d [four-host public SDK 1.0.2 acceptance](docs/follow-acceptance-2026-10-28.json):
      the same complete 76/76 core/replay and 133 network/control scenarios pass on
      macOS arm64, Linux x86_64, Windows x86_64 and physical Intel macOS x86_64.
      Source hashes match across hosts. Each exact compiler and all 346 native-host
      kernel/stdlib/ntest files match the pinned SDK manifest.
- [x] H3e transport-independent `NewStreaming` exchange: bounded immutable producer
      blocks, fixed/chunked framing and trailers, strict 100-continue gating,
      explicit caller-bounded release and early-final unsent-output suppression.
      Existing immutable clients and redirect snapshots retain their contract.
- [x] H3e [four-host public SDK 1.0.2 acceptance](docs/upload-acceptance-2026-10-28.json):
      88 core cases and 88 isolated replays, 133 prior network/control scenarios
      and 18 explicit streamed TCP/TLS scenarios per host. Sources and 346 native
      runtime files per SDK match. Intentional-abort fixtures use a peer 103
      checkpoint before closing; production code and original budgets are unchanged.
      Windows' first unconfirmed automatic-follow timeout remains recorded for
      broader timing/fault investigation; the corrected final suite passes fully.
- [x] H3f connected TCP streamed constructor and pull producer facade: bounded
      SupplyBody/FinishBody, response-first nonblocking writes, dual readiness on
      write backpressure and one finite continue timer under original controls.
      Existing immutable constructors and TLS's one-pending-operation contract remain.
- [x] H3f [connected TCP four-host acceptance](docs/tcp-upload-acceptance-2026-10-28.json):
      88 core cases/replays and 165 network/control scenarios per host (151 prior
      plus 14 streamed-facade scenarios). Matching public SDK 1.0.2 compilers and
      346 native runtime files per host are verified; Intel macOS runs natively.
      Constrained-window 64 MiB upload stops on 413 while a write is blocked.
      One fixture refinement accepts the valid full-fixed-payload-before-producer-
      finish race; both complete four-host matrices passed, product sources and
      timing budgets unchanged.
- [ ] H3f HTTPS/URL convenience-client scheduling, producer/replay contracts and
      automatic redirect integration; TLS currently permits one pending operation.
- [ ] IDNA/trailing-dot policy beyond the strict URL profile; Happy Eyeballs and
      deterministic fallback/fault matrices.
- [ ] Pooling/reuse, explicit upgrade/tunnel ownership and broader fault propagation.
- [x] Controlled TCP and TLS loopback consumer acceptance with matching public SDK 1.0.2
      on all four desktop hosts; published packages and mobile acceptance remain separate.

## H4 — Portable delivery

- [x] macOS x86_64 desktop production precompilation, imported linking and live
      protocol/client acceptance on physical Intel hardware with public SDK 1.0.2.
- [ ] Android/iOS build/link/runtime evidence for any advertised mobile faces.
- [ ] Local initial commit/submodule registration, assigned public origin, dependency
      lock, independent CI, relocated consumers, licenses and release artifacts.
- [ ] Complete fault/resource matrices and recheck protocol conformance boundaries.

HTTP/2, HTTP/3, transparent decompression, proxy routing, caching and server
framework features have no current implementation. Add explicit scope and
acceptance before advertising them.
