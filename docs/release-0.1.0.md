# http 0.1.0

First source release of the independent MIT HTTP/1.1 client library: bounded
HTTP/1.x heads, shared body framing, owned response events, strict HTTP(S) URLs,
explicit DNS/control budgets, TCP streaming uploads, 100-continue, early-final
suppression and explicit redirect/replay decisions. Plain HTTP has no TLS link
dependency. The optional http_tls package supplies verified HTTPS and automatic
streamed redirects. Pooling/reuse, Happy Eyeballs, HTTP/2/3, proxy routing and
upgrade/tunnel handoff remain deferred.

All published package manifests retain exact public Git dependencies. There is
no sibling-directory dependency rewrite in the source archive. Lock/fetch and
locked Git compilation require corrected Nyra 1.0.4 tools; that SDK is not yet
published at preparation time. This source release does not publish or imply
availability of SDK 1.0.4. Protocol qualification uses checksum-pinned public SDK
1.0.2 in private test snapshots; those overlays are not shipped package manifests.

The tag pipeline requires four native desktop jobs: 96 core cases and isolated
replays, 27 connected TCP scenarios, 9 controlled DNS scenarios and 14 streamed
TCP scenarios, including production TLS/fixture isolation. The optional adapter's
release qualifies the complete 276-scenario HTTP/HTTPS graph at its exact HTTP
pin. Source assets contain no precompiled native libraries. Build net_core's
native adapter for the selected target. No mobile runtime support is advertised.

Earlier three-host development receipts retain their exact scope and pending
Intel state; the release's own four-host receipts identify the released commits.
Historical Windows redirect/follow connection timeouts remain an investigation
limitation. Passing suites does not establish a root-cause fix. The Linux
partial-head fixture correction preserves its original protocol timing budgets.
