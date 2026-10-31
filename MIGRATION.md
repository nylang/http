# HTTP source migration

## 1.0.5 ownership refactor

Replace `HttpWriter.Request(...)` with `HttpHead.EncodeRequest(...)` and
`HttpWriter.Response(...)` with `HttpHead.EncodeResponse(...)`. Argument order,
validation, NetBuffer ownership and protocol diagnostics remain the same. The
empty writer namespace is removed; compiled consumers must rebuild. Internal
procedural aliases are removed in favor of state/value operations.

The package now requires matched 1.0.5 source stdlib/kernel for ASCII-only string
comparison/lowercasing, bounded byte observations and decimal integer formatting.
The selected 1.0.4 compiler can build that source dependency closure in a private
workspace; an unchanged 1.0.4 precompiled stdlib does not provide these new APIs.
No package tag or SDK publication is implied by this working tree.
