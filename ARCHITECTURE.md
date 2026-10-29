# http module architecture

HTTP modules distinguish immutable syntax, framing state, exchange policy and
transport ownership. The product faces remain transport/provider independent.

- `private/grammar.ny` owns byte grammar, ASCII comparison and value formatting;
  it owns no mutable head, body, socket or exchange state.
- `private/http.ny` with `scan.ny` owns head parsing and immutable head storage.
- `private/writer.ny` owns canonical head construction through head-parser operations.
- `private/framing_rules.ny` owns body limits and trailer admission shared by the
  decoder and encoder, without owning either cursor.
- `private/body.ny` owns incoming-body framing; `body_writer.ny` separately owns
  outgoing payload/chunk/trailer framing. Neither sees the other's cursor layout.
- `private/response.ny` owns informational/final head sequencing for one request.
- `private/exchange.ny` with `upload.ny` owns request/response progress, producer
  admission and early-final behavior. Both parts mutate one exchange state machine.
- `private/tcp_client.ny` with `tcp_upload.ny` owns the plain TCP adapter and its
  flush/read scheduling. HTTP grammar remains in the protocol modules.
- `private/url.ny` owns validated immutable URL values and request-head association.
- `private/url_reference.ny` owns URI-reference resolution and origin comparison,
  consuming the URL operation contract without accessing URL storage.
- `private/url_dial.ny` owns controlled DNS/address iteration and TCP client opening.
- `private/redirect.ny` owns redirect-chain history, hop filtering and replay policy;
  URI resolution and network dialing remain outside its state machine.

The client assembly imports exchange, TCP, URL, dialing and redirect modules.
Redirect policy consumes URL/reference operations; dialing consumes URL and TCP
operations; the TCP adapter consumes the exchange contract. Protocol modules do
not depend on clients or TLS. Tests have separate protocol and client selftest
TUs. No private parser, body, exchange or TCP state bag becomes barrel-visible.
