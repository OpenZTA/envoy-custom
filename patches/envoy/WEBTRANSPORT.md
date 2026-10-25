# WebTransport backport

`0012-webtransport.patch` builds on Envoy commit
`2fdc50edf463bd125b412409b3f52b78fed60cf6` after patches 0001–0011.
Its upstream starting point is Envoy commit
`ea6be314b74abcba959e1170ae962c04dab58253` (WebTransport support, PR 45630).
The existing Envoy and QUICHE license notices continue to apply.

OpenZTA additions in the patch:

* Current WebTransport HTTP/3 negotiation (`webtransport-h3`, WT_ENABLED),
  while preserving the pinned QUICHE draft negotiation for older clients.
* One active WebTransport session per QUIC connection; session-level flow-control
  extensions are not advertised. The upstream cluster must set
  `max_requests_per_connection: 1`.
* Reliable stream-reset negotiation, deferred CONNECT until SETTINGS arrive,
  bidirectional and unidirectional child-stream forwarding in both directions,
  FIN, RESET_STREAM, STOP_SENDING and QUIC stream-credit wakeups.
* Shared lifetime and authorization guards for child streams and datagrams.
  The native continuous-authz filter disables forwarding before resetting the
  authenticated CONNECT stream. The same policy session owns every child.
* Immediate datagram forwarding without an unbounded retransmission queue.
* Upstream QUIC client authentication with the configured proxy service
  certificate. No end-user key is forwarded. Client identity requires a software
  private key in this profile; unsupported key providers fail closed. Session
  caching and early data are disabled for upstream client identities.
* A successful HTTP response is rejected when the upstream did not negotiate
  WebTransport.

The runtime flag `envoy.reloadable_features.quic_support_web_transport` is false
by default. Enable it only with the authenticated HTTP/3 resource profile. Routes
must retain continuous authorization and fixed upstream destinations.

Native Go acceptance lives in `test/acceptance/webtransport_test.go` and requires
an explicitly supplied built image (`OPENZTA_ENVOY_IMAGE`). Running it without
that variable skips runtime execution. A successful compile or configuration
validation is not runtime acceptance. Full C++ verification remains the default
Docker release gate; `runtime-candidate` records an explicitly deferred C++ suite.
