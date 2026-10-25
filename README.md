# Pomerium Custom Envoy
[![Test (Linux)](https://github.com/pomerium/envoy-custom/actions/workflows/test-linux.yaml/badge.svg)](https://github.com/pomerium/envoy-custom/actions/workflows/test-linux.yaml)
[![Coverage Status](https://coveralls.io/repos/github/pomerium/envoy-custom/badge.svg?branch=main)](https://coveralls.io/github/pomerium/envoy-custom?branch=main)

This repo contains the custom Envoy extensions used in Pomerium, and tooling to compile Envoy with
those extensions statically linked in.

Most of the Bazel configuration and scripts were sourced from https://github.com/envoyproxy/envoy-filter-example and https://github.com/istio/proxy.

## OpenZTA gateway

The OpenZTA production profile pins Envoy 1.37.9 and statically links the HTTP and
network `continuous_authz` filters. Each authorized HTTP stream or TCP connection
is rechecked independently, including idle WebSocket, SSE and gRPC sessions.
Denials and authorization errors terminate access. HTTP/2 revocation resets the
affected stream without closing other authorized streams on that connection.
HTTP filters require an immutable `resource_host` identifying the NAC resource;
client `Host` cannot select the policy for a fixed application upstream. Explicit
trusted route metadata can bind individual routes to different resources. Route
upstream authority must be configured consistently with that resource binding.

```sh
docker build -f docker/Dockerfile -t openzta/envoy:continuous-authz .
cd test/acceptance
OPENZTA_ENVOY_IMAGE=openzta/envoy:continuous-authz \
  go test -race -count=1 -timeout=5m -v ./...
```

The Docker build runs the native controller, HTTP and TCP filter tests. The Go
acceptance suite starts the actual image with temporary PKI and independent
application/policy fixtures. Without `OPENZTA_ENVOY_IMAGE`, those container tests
are skipped; a successful compile-only Go run does not validate the gateway.

For a local Clang 19/Bazel installation, use `--config=openzta -c opt` and run
`bazel test --config=openzta -c opt //test/...`. This profile does not enable the
separate FIPS compile-time test matrix. HTTP/3/QUIC is enabled, including the
native client-authentication changes in `patches/envoy/0008-quic-client-authentication.patch`.
Ordinary upstream Envoy
images do not contain the OpenZTA filter types and cannot load their configuration.

## HTTP/3 client authentication

The pinned upstream rejects mandatory QUIC client authentication. Patch 0008
routes QUICHE client certificate verification through the selected Envoy server
TLS context, including its CA, validity, EKU, SAN, fingerprint and CRL checks.
Validated certificate metadata is exposed to the same HTTP continuous_authz
filter used by HTTP/1 and HTTP/2. HTTP/3 stream revocation resets the stream and
cancels its upstream without disconnecting other authorized streams.

QUIC TLS resumption and early data are disabled for this profile: every new
connection must present and prove its current client identity. A QUIC listener
must use `QuicDownstreamTransport` with `require_client_certificate: true`,
`enable_early_data: false`, ALPN `h3`, and TLS 1.3. Publishing TCP alone does not
publish QUIC; expose the corresponding UDP port too. Configure server QUIC
keepalive for quiet sessions and retain HTTP stream reauthorization.

The bootstrap explicitly enables
`envoy.reloadable_features.enable_universal_header_validator` in a static
runtime layer. The compile-time UHV flag alone does not enable it. Patch
`0011-websocket-extended-connect-upgrade.patch` supplies the RFC 6455 nonce when
an RFC 8441/9220 WebSocket is translated to an HTTP/1 backend, and removes the
legacy challenge response from HTTP/2 and HTTP/3 downstream responses.

The Go acceptance tests exercise real HTTP/3 with no HTTP/2 fallback: valid and
invalid certificates, configured certificate validation, no identity inheritance
from resumption, independent resource bindings, quiet stream revocation,
authorization outage, server keepalive, and upstream cancellation. Compile-only
checks do not establish these runtime properties.

Patch `0010-quic-p384-server-certificates.patch` supports P-384 server
certificates alongside P-256 and RSA, and propagates certificate initialization
failures instead of starting a QUIC listener with an unusable certificate.

The authorization DNS cluster uses a five-second refresh independent of DNS TTL,
with one-to-five-second retries after resolution failure. This bounds endpoint
IP-change recovery while authorization remains fail closed during an outage.

## Policy-protected UDP

UDP applications use CONNECT-UDP capsules over an authenticated HTTP stream.
The HTTP continuous_authz filter checks each tunnel independently, rechecks it
while idle, and resets it on denial or authorization-service failure. Resetting
the router stream closes its upstream UDP socket. Bind every configured UDP
destination to trusted resource metadata; never resolve a client-supplied URI
into an arbitrary network destination. Raw UDP backend listeners stay private.

The production profile enables UHV so that HTTP/2 and HTTP/3 extended CONNECT
and HTTP/1 Upgrade are handled consistently, including browser WebSocket.
Patch `0009-connect-udp-packet-semantics.patch` supplies the proper upgrade
response, receives full UDP packets rather than truncating them to 1500 bytes,
and preserves empty datagrams. Payloads above the portable 65507-byte limit
reset their tunnel. Unknown capsule types and context IDs are ignored.
HTTP/3 peers can negotiate native QUIC DATAGRAM frames. Peers without that
extension and packets larger than the QUIC payload limit use capsule fallback.
QUIC Datagrams use the immediate-send API without an extra userspace queue; congestion switches to
flow-controlled capsules; HTTP response backpressure pauses upstream UDP reads.

`TestConnectUDPPacketSemanticsAndRevocation` exercises the built image through
HTTP/1, HTTP/2 and HTTP/3, including empty/binary/large packets and idle revocation.
The Protocol LAB client provides paced loads, unlimited sessions, packet traces,
and a bounded loopback adapter for ordinary UDP applications. Its deployment
declares `LAB_CONNECT_UDP_ENABLED=true` only with the verified native profile;
the flag is a deployment declaration, not a substitute for wire acceptance.

## WebTransport and production deployment

Patch `0012-webtransport.patch` adds a WebTransport HTTP/3 session bridge with
BIDI/UNI streams, datagrams, stream-credit wakeups, service-certificate upstream
mTLS, and continuous authorization of the parent CONNECT session. The runtime
flag is disabled by default. The supported profile uses one WebTransport session
per QUIC connection and requires `max_requests_per_connection: 1` on the upstream
cluster. See [the backport profile](patches/envoy/WEBTRANSPORT.md) for negotiation,
key-provider restrictions and the exact runtime acceptance requirement.

Deployment generation, certificate/configuration validation, bounded container
limits, release evidence and rollback instructions are in
[deploy/production/README.ru.md](deploy/production/README.ru.md) and
[the operations guide](deploy/production/OPERATIONS.ru.md). The generator validates
the actual supplied binary and immutable image. Release export requires runtime
evidence for that image and the current patch hashes. A candidate with the full
C++ suite explicitly deferred retains that status in its release metadata;
configuration validation and LAB feature flags do not establish runtime support.

## Building

Follow the [Envoy Bazel Install](https://github.com/envoyproxy/envoy/blob/main/bazel/README.md#installing-bazelisk-as-bazel) docs to install bazel.

This repo is configured to build using clang and libc++. The easiest way to install these is using your distro's package manager. Ensure `clang`, `lld`, `lldb`, and `libc++` (on Ubuntu, `libc++1`) are installed.

To build the Envoy static binary:

`bazel build //:envoy`

To build in debug mode:

`bazel build -c dbg //:envoy`

To build using Envoy sources from a local directory:

`bazel build --override_repository=envoy=/path/to/envoy //:envoy`

or, add `common --override_repository=envoy=/path/to/envoy` to a file named `user.bazelrc` in this repo.

## Testing

To run the tests in this repo:

`bazel test //...`

To run the regular Envoy tests from this project:

`bazel test @envoy//test/...`

### Coverage

To run tests with code coverage, create a `bazel` task in `.vscode/tasks.json` as follows:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Test with coverage",
      "type": "bazel",
      "command": "coverage",
      "targets": ["//source/extensions/..."],
      "options": [
        "--instrumentation_filter=.*",
        "--experimental_split_coverage_postprocessing",
        "--experimental_fetch_all_coverage_outputs"
      ]
    }
  ]
}
```

Then, run the task. Coverage info will be displayed in the test explorer view in vscode.

## IDE setup

The following vscode extensions are recommended:

- https://marketplace.visualstudio.com/items?itemName=BazelBuild.vscode-bazel
- https://marketplace.visualstudio.com/items?itemName=llvm-vs-code-extensions.vscode-clangd
- https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb

### Clangd config

The following clangd extension settings are recommended:

```json
"clangd.checkUpdates": true,
"clangd.arguments": [
    "--clang-tidy",
    "--header-insertion=never",
    "--all-scopes-completion",
    "--compile-commands-dir=${workspaceFolder}/",
    "--query-driver=**",
    "--pch-storage=memory" // optional
    "-j",
    "xx" // <- set this to (number of cores / 2)
],
```
