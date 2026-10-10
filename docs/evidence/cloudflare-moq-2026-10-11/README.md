# Cloudflare MoQ — live execution 2026-10-11

The [reusable C# client](../../../src/Pinhole.Moq/README.md) and
[live probe](../../../samples/Pinhole.MoqProbe/README.md) exchanged application
bytes through the actual Cloudflare Draft16 service on both supported .NET
runtimes. This is Internet relay evidence; no loopback echo is substituted.

The user supplied an existing publish+subscribe token and a subscribe-only
token for an already provisioned relay. No relay, token or account plan was
created, deleted or changed. Tokens stayed in a mode 0600 file under an owned
mode 0700 temporary directory; no token, token-bearing URL, account ID, relay
ID, namespace identifier, peer error phrase or raw exception message appears
in these reports.

## Environment and result

Arch/Omarchy Linux x64, .NET SDK 10.0.401, runtimes 8.0.31 and 10.0.12. Official
Microsoft libmsquic 2.6.2 was supplied through the existing user-space
extraction in `/tmp/pinhole-quic-live/msquic/usr/lib/x86_64-linux-gnu`; system
packages and firewall rules were unchanged. There are no project-owned
P/Invoke calls, Rust bridge or NuGet runtime dependencies. The .NET QUIC API
uses native MsQuic internally; this is not a claim of native-free deployment.

| Gate | .NET 8.0.31 | .NET 10.0.12 |
|---|---|---|
| Native QUIC ALPN `moqt-16`, validated service certificate | PASS | PASS |
| A→B→A byte-exact echoes | 50/50 | 50/50 |
| Subscribe-only observer copies | 50/50 | 50/50 |
| Empty and 64-KiB objects | PASS | PASS |
| 64KiB+1 rejected locally | PASS | PASS |
| Subscribe-only publication refused with same-target positive control | PASS | PASS |
| Modified-signature subscription refused by actual service | PASS | PASS |
| Owned subscriptions/sessions cleaned up before PASS | PASS | PASS |
| Offline parser/request-credit tests | 24 passed, 0 failed | 24 passed, 0 failed |

The normal 48 echoes use distinct 256-byte payloads; two additional objects test
empty and 64-KiB payloads. Both directions and all observer copies are compared
byte-for-byte. Each publishing side owns a separate namespace; both sides
subscribe to the other's track. The third independent session uses the
subscribe-only credential. All three sessions run in one desktop process.

Cloudflare returned request error 32 (UNINTERESTED) when the subscribe-only
session attempted to publish. The publish+subscribe session then successfully
published the exact same target as a positive control. For a deliberately
changed JWT signature, the service can still return SERVER_SETUP, but closed
that session with application error 3 (PROTOCOL_VIOLATION) when it subscribed
to the known live track. Neither negative gate accepts a timeout, and these
observed codes are not relabeled UNAUTHORIZED. Setup alone is not evidence of
token authorization.

## Measurements

These are individual functional run timings, not a performance benchmark.
The startup measurement includes credential-file parsing and three sequential
client-to-Cloudflare sessions;
RTT includes A→B→A and waiting for the separate observer copy. Both peers are
on the same computer, so these results establish neither phone/carrier
behavior nor geographical latency.

| Measurement | .NET 8 | .NET 10 |
|---|---|---|
| Three sessions established | 147.25 ms | 115.32 ms |
| Echo RTT p50 | 4.62 ms | 4.33 ms |
| Echo RTT p95 | 32.53 ms | 31.02 ms |
| Run including normal cleanup | 1535.49 ms | 1635.76 ms |

Each [net8.json](net8.json) / [net10.json](net10.json) report records the probe
and reusable client assembly SHA-256, runtime, platform, random payload digest
and actual service error codes. The verifier requires every functional gate,
filters allowed output fields, bounds its owned process and refuses stale
output-file reuse. The recorded reports reflect the excluded MAX_REQUEST_ID
boundary fix and local credit rejection preserves the session: credit 100 permits 0..98, then credit 102 permits 100. Zero credit
excludes request 0; extending it does not lose the next request ID.

## Scope and remaining integration

This optional `Pinhole.Moq` project is a usable experimental stream publisher/
subscriber, separately referenced by applications. The core `PinholeNode`
does not automatically select it as relay fallback. TLS protects each
client-to-Cloudflare connection; this adapter does not wrap objects in
Pinhole's end-to-end peer cryptography. Short-code discovery, production token
issuance, NAT punching, automatic fallback and end-to-end core integration
are separate work.

The implementation deliberately covers one-element UTF-8 namespaces, live
subscriptions and bounded reliable subgroup streams. It does not implement
FETCH, browser WebTransport, unreliable datagrams, media codecs or automatic
reconnect/migration. Incoming subgroup streams must finish within 15 seconds.
.NET 8/10's public QUIC API has no unreliable-datagram data path, so full
MoQ Draft16 conformance is not claimed even though Cloudflare accepts this
stream subset. These live results cover Linux only; Windows deployment uses
the MsQuic bundled with .NET on supported OS versions and is not proven here.

Primary references: [Cloudflare service and authentication](https://developers.cloudflare.com/moq/),
[Cloudflare supported message matrix](https://developers.cloudflare.com/moq/feature-matrix/),
[MoQ Transport Draft16](https://www.ietf.org/archive/id/draft-ietf-moq-transport-16.html),
[Cloudflare reference implementation](https://github.com/cloudflare/moq-rs),
and [Microsoft QUIC deployment requirements](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/quic/quic-overview).
