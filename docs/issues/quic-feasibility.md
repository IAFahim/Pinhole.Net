# C# QUIC assessment — 2026-10-11

Evaluate **System.Net.Quic first**. The owner explicitly corrected the earlier
focus on Hermod/HTTP3ConformanceTests and requested a prominent C# implementation.
The previous exclusion of Microsoft's API interpreted "no FFI" too broadly for
an evaluation. Its normal C# API requires no project-owned P/Invoke or Rust
bridge, but its native MsQuic implementation still matters for deployment.
It does not satisfy a completely native-free requirement.

Microsoft documents stable APIs from .NET 9, preview APIs on .NET 8, UDP transport,
TLS 1.3, multiplexed streams and platform dependencies. Linux needs libmsquic;
Windows includes it in supported runtimes. [Microsoft QUIC documentation](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/quic/quic-overview).

## Concrete probe and results

The [standalone official-API probe](../../samples/Pinhole.QuicProbe/README.md)
targets .NET 8/10 with no NuGet packages or shipping dependency changes. It
generates two identities and pins their certificates, then attempts 101
byte-exact echoes and EOF checks on a TLS 1.3 bidirectional stream. Network
operations use one cancellation deadline; JSON separates prerequisites from
successful traffic and only records timings after verification.

Both targets restored offline and compiled with zero warnings/errors. The
authoring session's sandbox denied sockets and the machine lacked libmsquic,
so its first runs returned **BLOCKED** (exit 2) with `IsSupported=false` and
`UdpError=AccessDenied`. A full-access follow-up session provided libmsquic
2.6.2 (official Microsoft Ubuntu 24.04 package, loaded user-space via
`LD_LIBRARY_PATH`, system OpenSSL 3) and completed every gate:

| Check | .NET 8.0.31 | .NET 10.0.12 |
|---|---|---|
| QuicConnection.IsSupported | true (libmsquic 2.6.2) | true (libmsquic 2.6.2) |
| QuicListener.IsSupported | true | true |
| Public unreliable datagram member | none found | none found |
| Loopback UDP prerequisite | available | available |
| C#↔C# verified echoes / timings | 101/101; 67.1 ms connect, 59.4/122.2 µs p50/p95 | 101/101; 54.9 ms connect, 33.6/152.0 µs p50/p95 |
| C#↔Rust (Quinn) echoes / timings | 101/101; 72.2 ms connect, 40.5/78.9 µs p50/p95 | 101/101; 60.4 ms connect, 17.8/24.1 µs p50/p95 |
| Incorrect server pin | rejected by the TLS callback, no traffic | rejected by the TLS callback, no traffic |

Hashed evidence: [docs/evidence/quic-probe-2026-10-11](../evidence/quic-probe-2026-10-11/README.md).
Timings are loopback reliable-stream measurements (64-byte payloads,
TLS 1.3, ALPN `pinhole-quic-probe/1`); they are not an Internet, NAT or relay
benchmark, and compilation alone was never counted as success.

## Fit for Pinhole

| Requirement | What remains |
|---|---|
| Reliable encrypted streams | Provided by the API; the probe still needs an executable network environment. |
| Unreliable game datagrams | Not exposed by the inspected .NET 8/10 public API. Retain existing datagram semantics. |
| Share-code discovery, NAT punching, relay fallback | Require separate coordination and routing. QUIC does not replace these services. |
| Existing raw UDP/iroh relay packet I/O | No packet injection hook was found in the inspected public endpoint/connection options. Integration is not verified. |
| Rust QUIC interoperability | Test matching ALPN, certificates and framing against an independent implementation. |
| Native iroh interoperability | Requires iroh's identity and protocol behavior in addition to standard QUIC. |
| Android/iOS, AOT and deployment | Still need actual platform validation; this desktop probe supplies none. |
| Lowest-latency connection selection | Measure viable authenticated routes; loopback stream timings cannot establish this. |

Microsoft's datagram API proposal remains separate from the installed public
API. Native MsQuic capability does not imply C# API availability.
[Runtime datagram proposal](https://github.com/dotnet/runtime/issues/123418).

The interop gates now pass locally. The [Windows/Linux workflow](../../.github/workflows/quic.yml)
repeats them on GitHub runners with distro libmsquic (Ubuntu 24.04) and the
bundled Windows implementation, on .NET 8/10, and uploads hashed JSON
evidence; it is published with this change and separate from shipping CI.

What remains before any backend consideration: benchmark comparable delivery
semantics (the public API exposes no unreliable datagrams), real network
paths, and NAT/relay integration. Hermod exploration is deferred; no source
acquisition or upstream test report is treated as our execution evidence.

Pinhole's existing direct UDP, TCP and encrypted relay transports remain in
place. No ticket/wire change, new custom QUIC/TLS stack or dependency adoption
is made by this evaluation. The [physical phone TCP result](../evidence/phone-trial-2026-10-11/README.md)
remains a separate unresolved trial.
