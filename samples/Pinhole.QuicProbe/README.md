# Official C# QUIC probe

This standalone sample evaluates `System.Net.Quic`. It has no NuGet packages,
project-owned P/Invoke declarations, Rust bridge or reference to the shipping
Pinhole library. The .NET implementation uses native MsQuic internally.

```sh
dotnet run --project samples/Pinhole.QuicProbe -f net10.0 -- --check
dotnet run --project samples/Pinhole.QuicProbe -f net10.0
```

Use `-f net8.0` to check the existing minimum runtime as well. This project opts
into the preview API on .NET 8; .NET 9+ exposes stable APIs. Linux requires
libmsquic and compatible TLS support. See [Microsoft's platform dependencies](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/quic/quic-overview#platform-dependencies).

`--check` reports prerequisites without performing the handshake. A normal run
creates two loopback peers, pins their independently generated certificates on
both sides, and uses TLS 1.3 with a dedicated ALPN. It verifies 101 distinct,
64-byte echoes and stream EOF. The first echo includes connection establishment;
the other 100 round trips produce p50/p95 latency. Network operations share a
15-second cancellation deadline. These are reliable stream results, not raw UDP
datagram results or proof of Internet connectivity.

The JSON report uses these outcomes:

| Status | Exit code | Meaning |
|---|---|---|
| READY | 0 | Prerequisites passed; `--check` did not run an echo. |
| PASS | 0 | The authenticated echo and EOF checks completed. |
| BLOCKED | 2 | Platform, QUIC runtime support or UDP permissions prevent execution. |
| FAIL | 1 | Execution failed; read the reported exception. |

## Observed on 2026-10-11

Offline restore and build succeeded for both targets with zero warnings/errors.
The authoring session's sandbox denied UDP sockets, and this machine had no
libmsquic installed, so its first runs returned `BLOCKED` with
`IsSupported=false` and `UdpError=AccessDenied`. A full-access session on the
same machine then loaded libmsquic 2.6.2 (Microsoft's official Ubuntu 24.04
package, extracted user-space and found through `LD_LIBRARY_PATH`) and every
verifier gate passed on .NET 8.0.31 and 10.0.12: C#↔C# loopback echo,
C#↔Rust Quinn echo, and TLS rejection of an incorrect server pin — 101/101
byte-exact echoes each, timings in the
[evidence record](../../docs/evidence/quic-probe-2026-10-11/README.md).
These remain loopback reliable-stream results: no NAT traversal, relay,
Internet path or phone result is claimed. See the
[QUIC assessment](../../docs/issues/quic-feasibility.md) for the integration gaps.

## Independent Rust interoperability fixture

The `rust-peer` executable uses Quinn 0.11.12 and rustls, with direct versions
pinned and the dependency closure locked. It is a test process, never a Rust
binding or dependency of the C# SDK. The C# probe starts and retires only its
owned child. A fresh readiness record supplies the loopback endpoint and server
certificate. Only the public client certificate is written to a temporary
directory; private keys stay in memory. Both peers authenticate certificates,
check all 101 messages, and require stream EOF before a successful report.

```sh
cargo build --release --locked --manifest-path samples/Pinhole.QuicProbe/rust-peer/Cargo.toml
dotnet build samples/Pinhole.QuicProbe -c Release
python samples/Pinhole.QuicProbe/verify.py --framework net10.0 --rust-server samples/Pinhole.QuicProbe/rust-peer/target/release/pinhole-quic-peer --output artifacts/quic/net10.json
```

On Windows, append `.exe` to the Rust executable. Choose a fresh output file
for each invocation. The runner records executable and lockfile hashes and
requires three outcomes: C# loopback echo, C#↔Rust echo, and TLS rejection of an
incorrect server certificate pin. The last case must report
`EXPECTED_REJECTION` with no measurements, based on an actual certificate
callback rejection. A timeout, absent native library or denied socket cannot
satisfy that negative test. All three checks must pass for the runner to exit 0.

The [QUIC feasibility workflow](../../.github/workflows/quic.yml) prepares
libmsquic on Ubuntu 24.04 and uses the bundled Windows implementation. It covers
.NET 8/10, runs the three checks and uploads JSON evidence. It is separate from
shipping CI and can also be dispatched manually after publication.

The Rust fixture built with locked dependencies on rustc 1.98.1 and the C#
probe built on both targets with zero warnings/errors. The full-access
follow-up session executed the real verifier twice (once per framework) after
providing libmsquic: all three cases — C# loopback, C#↔Rust byte-exact echo,
and incorrect-pin rejection — passed and are recorded with assembly, binary
and lockfile hashes in `net8.json`/`net10.json` under
[docs/evidence/quic-probe-2026-10-11](../../docs/evidence/quic-probe-2026-10-11/README.md).
The [QUIC feasibility workflow](../../.github/workflows/quic.yml) repeats the
same gates on GitHub runners for Ubuntu 24.04 (distro libmsquic) and Windows
(bundled implementation).
