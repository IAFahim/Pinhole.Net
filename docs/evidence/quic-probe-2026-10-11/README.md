# QUIC probe — local execution 2026-10-11

First live run of the [official-API QUIC probe](../../../samples/Pinhole.QuicProbe/README.md).
The authoring session that wrote the probe was sandboxed (no network sockets,
no Git writes) and could only report `BLOCKED`; this run used a full-access
session on the same machine and completed every gate the verifier defines.

## Environment

- Desktop: Omarchy (Arch Linux) x64. .NET SDK 10.0.401; runtimes .NET 10.0.12
  and .NET 8.0.31. rustc/cargo 1.98.1.
- libmsquic 2.6.2 from Microsoft's official `ubuntu/24.04/prod` package
  (`libmsquic_2.6.2_amd64.deb`), extracted into `/tmp` and loaded through an
  `LD_LIBRARY_PATH` symlink directory. No system packages were changed and no
  root was used; the system OpenSSL 3 satisfies the library.
- Independent peer: Quinn 0.11.12 / quinn-proto 0.11.18 / rustls 0.23.45,
  `cargo build --release --locked`. The C# probe was built `-c Release` for
  both target frameworks and driven by `verify.py`, which hashes the assembly,
  Rust binary and `Cargo.lock` into each report (`net8.json`, `net10.json`).

## Results — all three verifier gates, both frameworks

| Case | .NET 10.0.12 | .NET 8.0.31 |
|---|---|---|
| C#↔C# loopback echo | PASS, 101/101 | PASS, 101/101 |
| C#↔Rust (Quinn) echo | PASS, 101/101 | PASS, 101/101 |
| Incorrect server pin | PASS (EXPECTED_REJECTION, no measurements) | PASS (EXPECTED_REJECTION, no measurements) |

Release-build timings (64-byte payloads, reliable bidirectional stream,
loopback; connect time includes the TLS 1.3 handshake):

| Case | Connect→first echo | RTT p50 | RTT p95 |
|---|---|---|---|
| .NET 10 loopback | 54.9 ms | 33.6 µs | 152.0 µs |
| .NET 10 ↔ Rust | 60.4 ms | 17.8 µs | 24.1 µs |
| .NET 8 loopback | 67.1 ms | 59.4 µs | 122.2 µs |
| .NET 8 ↔ Rust | 72.2 ms | 40.5 µs | 78.9 µs |

Interoperability detail: the C# client (`System.Net.Quic`/MsQuic)
authenticated the Quinn server's certificate by SHA-256 pin and the Quinn
server required the C# client certificate byte-exactly; ALPN
`pinhole-quic-probe/1`, TLS 1.3 on both sides, all 101 payloads matched,
both halves reached EOF, and the deliberately corrupted pin was rejected by
the TLS callback with no application traffic sent.

## Scope

Loopback, reliable-stream semantics only. These numbers do not benchmark NAT
traversal, relay fallback, Internet paths, or unreliable datagrams — the
inspected .NET 8/10 public API exposes no unreliable-datagram surface, and
`System.Net.Quic` still carries native MsQuic as a deployment dependency.
The [QUIC feasibility workflow](../../../.github/workflows/quic.yml) repeats
these gates on GitHub runners: first run
[38086611685](https://github.com/IAFahim/Pinhole.Net/actions/runs/38086611685)
passed Ubuntu but failed Windows (`ConfigurationLoadCredential`/
SEC_E_NO_CREDENTIALS — Schannel cannot open the ephemeral `CreateSelfSigned`
key; fixed by persisting identities through PFX), and
[run 38087357297](https://github.com/IAFahim/Pinhole.Net/actions/runs/38087357297)
passed all four jobs (Ubuntu 24.04 + Windows, .NET 8 + .NET 10).
