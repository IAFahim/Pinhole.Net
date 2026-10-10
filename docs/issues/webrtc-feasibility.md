# WebRTC candidate feasibility — issue #45 M1

Measured comparison of the pinned SIPSorcery candidate against the current
Pinhole backend, run on 2026-10-10 by `samples/Pinhole.WebRtcCompare`
(noninteractive, in-process, loopback host candidates, no STUN/TURN, net10.0
Release, Linux). Source: commit `dc1a121`.

## Candidate record

| Property | Value |
|---|---|
| Package | SIPSorcery 10.0.17 (NuGet) |
| Pinned upstream | `3ef46acfa05cbfb74debea457f64f445a9908786` (main HEAD, matching 10.0.17) |
| Maintenance | Active; LICENSE copyright 2006–2026; package current on NuGet |
| License | BSD-3-Clause **plus an additional use-restriction clause** (geopolitical boycott terms in LICENSE.md §2). Redistribution of Pinhole binaries embedding SIPSorcery propagates that restriction to every downstream user. Not unrestricted BSD — a concrete distribution-fit decision, not an assumption. |
| Transitive packages | BouncyCastle.Cryptography 2.7, Concentus 2.2.2, DnsClient 1.8.0, Makaretu.Dns(+Multicast), SIPSorcery.WebSocketSharp, Common.Logging.Core 3.4.1, IPNetwork2, SimpleBase, Microsoft.Extensions.*, Tmds.LibC |
| Managed/native | All managed; no native runtimes/ folder |
| Added deploy size | ≈6 MB beyond what Pinhole already ships (SIPSorcery.dll 5.0 MB, Concentus 0.4 MB, websocket-sharp 0.2 MB, DnsClient 0.16 MB, Makaretu.Dns 0.09 MB; BouncyCastle 5.2 MB is shared with Pinhole) |
| Trimming | **Fails**: `PublishTrimmed` → IL2104 from Common.Logging 3.4.1 (netstandard1.3, 2016-era), NETSDK1144 abort. Pinhole itself is `IsAotCompatible`. |
| Direct peer TCP | **Not supported**: `RtpIceChannel` gathers UDP local candidates; its TCP sockets (`RtpTcpSocketByUri`) exist only to reach ICE *servers* (TURN over TCP/TLS). No peer-to-peer TCP candidate pairs. (#45's source inspection confirmed at this commit.) |
| TURN/TCP/TLS | Supported for reaching TURN servers; this is relay transport, not direct TCP. Not exercised in this run — no TURN server in this profile. |
| ICE restart | `RTCPeerConnection.restartIce()` exists (API present; recovery behavior not exercised here). |
| Cancellation | No first-class CancellationToken on offer/answer/channel APIs observed; closing the peer connection is the teardown primitive. Pinhole carries deadlines/cancellation through every stage. |

## Measured (same host, same payloads, same process)

| Metric | WebRTC reliable | WebRTC `maxRetransmits=0` unordered | Pinhole UDP (current) |
|---|---|---|---|
| Connect to first payload | 446 ms | 211 ms | **38.7 ms** |
| RTT p50 / p95 (32 B ping-pong) | 25,100 / 25,177 µs | 25,092 / 25,135 µs | **5 / 6 µs** |
| Throughput (1200 B messages) | 305 msg/s (3.7 MB/s) | 158 msg/s | **332,812 msg/s (399 MB/s)** |
| GC allocations (scenario) | 205 MB | 200 MB | **12 MB** |
| Working set at end | 119 MB | 127 MB | 136 MB |

Observations:

- The WebRTC RTT floor of ~25.1 ms is timer-dominated (SCTP delayed-ACK /
  ack-clock pacing), not wire time; it applies identically to the unreliable
  channel, which showed **no latency benefit** from `maxRetransmits=0` here.
- The reliable channel required 6,427 application backpressure yields
  (`bufferedAmount > 4 MB → await`) to complete a 10,000-message firehose
  without starving the in-process event loop; the unreliable mode needed
  6,472. `bufferedAmount` is real, app-visible flow control — a capability
  difference to expose, not hide: Pinhole datagram `Send` is fire-and-forget.
- Connect time includes DTLS certificate generation and ICE checks. It is
  inside the 15-second overall target but ~10x the current backend on the
  same machine, before any NAT, TURN, or cross-machine cost.
- Both WebRTC modes allocate ~17x the current backend for the identical
  workload in-process.

Limitations of this evidence: loopback only (no NAT punching, no TURN, no
loss), in-process signaling (SDP exchange cost is real but no network
signaling was measured), and no standard browser reference peer yet — the
SDP seam for one exists in the prototype. Unsupported/unmeasured modes
(direct TCP, TURN/TCP/TLS, NAT topologies, browser interop) are retained
backend responsibilities, not candidate capabilities.

## Decision (M1): retain the current backend; no migration

- The candidate cannot serve direct peer-to-peer TCP at all, cannot trim, adds
  ~6 MB and a restrictive license clause, and measures an order of magnitude
  worse on connect time, per-message latency, and throughput for datagram-style
  game/chat workloads on identical hardware.
- WebRTC's genuine advantages — browser interop, built-in reliable ordered
  delivery with application backpressure, and a standards-track TURN story —
  do not appear in Pinhole's requirement set for the host/join SDK, whose
  traffic model is exactly the unreliable small-datagram case the current
  backend serves at 332k msg/s.
- Therefore: **retain** the current UDP+TCP+iroh backend for the SDK facade
  (M2). Re-open the WebRTC evaluation only if a browser-peer requirement
  lands; the prototype and this record are the starting point, and the
  reference-peer + TURN-matrix validation would then be mandatory, not
  optional, before any adoption.
