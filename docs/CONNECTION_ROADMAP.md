# Connection techniques status — 2026-10-09

Tracking issue: [#40](https://github.com/IAFahim/Pinhole.Net/issues/40).
The issue was created before this implementation work. Keep its full scope open
until the remaining implementation and validation are complete.

Two of ten requirements have shipped. Five more now have substantial .NET drafts:
TCP, IPv6 router firewall leases, source-bound UDP interface candidates, initial
authenticated candidate exchange/signaling-only relays, and NAT diagnostics with
coordinated measured port prediction.
They are not complete across the phone, platforms and real networks. No percentage
here measures connection success across routers/carriers.

| Requirement | Current status | Remaining work |
|---|---|---|
| Kotlin PCP/NAT-PMP/UPnP router mapping | Shipped in OpusVoice `affd577` | Real gateway/carrier coverage belongs to the end-to-end validation requirement |
| Authenticated direct TCP | .NET local draft: framing, fresh stream proof, bidirectional initiation, TCP router leases, UDP preference/recovery | Kotlin transport, interop, actual OS/socket checks and simultaneous-open evaluation; [#43](https://github.com/IAFahim/Pinhole.Net/issues/43) |
| Source-bound per-interface IPv4/IPv6 checks | .NET local draft: bounded source sockets, same-source STUN/checks, selected-source direct traffic, removal/rebind recovery and diagnostics | Actual source-bound socket/route-change/platform checks, Kotlin parity and per-interface TCP/router ownership; [draft details](INTERFACE_CANDIDATES.md) |
| Initial two-way authenticated candidate exchange and signaling-only policy | .NET local draft: authenticated initial lists, direct-only completion/acceptance, relay data enforcement and recovery | Real iroh/TURN/socket/platform validation and Kotlin parity; [draft behavior](RELAY_SIGNALING.md) |
| IPv4/IPv6 LAN discovery and Android browsing | Shipped: core `5f4f2b0`, Android `169fd9d` | Core final CI/issue closure pending; real LAN coverage remains part of end-to-end validation |
| UPnP IPv6 firewall-control pinholes | .NET local draft: source-bound control, UDP/TCP leases, expiry/renewal/disposal/churn and diagnostics | Kotlin parity, real socket/router/platform checks and publication; [draft details](IPV6_FIREWALL.md) |
| Rich NAT behavior diagnostics and measured bounded port prediction | .NET local draft: fresh-socket RFC 5780 diagnostics, strict correlated STUN, negotiated actual-socket sampling and bounded attempts/refusal | Real sockets/cooperating servers/carriers, resource/performance/platform checks, Kotlin parity and evidence limits; [diagnostics](NAT_BEHAVIOR.md), [prediction](PORT_PREDICTION.md) |
| Kotlin TURN and independently configured fallback providers/transports | Not implemented; .NET TURN with supplied credentials and existing iroh HTTPS relay supported | Kotlin allocations/permissions/data handling, credential/provider configuration, recovery and honest relay labels |
| Desktop persistent listener port and normal host firewall integration | Receiver accepts a chosen port; app-owned firewall integration incomplete | Linux/macOS/Windows app integration, executable/port rules and reachability diagnostics |
| Real sockets, interop, topology/platform/release evidence | Existing shipped-feature CI and fixtures; current drafts compile with warnings as errors | Execute actual socket suites and all platform/interop/resource/performance checks; repeat fresh-install LTE/Wi-Fi runs; final commits/pushes/CI |

Latest local evidence: the full solution compiles for its target frameworks with
zero warnings/errors. The actual selected xUnit methods pass **154/154** without OS
sockets: TCP framing/crypto/fresh proof/session handling, router protocol fixtures,
lease lifecycle races, 20 IPv6 firewall checks, 15 signaling checks, 10 interface
checks, 19 NAT diagnostics checks, 22 prediction checks, candidate-budget
preservation, discovery defaults and three virtual NAT recovery scenarios.
Memory streams and modeled NAT do not prove physical reachability. Real TCP
session/router, public NAT diagnostics, interface-source UDP and IPv6 SSDP/source-bound
HTTP tests compile but have not run in this restricted workspace.

The user has authorized testing/publication and is handling commits/pushes and
network-dependent checks. The current tool sandbox still denies OS sockets/GitHub
CLI connections, writes to the phone/receiver repositories and `.git` mutations.
Read-only probes confirmed these tool restrictions; they do not establish that the
host PC lacks internet or account access. Another actor committed the earlier TCP,
IPv6 firewall and initial signaling drafts as `50cea0f` during this local work;
current source/interface/signaling/NAT/prediction changes are not included in that commit.
Do not bypass restrictions or infer remote push/CI/release success from local git
state. The TCP router-mapping hardening and lease-worker changes remain described
in [DIRECT_TCP.md](DIRECT_TCP.md).

Broader evidence needed for scale and the measured limitations remain in
[CONNECTIVITY_AUDIT.md](CONNECTIVITY_AUDIT.md). No combination of these techniques
guarantees direct communication when both networks offer no permitted route.

For the user's host-side checks, run
`bash .github/scripts/verify-connectivity-drafts.sh`. It runs the full warning-free
solution build, functional/socket checks, resource checks in a fresh process and
performance checks in another fresh process. Linux/macOS/Windows CI, Kotlin
interop and real router/carrier/VPN runs are additional release evidence, not
replaced by this local script. On macOS, prepare the TURN loopback aliases as CI
does with `.github/scripts/prepare-macos-loopback.sh` before running the suites.
Local child-issue bodies for publication are in [relay signaling](issues/relay-signaling.md),
[interface candidates](issues/interface-candidates.md) and
[NAT diagnostics/prediction](issues/nat-measurement-prediction.md); the already-created
parent #40 remains the authoritative full-scope tracker.
