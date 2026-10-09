# Connection techniques status — 2026-10-09

Tracking issue: [#40](https://github.com/IAFahim/Pinhole.Net/issues/40).
The issue was created before this implementation work. Keep its full scope open
until the remaining implementation and validation are complete.

About 30% is a rough estimate of implementation progress across this roadmap.
It is not a connection success percentage, a completion guarantee or a measurement
across routers/carriers. Two of ten requirements have shipped; TCP and IPv6 router
firewall work have substantial .NET drafts but are not completed across platforms.

| Requirement | Current status | Remaining work |
|---|---|---|
| Kotlin PCP/NAT-PMP/UPnP router mapping | Shipped in OpusVoice `affd577` | Real gateway/carrier coverage belongs to the end-to-end validation requirement |
| Authenticated direct TCP | .NET local draft: framing, fresh stream proof, bidirectional initiation, TCP router leases, UDP preference/recovery | Kotlin transport, interop, actual OS/socket checks and simultaneous-open evaluation; [#43](https://github.com/IAFahim/Pinhole.Net/issues/43) |
| Source-bound per-interface IPv4/IPv6 checks | Not complete; link-local scopes and LAN interface membership are supported | Gather/probe routable candidates through each active interface, prioritize checks, handle Wi-Fi/cellular/VPN changes |
| Initial two-way authenticated candidate exchange and signaling-only policy | Not implemented; current candidate announcements principally follow establishment | Exchange both sides' current candidates before direct-only application traffic; explicit API and negative tests |
| IPv4/IPv6 LAN discovery and Android browsing | Shipped: core `5f4f2b0`, Android `169fd9d` | Core final CI/issue closure pending; real LAN coverage remains part of end-to-end validation |
| UPnP IPv6 firewall-control pinholes | .NET local draft: source-bound control, UDP/TCP leases, expiry/renewal/disposal/churn and diagnostics | Kotlin parity, real socket/router/platform checks and publication; [draft details](IPV6_FIREWALL.md) |
| Rich NAT behavior diagnostics and measured bounded port prediction | Not implemented beyond the existing multi-server mapping hint | Independent measurements, coordinated predictable allocation checks, refusal for random/double NAT; no port-scanning amplification |
| Kotlin TURN and independently configured fallback providers/transports | Not implemented; .NET TURN with supplied credentials and existing iroh HTTPS relay supported | Kotlin allocations/permissions/data handling, credential/provider configuration, recovery and honest relay labels |
| Desktop persistent listener port and normal host firewall integration | Receiver accepts a chosen port; app-owned firewall integration incomplete | Linux/macOS/Windows app integration, executable/port rules and reachability diagnostics |
| Real sockets, interop, topology/platform/release evidence | Existing shipped-feature CI and fixtures; current drafts compile with warnings as errors | Execute actual socket suites and all platform/interop/resource/performance checks; repeat fresh-install LTE/Wi-Fi runs; final commits/pushes/CI |

Latest local evidence: the full solution compiles for its target frameworks with
zero warnings/errors. The actual selected xUnit methods pass **86/86** without OS
sockets: TCP framing/crypto/fresh proof/session handling, router protocol fixtures,
lease lifecycle races, 20 IPv6 firewall checks, discovery defaults and three virtual
NAT recovery scenarios. Memory streams and modeled NAT do not prove physical
reachability. Real TCP session/router and IPv6 SSDP/source-bound HTTP tests are
compiled but have not run in this restricted workspace.

Current permissions allow core source edits and temporary artifacts. They deny OS
sockets/GitHub connections, writes to the phone/receiver repositories and `.git`
mutations. The user selected continued local work with tests and pushes pending.
Do not bypass those restrictions or report the drafts as committed, pushed,
CI-green or released. Current local drafts also include the TCP router-mapping
hardening and lease-worker changes described in [DIRECT_TCP.md](DIRECT_TCP.md).

Broader evidence needed for scale and the measured limitations remain in
[CONNECTIVITY_AUDIT.md](CONNECTIVITY_AUDIT.md). No combination of these techniques
guarantees direct communication when both networks offer no permitted route.
