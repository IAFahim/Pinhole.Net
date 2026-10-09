The goal remains to complete the connection techniques across the managed .NET core and the OpusVoice phone integration. Discovery defaults alone do not complete the transports, candidate coordination, router protocols or platform integration. Keep this issue open until the remaining implementations and release checks are complete.

## Completed implementation

- **Android/Kotlin PCP, NAT-PMP and UPnP router mapping:** enabled by default, uses the actual session socket, renews/releases leases and updates authenticated candidates after network changes. OpusVoice `affd577`; [OpusVoice #2](https://github.com/IAFahim/OpusVoice/issues/2) is closed. Its completed evidence includes fifteen protocol/lifecycle checks and ten interop cases; [that commit's CI](https://github.com/IAFahim/OpusVoice/actions/runs/37805542469) passed.
- **IPv4/IPv6 LAN discovery implementation and Android browsing:** core `5f4f2b0`, Android `169fd9d`. The core gathers/announces on active multicast interfaces and preserves link-local scope; foreground Android NSD browsing supports selecting a nearby receiver. Final core release/CI verification remains tracked by #41 and the validation requirement below.

## Implemented .NET drafts; cross-platform completion still pending

Core commits `50cea0f` and `dd7f8ac` contain the local implementations below. A commit or modeled pass does not establish real-network or .NET/Kotlin interoperability.

| Requirement | Implemented in the .NET core | Still required |
|---|---|---|
| Authenticated direct TCP (#43) | Bounded listener/connector/framing, fresh encrypted stream proof, reverse initiation, TCP router leases, UDP preference and recovery | Kotlin transport/path reporting, real IPv4/IPv6 socket and interop tests, previous-version compatibility/performance, OS simultaneous-open evaluation, platform CI |
| Per-interface connectivity | Up to four source-bound UDP sockets, same-source STUN and replies, IPv4/IPv6 diversity, source removal/rebind recovery, bounded candidate selection that preserves introductions/router grants | Kotlin parity, actual interface/route-change/VPN/carrier checks, per-interface TCP/router ownership |
| Initial candidate exchange/signaling-only policy | Authenticated two-way initial lists, direct-only Connect/Accept when policy is enabled, relay application-data enforcement, cancellation and recovery | Kotlin parity and actual iroh/TURN/socket/platform checks. `RelaySignalingOnly` is an explicit opt-in; normal relay data fallback remains the default |
| UPnP IPv6 firewall pinholes | Source-bound control, bounded UDP/TCP leases, renewal/refusal/expiry/disposal/interface churn and diagnostics | Kotlin parity, real gateway/source-bound socket tests and platform CI; host-firewall integration is separate |
| NAT diagnostics and bounded coordinated prediction | Fresh diagnostic-socket RFC 5780 measurements, strict correlated STUN, negotiated fresh application-socket measurements, default-enabled prediction with refusal for unreliable evidence | Cooperating real STUN servers, real carrier/router/socket coverage, resource/performance/platform checks, Kotlin parity and documented limitations |

Prediction tries at most eight measured nearby ports for six rounds, requires authenticated negotiation and normal encrypted peer proof, and never publishes guesses as reflexive candidates. Two modeled predictable symmetric NATs reach direct communication, including a signaling-only case; random allocation retains the labeled relay path. These are model results, not a real mobile-to-PC success claim. STUN cannot reliably count NAT layers, and neither diagnostics nor prediction guarantees future allocation or a permitted direct route.

## Full-scope checklist and remaining work

- [x] Implement Android/Kotlin PCP, NAT-PMP and UPnP mapping with renewal, release, network changes, candidate publication and best-effort defaults.
- [ ] Complete authenticated direct TCP across .NET/Kotlin, including real socket/security/interop checks, framing/capability negotiation, active/reverse initiation, TCP router mappings and evidence-based OS simultaneous-open evaluation. .NET draft is implemented; #43 remains open.
- [ ] Complete per-interface IPv4/IPv6 candidate gathering and checks across .NET/Kotlin, including Wi-Fi/Ethernet/cellular/VPN changes and actual per-interface TCP/router ownership. Source-bound .NET UDP draft is implemented.
- [ ] Complete initial two-way authenticated candidate exchange and explicit signaling-only relay policy across .NET/Kotlin, with real relay checks and no relayed application data under that policy. .NET draft is implemented.
- [x] Implement IPv4/IPv6 LAN multicast discovery/candidate advertisement in core and integrate Android LAN browsing/authenticated-key receiver selection where listener capabilities support it. Final release verification/issue closure remains under #41 and the end-to-end gate below.
- [ ] Complete UPnP IPv6 firewall-control pinholes across core/phone with real gateway/platform evidence, lease lifecycle and refusal handling. .NET draft is implemented.
- [ ] Complete NAT diagnostics and bounded, coordinated prediction across core/phone with real measurements, negative cases and resource limits. .NET draft is implemented; random/unstable/unresolved private mappings must fail honestly without arbitrary port scanning, and multiple NAT layers must not be claimed detectable or universally traversable.
- [ ] Implement Kotlin TURN allocations, permissions, data/recovery and independently configured fallback providers/transports, preserving peer authentication, credentials and accurate direct/relay labels. Existing .NET TURN with supplied credentials and iroh HTTPS relay support do not complete phone parity.
- [ ] Complete desktop/receiver persistent owned listener-port and normal Linux/macOS/Windows host-firewall integration, including concrete executable/port rules and reachability diagnostics. Receiver accepts a chosen port; installer/app integration remains incomplete.
- [ ] Complete the release evidence: full real-socket suites; .NET/Kotlin and previous-version interop; negative/security/resource/performance checks; topology/platform CI; fresh-install LTE/Wi-Fi, carrier/CGNAT/double-NAT, IPv4/IPv6-only and VPN tests; published changes, verified CI and documentation of measured limits. Close child issues only when their own acceptance criteria pass.

## Verified evidence and next validation

- Full solution builds for its target frameworks with **zero warnings/errors**.
- **154/154 selected actual xUnit cases pass** without OS sockets: TCP framing/crypto/session proof, router protocol/lifecycle fixtures, 20 IPv6 firewall checks, 15 signaling checks, 10 interface checks, 19 NAT diagnostics checks, 22 prediction checks, candidate-budget/default checks and modeled recovery scenarios.
- Memory streams, the independent in-memory relay and modeled NAT translation/filtering do not prove physical reachability. The compiled real TCP, IPv6 SSDP/source-bound HTTP, interface UDP and public diagnostic socket checks remain pending, as do full resource/performance/platform and phone interop runs. Current draft CI has not been verified by this update.

Run `bash .github/scripts/verify-connectivity-drafts.sh` on a host with normal socket access for the full build, functional/socket suite and separate resource/performance test processes. On macOS prepare the TURN loopback aliases using `.github/scripts/prepare-macos-loopback.sh` as CI does. This script does not replace the real phone/network runs or the Linux/macOS/Windows matrix.

Detailed implementation/remaining-work notes are in `docs/CONNECTION_ROADMAP.md`, `docs/CONNECTIVITY_AUDIT.md`, `docs/DIRECT_TCP.md`, `docs/INTERFACE_CANDIDATES.md`, `docs/RELAY_SIGNALING.md`, `docs/IPV6_FIREWALL.md`, `docs/NAT_BEHAVIOR.md` and `docs/PORT_PREDICTION.md`. Prepared child-issue bodies for interface candidates, signaling and NAT/prediction are in `docs/issues/` and are not yet published as separate issues.

Use #23 and related existing issues for security, recovery, soaks and release gates; avoid duplicating their implementations. #39 covers discovery defaults, #41 LAN discovery and #43 TCP. Pinhole.Net remains managed C#. Completion of this checklist is not an Internet-wide connection-success percentage: standard techniques improve coverage, but networks can provide no permitted direct route.
