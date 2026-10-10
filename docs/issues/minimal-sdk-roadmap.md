# Minimal connection SDK roadmap — 2026-10-10

GitHub plan: [#45](https://github.com/IAFahim/Pinhole.Net/issues/45).
This is the published plan and issue-disposition snapshot; implementation checkboxes
remain pending until their own evidence is attached.

## Outcome

Two people run an application, share an invitation code, and connect with a few lines of C#. Players do not need Steam integration, a Pinhole account, manual port forwarding, or knowledge of signaling, ICE, relay credentials, and NAT types.

Pinhole supplies the small developer API and infrastructure integration. Prefer maintained networking libraries and existing services for the implementation. Applications send their own bytes; games, chat, audio, and optional file transfer can use the same connection facility.

**Owner clarification, 2026-10-10: direct UDP, direct TCP, NAT punching, and automatic connection selection remain required. Optimize both time to connected application traffic and ongoing latency. WebRTC is a candidate backend, not an instruction to remove those capabilities or rewrite the working transport.**

This issue replaces the planning mandates in #15, #23, and #40. Their outstanding useful requirements are mapped below; closing those planning issues as superseded does not mean their original implementations are complete. Existing security, compatibility, recovery, and resource requirements remain.

## Product contract and boundaries

- Account-free for end users. An infrastructure operator may still need a provider account, credentials, and a budget. Developers configure the service once; players share codes.
- Keep the SDK, adapters, samples, and tests managed C# under the existing requirement. Inspect transitive dependencies. Existing external network-test tools and relay servers remain separate infrastructure. A native transport dependency is not silently approved by choosing another protocol.
- Preserve direct UDP, direct TCP, hole punching, encrypted relay fallback, explicit deadlines, cancellation, and authenticated peer admission. A direct route is attempted when viable; NAT hints are hints, not proof that an attempt cannot work.
- Automatically establish a usable authenticated route within one overall deadline. Improve a working route when measured latency and stability justify it. No promise of the mathematically fastest path or universal connectivity.
- Carry arbitrary application messages with explicit message-size, reliability, ordering, and backpressure capabilities. Backend limits are reported, not hidden. Existing unreliable datagram semantics do not become a reliable-delivery promise.
- This is an SDK integrated by an application developer. It does not modify an uncooperative Steam game, provide a transparent IP/TCP/QUIC tunnel, or require a new game engine, lobby framework, DHT, general congestion framework, or custom cryptographic protocol.
- One host and one joining peer is the first supported workflow. Multi-peer rooms, presence, matchmaking, file synchronization, and audio device integration are separate optional work.

## Proposed developer experience

Conceptual API; names and signatures are not yet implemented:

```csharp
// Host application, with service configuration supplied once at startup:
await using var host = await Pinhole.HostAsync(ct: ct);
Console.WriteLine(host.Code);
await using var connection = await host.AcceptAsync(ct);
await connection.SendAsync(payload, ct);

// Friend's application:
await using var connection = await Pinhole.JoinAsync(code, ct: ct);
await foreach (var message in connection.ReceiveAsync(ct))
    Handle(message);
```

- [ ] Implement a runnable two-process host/join example requiring at most ten SDK statements per side, excluding application handlers and one-time operator configuration.
- [ ] Expose connection state, cancellation/deadline, actual route, maximum message size, and supported delivery modes. Keep provider and candidate tuning in optional configuration.
- [ ] Keep the backend seam internal and minimal while evaluating two implementations. Do not build a plugin framework or promise that every transport can implement every capability.
- [ ] Preserve `PinholeNode`, `PinholeConnection`, existing tickets, and existing applications during the prototype. Introduce the host/join layer additively; decide packaging after measuring dependencies and package size.

## Architecture and reuse decisions

| Concern | Reuse / initial choice | Pinhole's responsibility |
|---|---|---|
| Current direct UDP/TCP and iroh fallback | Existing tested Pinhole backend | Preserve compatibility and fix defects; use it as the comparison baseline. |
| Standard traversal, encrypted data channels, reliability | Evaluate pinned SIPSorcery first; another maintained managed implementation only if a concrete blocker warrants it | Small adapter and capability reporting. Do not hand-port ICE, DTLS, SCTP, or a new ARQ stack. |
| Invitation lookup and signaling | Existing signaling examples/service capabilities and .NET HTTP/WebSocket support | Narrow code-to-session coordination, expiry, admission and backend agreement. Extend the existing rendezvous service only if that is smaller than reusing an established service. |
| Relay infrastructure | Cloudflare Realtime TURN plus configurable standard/self-hosted TURN; retain existing iroh routes in the current backend | Server-side issuance/refresh of temporary credentials, provider configuration, cost limits, honest route labels and outage handling. |
| Diagnostics and tests | Existing .NET diagnostics, CI, Patchbay, coturn, reference relay and property-test tools | Redacted SDK-level measurements and scenario adapters. |
| Verified files/directories | Existing optional `Pinhole.Blobs` and #14/#32 | Preserve verification/resume. File transfer is not required to implement host/join. |

### Feasibility questions that must be answered before migration

The inspected SIPSorcery source is pinned at `3ef46acfa05cbfb74debea457f64f445a9908786`. Its [ICE candidate handling](https://github.com/sipsorcery-org/sipsorcery/blob/3ef46acfa05cbfb74debea457f64f445a9908786/src/SIPSorcery/net/ICE/RtpIceChannel.cs) rejects non-UDP remote candidates while separately containing TCP/TLS connections to ICE servers. **TURN reached over TCP/TLS is not proof of direct peer-to-peer TCP.** Keep #43 and the current direct TCP route unless an alternative proves that capability.

Its [data-channel implementation](https://github.com/sipsorcery-org/sipsorcery/blob/3ef46acfa05cbfb74debea457f64f445a9908786/src/SIPSorcery/net/WebRTC/RTCDataChannel.cs) also warrants a concrete unreliable-channel test: verify unordered delivery and the actual meaning of zero retransmissions under loss. Configuration names are not evidence of behavior. The current [license](https://github.com/sipsorcery-org/sipsorcery/blob/3ef46acfa05cbfb74debea457f64f445a9908786/LICENSE.md) includes additional use restrictions; evaluate the exact package license and distribution fit rather than assuming unrestricted BSD terms.

- [ ] Record candidate version/commit, maintenance evidence, exact license, transitive packages, managed/native footprint, installed size, AOT/trimming result, cancellation, buffering, message limits, delivery semantics, direct TCP, TURN/TCP/TLS and ICE-restart support.
- [ ] Run a bounded proof of concept using the candidate's existing features and production sockets. Publish blockers and small required adapter work, with source links and real results.
- [ ] Compare current backend, candidate backend, and a hybrid retaining current direct TCP. Adopt only the smallest option that satisfies the declared capabilities and demonstrably reduces maintenance.
- [ ] Stop at the feasibility decision if the candidate cannot satisfy requirements. Keep the current backend and small SDK facade rather than growing a replacement networking stack to rescue the migration.

## Invitation, signaling, and infrastructure

Short codes need an available coordination service. A TURN server relays packets; it does not by itself create the host/join directory.

- [ ] Specify invite format/version, entropy, lifetime, host ownership, allowed join count, expiry/revocation, rejoin policy, collision handling, rate limits and maximum active rooms. Reuse standard cryptographic randomness and established admission mechanisms.
- [ ] Treat an invitation as a capability and document its trust model. Authenticate the exchanged peer key/DTLS fingerprint; DTLS encryption alone does not prove a friend's identity. If short codes require trusting the coordinator, disclose that choice and offer an authenticated full invitation/confirmation path. Do not weaken existing pinned-key tickets or invent a PAKE.
- [ ] Keep signaling payloads, offers/answers, candidates, ICE generations, queues and reconnect work bounded. Reject stale/cross-session messages and close abandoned rooms.
- [ ] Keep provider master secrets server-side. Issue short-lived scoped TURN credentials; handle renewal, revocation, expiry, provider outage and quotas without embedding an API token in the SDK or game.
- [ ] Provide a configured hosted service and a self-hosted option using existing components. Record operator ownership, deployment/runbook, separate signaling costs, usage accounting, budget controls and support limits before advertising zero-configuration public infrastructure.
- [ ] Keep signaling and relay providers replaceable through narrow configuration. A provider outage must not stop an established direct connection when coordination is no longer needed.

As checked on 2026-10-10, Cloudflare lists **1,000 GB of monthly free egress shared across Realtime SFU and TURN**, then **$0.05/GB**; other infrastructure has separate pricing. This is a provider allowance, not unlimited per-player bandwidth or a permanent Pinhole SLA. See [pricing](https://developers.cloudflare.com/realtime/sfu/platform/pricing/) and [temporary credential generation](https://developers.cloudflare.com/realtime/turn/generate-credentials/). Use TURN without requiring an SFU for the two-peer data use case.

## Automatic connection and latency policy

- [ ] Under #28, use bounded concurrent/staggered viable direct UDP, direct TCP and relay attempts under one deadline. Reuse a backend's existing candidate checks rather than layering a second ICE implementation over it.
- [ ] Do not let dead DNS, a blackholed address family, failed direct punching, or one stalled provider serially consume every alternative's budget. Begin relay preparation early enough to provide prompt fallback.
- [ ] Agree backend and authenticated session on both ends. Competing successful attempts cannot create duplicate logical sessions, deliver application data twice, silently change identity, or downgrade authentication.
- [ ] Return after authenticated application traffic is usable, not merely after a socket connects or a candidate is nominated. Continue bounded improvement probes where supported.
- [ ] Measure route RTT, loss and stability. Select improvements with hysteresis and a declared policy; distinguish lowest observed latency, direct preference and relay cost. Never label TURN/TCP as direct TCP.
- [ ] Define recovery and pending-send behavior, backpressure and terminal conditions. Preserve the logical SDK object for supported live-process changes; a backend replacement/restart must not imply lossless or exactly-once replay.
- [ ] Retain the current 15-second overall connect target until the measured comparison establishes a better supported default. Freeze p95/p99 connection, recovery, traffic and resource budgets before accepting a new default; do not loosen existing floors to make it win.

## Execution order and exit gates

### M0 — Scope and issue audit

- [x] Record the owner goal: minimal host/join codes, end-user account-free use, reuse first, direct UDP/TCP, punching and automatic low-latency connectivity.
- [x] Publish the complete issue disposition and cross-links below; supersede redundant planning mandates without removing working code or safety gates. #15/#23/#40 are closed as superseded/not planned under the previous scope; the other sixteen audited issues remain open.

### M1 — Comparative feasibility prototype

- [ ] Add an isolated noninteractive C# prototype using pinned existing WebRTC components and a bounded signaling setup; use existing test credentials/infrastructure configuration, not production master secrets.
- [ ] Demonstrate two .NET peers and a standard WebRTC reference peer. Confirm supported reliability modes and source/route labels, then compare the same payload/workloads with the current backend.
- [ ] Test direct IPv4/IPv6 UDP, reachable direct TCP, NAT-punched UDP, TURN/UDP, TURN/TCP and TURN/TLS separately. Unsupported modes are blockers or retained-backend responsibilities, not passing tests.
- [ ] Produce an adoption/hybrid/retain decision with dependency size, C# integration code to maintain, licensing, support and measured latency/resource evidence. No migration by assumption.

### M2 — Small host/join facade and coordination

- [ ] Implement only the accepted facade/adapter and code service integration, including deadlines, cancellation, authenticated invites and provider credential handling.
- [ ] Run separate-machine host/join examples without Steam SDK or player login. Existing ticket-based applications still pass their compatibility checks.

### M3 — Automatic routing and recovery

- [ ] Finish #28/#29/#30/#31/#43 for the selected capability set: bounded racing, authenticated discovery, provider failover, same-session recovery, direct UDP/TCP and truthful diagnostics.
- [ ] Exercise cancellation at every establishment/recovery stage; losing attempts and disposal retire owned sockets, timers, queues, sessions and relay allocations.

### M4 — Real network, platform, security and performance evidence

- [ ] Reuse #24/#25/#26/#27/#33/#34. Cover same LAN, separate NATs, carrier/CGNAT, symmetric/blocked UDP, IPv4-only/IPv6-only, VPN, slow/failed provider, signaling loss, and 1-second/30-second/5-minute outages.
- [ ] Test real Windows/Linux/macOS on declared .NET versions. Test the actual phone/C# runtime or an existing compatible Android integration; do not hand-write a second WebRTC protocol stack. Any conflict with the managed-only/support requirements needs an explicit decision before adoption.
- [ ] Run real Wi-Fi ↔ LTE and VPN transitions, suspend/resume and declared background support with authenticated traffic on the proposed backend. Existing phone results validate the existing backend only.
- [ ] Measure attempt counts/failures, time to first usable application message and recovery, p50/p95/p99 RTT, loss/delivery semantics, idle traffic, relay bytes, allocation/CPU/heap and fairness. Match topology, endpoints, payload, verification and deadlines between candidates.
- [ ] Complete independent review of invitation trust, signaling/fingerprint binding, provider credentials, adapter concurrency, migration and retained custom code. Upstream reuse does not replace integration review.
- [ ] Run 24-hour and 72-hour workloads on exact candidate hashes with declared resource budgets and scenario coverage. The running `4f3caea` two-client cancel/resume/short-blackout soak remains useful baseline evidence, not proof of new WebRTC/signaling behavior or all #34 scenarios.

### M5 — Compatibility, canary and conditional retirement

- [ ] Use #17/#35 to verify package/API/ticket compatibility and dependency/license/support documentation. Different wire protocols must explicitly agree a backend; existing Pinhole tickets do not magically become WebRTC-compatible.
- [ ] Ship additively/opt-in first with retained current backend, a canary, diagnostics and rollback. Existing required performance/security gates remain.
- [ ] Change the default only after the comparison and release gates pass. Announce any later legacy deprecation with a versioned migration/support period and replacement evidence for every retained capability.
- [ ] Obtain the existing owner merge/release approval at the final reviewable release step. This planning issue does not authorize production service deployment or paid provisioning.

## Existing issue disposition

Audit baseline: **19 open Pinhole.Net issues**, read individually on 2026-10-10. OpusVoice and `YouAnd-I/OpusVoice.Receiver` had no open issues at the audit; [OpusVoice draft PR #4](https://github.com/IAFahim/OpusVoice/pull/4) remains a current-backend interoperability change and is not automatically merged, closed or deprecated.

| Issue | Disposition | Requirements and next home |
|---|---|---|
| #15 connection-power audit | Superseded planning issue | Its remaining measured relay-selection decision goes to #28/#27 and this route policy. Historical plaintext/identity/discovery/PMTU claims are not current implementation facts. |
| #23 reliability roadmap | Superseded planning issue | This becomes the product roadmap. Retain its authenticated recovery, managed C#, deadlines, evidence and release obligations in the existing child issues. |
| #40 implement all techniques across core/phone | Superseded exhaustive implementation mandate | Direct UDP/TCP stay required (#43/#28); candidate/interface and recovery needs stay in #28/#31/#33. Reuse standard-library signaling/TURN when proven. Additional handwritten Kotlin parity, port prediction and IPv6 gateway pinholes are conditional on measured gaps, not prerequisites to the simple SDK. Persistent listener/firewall and truthful platform behavior remain #43/#33/#35 responsibilities. Keep existing implementations. |
| #14 blobs | Optional application layer; keep open | Existing verified file/directory APIs and missing gates remain. Outside initial host/join MVP; historical core-plaintext descriptions are obsolete. |
| #17 test/release discipline | Keep open | Reuse current CI/API/warnings gates; add adapter/invitation traces and compatibility evidence. |
| #20 managed component/congestion selection | Rescope; keep open | Own the evidence-based managed component comparison. Custom blob ARQ/controller tuning is conditional/optional, not a required new framework or duplicate WebRTC reliability layer. |
| #24 security review | Keep open | Include invite admission, signaling/fingerprint trust, provider credentials, adapter and retained transport. Existing review limitations remain visible. |
| #25 diagnostics | Keep open | Normalize backend, direct UDP/TCP versus relay transport, connection/latency/recovery measures and safe redaction. |
| #26 real topology | Keep open | Test actual SDK backends with existing tools/servers and actual blocked-UDP captures/counters. |
| #27 bottleneck/performance | Keep open | Compare current/candidate/hybrid under matched conditions; separate connection time, unreliable messages and reliable transfers. |
| #28 candidate racing | Extend; keep open | Own bounded automatic selection, backend agreement, authenticated completion and measured route upgrades. |
| #29 identity/rediscovery | Extend; keep open | Account-free invite lookup, authenticated signaling/key binding and restart/roaming freshness; no new DHT. |
| #30 relay recovery | Keep open | Existing/configured provider outages, expired/refreshed credentials, independent fallback and honest service limits. |
| #31 logical recovery | Keep open | Same SDK object, ICE restart or retained-backend recovery, bounded outage behavior and explicit delivery limits. |
| #32 blob resume | Optional application layer; keep open | Verification/checkpoint/crypto invariants still apply; reusing a reliable channel does not implement durable resume. |
| #33 platform/device | Keep open | Validate actual selected components and the retained direct TCP/UDP capabilities; existing passes are baseline only. |
| #34 resources/soaks | Keep open | Cover adapter, signaling, racing and recovery work plus retained transport; preserve and correctly scope the running baseline soak. |
| #35 release gate | Keep open | Exact-candidate compatibility, supported cohorts, review, managed/licensing evidence, canary and rollback. Optional blob issues block a blob release, not a connection-only MVP by association. |
| #43 direct TCP | Required; keep open | Preserve direct TCP and phone interoperability. TCP/TLS to a TURN server is a different capability; no TCP simultaneous-open guarantee without actual OS evidence. |

Completed #18/#38/#41/#42/#44 stay closed. Their useful code, regression tests and evidence remain. **Only planning mandates are superseded now. No public API, package, wire format or current transport is deprecated by this issue.**

## Final acceptance

- [ ] Two supported applications connect by shared invitation code with minimal SDK calls and no player accounts/Steam SDK.
- [ ] Direct UDP, direct TCP and NAT punching remain available, with authenticated automatic fallback and measured selection latency.
- [ ] The adopted implementation demonstrably reduces custom code/maintenance without dropping required capabilities or inventing another protocol stack.
- [ ] Capability limits, infrastructure ownership/costs, invitation trust, lifecycle behavior and platform evidence are explicit.
- [ ] The exact release candidate satisfies retained security, compatibility, resource and recovery gates; rollout is reversible.

**First implementation task: M1, the bounded comparative prototype. The working transport remains the baseline until that evidence supports a change.**

