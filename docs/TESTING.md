# Testing: the topology/loss lab

iroh validates its connectivity claims against 70+ real network scenarios (Linux network
namespaces, `tc netem`). Pinhole's equivalent — scoped for a managed-only repo that must
run its tests identically on Linux, macOS, and Windows — is an **in-process virtual
internet** injected under the engine's socket layer. No privileges, no namespaces, no
skipped-on-Windows traits: every scenario is just another test.

## Where it lives

- `src/Pinhole/UdpSocket.cs` — the seam: `internal interface IUdpSocket` (bind, local
  endpoint, send, receive, dispose) plus `SystemUdpSocket`, the exact previous OS-socket
  behavior. `NodeEngine` talks only to the interface; `PinholeOptions.UdpSocketFactory`
  (internal, test-only) substitutes a virtual one. Production behavior is byte-identical —
  the receive-loop semantics (200 ms poll wake, timeout exceptions, dispose wake) are part
  of the contract.
- `tests/Pinhole.Tests/VirtualNet/` — the lab:
  - `VirtualNetwork` — routes datagrams between attached sockets through NATs, with
    drop/delay/reorder shaping. Zero-delay packets are delivered synchron on the sender's
    thread (loopback-causal); delayed packets ride a scheduler where jitter produces
    reorder. Every packet's fate is counted (`Counters()`), so a failing scenario reports
    its physics, not just its outcome.
  - `VirtualNat` — the four RFC 4787 behaviors (`FullCone`, `RestrictedCone`,
    `PortRestricted`, `Symmetric`): endpoint-independent mapping for cones, per-destination
    for symmetric, and the matching inbound filters. Hairpinning works (two sockets behind
    one box punch through its own public side). `ExpireMappings()` is the silent
    DHCP-renew/router-reboot event; `BlockAllOutboundDirect` is the UDP-blocked hotel.
  - `VirtualStunServer` — an RFC 5389 responder on a virtual address; behind a NAT it
    reports the NAT's public mapping, so reflexive discovery and symmetric-NAT detection
    run against real translation physics.
  - `LossModels` — `IndependentLoss` (Bernoulli) and `GilbertElliottLoss` (two-state burst
    loss), plus `Subnet`/`LinkRule` shaping rules (first match wins, post-NAT addresses).
  - `VirtualLab` — harness: binds `PinholeNode`s into the net (per-NAT or internet-
    attached hosts, fresh attachment per rebind — a rebind really changes address),
    virtual STUN, and an optional real-loopback `FakeTurnServer` relay (the relay path
    deliberately rides real sockets: the engine's fallback orchestration is under test,
    while the direct path faces the virtual physics).
- Address plan is all documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`, `2001:db8::/48`, `172.31.0.0/16` private sides) — nothing in the lab
  can touch a real network.

## The scenario matrix (`TopologyLabTests`)

The 16-cell NAT pairing theory (`NatMatrix_*`) drives every
(listener-NAT × dialer-NAT) combination with a TURN relay configured. Expected outcomes
are the classical hole-punching physics table, and the lab reproduces it exactly:

- **Direct (13 cells)** — every pairing except the three below. Cone sides punch through
  one endpoint-independent mapping; symmetric sides get in through the cone side's loose
  filter and the engine's observed-source adoption; restricted/port-restricted pairs open
  each other's filters by punching first.
- **Relay-only (3 cells)** — symmetric×symmetric, symmetric×port-restricted,
  port-restricted×symmetric: per-destination mappings on both sides make every advertised
  reflexive wrong for the other peer. The session meets on the relay and stays there —
  asserted over a quiet window with traffic still flowing.

Scenario facts beyond the matrix: UDP fully blocked (both sides — not one direct datagram
escapes, the relay carries everything, asserted via the network's delivery counters),
CGNAT hairpin through one shared NAT, silent mapping expiry healed by keepalive adoption
(~0.5 s), a v4→v6 mid-connection roam (same connection object flows on the new family),
a mid-transfer server roam (the blob ARQ completes on the rebound path), a relay restart
followed by fresh redial (ghost allocations retired, reallocation, fresh ticket), and a
relay outage while direct carries (a non-event, as it should be).

## The loss ladder (`LossLadderTests`) — the CC baseline

The blob ARQ's fixed 4×64-chunk window and 900 ms re-requests, driven by increasing loss
on the direct path, goodput logged per rung. These curves are the baseline the ARQ
congestion-control work (#20 part 2) is judged against — re-run this file before and
after any CC change and compare the logged lines.

Representative numbers (single runner, 512 KiB per rung): 1% ≈ 494 KiB/s, 2% ≈ 464,
5% ≈ 410, 10% ≈ 101, 20% ≈ 82; Gilbert-Elliott at 10% mean with bursts of 8 ≈ 251.
Two facts a CC design should know: the cliff between 5% and 10% (the fixed 900 ms
re-request dominates once several rounds are needed), and that bursty loss at the same
mean is *gentler* than independent loss — clean stretches between bursts let the window
run, while iid loss at 10% keeps every round short.

Assertions are deliberately loose (completion, byte-exact verification, curve ordering);
exact goodput is machine-dependent and belongs in the logs.

## Known gaps the lab established

- **A TURN-relayed session cannot survive its single TURN server restarting in place.**
  This is a TURN-specific property: TURN peers address each other by *allocation*
  transport addresses, which die with the server process — both peers hold addresses on
  the dead server and, with no other path, no channel remains to learn the fresh ones.
  The iroh HTTPS relays are different by construction: they are dialed by *identity*
  (peer key), so a restarted relay is re-reached through the same URL and key without any
  address re-learning; their outage behavior is reconnect/backoff, not address death —
  not covered by this lab's restart scenario either way. What IS guaranteed for TURN now:
  a *definitive* rejection (437 allocation mismatch — `TurnRejectException`) retires the
  ghost client and reallocates within the path-validation window, while a *transient*
  permit failure (lost datagram, timeout) retries the permit and never flaps a healthy
  allocation; the server re-advertises fresh relay candidates, and a fresh-ticket redial
  heals in ~9 s end to end.
- **Relay-leg liveness** now mirrors direct-path validation: a degraded relay-carried
  session probes its relay when silent and escalates to the same suspect machinery
  (before the lab, a dead relay black-holed relayed traffic until the minutes-long TURN
  refresh cadence noticed).

## Adding a scenario

One test, one `VirtualLab`. Bind nodes with `lab.BindNodeAsync(nat)` or
`lab.BindNodeAsync(hostAddress: …)`; shape paths with `lab.Net.AddRule(LinkRule…)`;
assert outcomes and print `lab.Net.Counters()` so failures carry their physics. For blob
scenarios, `BlobServer`/`BlobClient` take the same options via `NodeOptions`
(`lab.BaseOptions(...)` + your socket factory). Deterministic seeds for loss models keep
a rung reproducible; budgets come from `TestBudget`.

## Real-infrastructure tests (#26): real relays, real OS sockets

`tests/Pinhole.Tests/RealNet/` runs scenarios against REAL external infrastructure —
no virtual network, no fake relay — on the production `SystemUdpSocket` path:

| Scenario | Infrastructure | What it proves |
|---|---|---|
| relay-only connect + flow | a real `iroh-relay` server process (dev HTTP on loopback) | the managed iroh-relay WebSocket client interoperates with the reference server; relay-only sessions are `Degraded` + end-to-end encrypted; no hidden UDP bypass (all non-relay candidates stripped from the string) |
| 256 KiB blob download through the relay | same | the full blob stack (Hello/Welcome negotiation, sealed frames, BLAKE3 verification) over a real relay |
| real relay process death + restart | kill the server, start a fresh process on the same port | the logical connection object survives a REAL server restart and heals onto an available path; the healed path (direct or relay) is recorded in the report |
| TURN relay connect + flow | a real `turnserver` (coturn) process, RFC 5766 UDP, long-term credentials | `TurnClient` interoperates with the reference TURN server |

### Running them

```sh
cargo install iroh-relay --features server --version 1.3.0 --locked   # pinned, test-only
IROH_RELAY_BIN="$(cargo bin --find iroh-relay 2>/dev/null || echo ~/.cargo/bin)/iroh-relay" \
  dotnet test -c Release --filter "FullyQualifiedName~RealNetworkTests"
# TURN scenario: provide any coturn build, e.g. COTURN_BIN=/usr/bin/turnserver
```

Without the env vars the tests SKIP with instructions (they never touch public relay
operators). Every run leaves `report.json` (tool + version, socket implementation, relay
protocol, duration, healed-path note) and the captured server logs under
`$TMPDIR/pinhole-realnet/<scenario>-*/` — kept on pass and fail as evidence.

### Honest division of evidence

- **Real**: the relay/TURN protocol interop above, plus every plain loopback test in the
  suite (those have always used real kernel sockets — direct path, real UDP).
- **Virtual (portable, every OS)**: NAT matrix physics, loss/delay shaping, blocked-UDP
  hotels, CGNAT hairpin — the topology lab above, which can force topologies a
  loopback machine physically cannot.
- **Root-gated, documented gap**: full kernel-level NAT/firewall/impairment matrices
  (Linux namespaces via the Patchbay CLI, or `ip/nft/tc`) are not yet wired into the C#
  harness; the scenarios exist virtually and the tools are external, so the remaining
  work is a TOML scenario set + runner permissions (needs `CAP_NET_ADMIN`), no new
  simulator. A Linux-namespace run will never be reported as Windows/macOS validation.

## #29 — rediscovery (persistent identity, signed address records)

`RediscoveryTests.cs` runs on real loopback sockets with an in-process
`Pinhole.Rendezvous` introducer — no virtual network, no external processes.

| Scenario | Test | Proof |
|---|---|---|
| Identity persistence | `SameSeed_FullIdentityStableAcrossRestart` | same seed ⇒ same peer ID, static key, endpoint key across binds; v3 ticket round-trips; truncated v3 refused |
| Record authentication | `RecordVerification_AcceptsGoodRecordOnly` | good record passes; wrong pin, wrong peer id, any tampered byte, expiry, truncation all fail |
| Rollback protection | `RecordRollback_RejectedBySequenceCache` | strictly-older sequence rejected, same sequence retried, per-peer independence |
| Introducer passthrough | `RendezvousServer_PassesRecordsThroughAndStaysLegacyCompatible` | record served verbatim; legacy clients keep the endpoint form; hostile payloads ignored |
| Restart without a new ticket | `ReconnectAfterRestart_NoNewTicket` | the acceptance criterion: same seed revived on a fresh port, old ticket still connects, identity identical |
| Simultaneous roam | `BothPeersRoamSimultaneously_EitherDirectionReconnects` | both peers rebind; both stale tickets heal, both directions |
| All cached addresses dead | `AllCachedAddressesDead_RediscoveredRecordCarriesTheDial` | the fresh port demonstrably enters the dialer's candidate set |
| Poisoning | `PoisonedRecord_CannotImpersonate_OnlyDeniesAvailability` | a live impostor's self-consistent record and a forged-signature record are both refused; the impostor node never sees a session |
| Stale records | `StaleRecord_DeadEndpoints_TimesOutWithoutImpersonating` | an authentic record pointing at a dead address: honest timeout |
| Provider outage | `ProviderOutage_AllProvidersDown_DialFailsCleanlyAndBounded` | dead introducer + throwing provider ⇒ bounded, honest timeout |
| Multiple providers | `MultipleProviders_DeadFirst_LiveSecondStillHeals` | first-verified-wins across a dead and a live provider |

The "relay restart with changed TURN addresses" case from the issue is covered at the
reachability-record level by `AllCachedAddressesDead_...` (every cached address replaced);
relay *failure* recovery itself is #30's scope, and records deliberately carry no relay
candidates (they would embed TURN credentials).


## #30 — relay failover and changed allocations

`RelayFailoverTests.cs` runs in the virtual lab against two or three *independently
addressed* TURN servers (each fake on its own loopback IP, mirroring real deployments),
short allocation lifetimes so a killed server is detected in seconds, and the RFC
receive-side permission gate ON by default. `FakeTurnServer` gained that gate plus
injectable allocation refusals (quota/auth) and send-path counters.

| Scenario | Test | Proof |
|---|---|---|
| Lose one of two relays | `TwoRelays_LoseOne_RelayOnlySessionSurvivesOnTheSurvivor` | relay-only session keeps flowing on the survivor, same connection objects |
| Relay restarts in place, both allocations change | `RelayRestartInPlace_BothAllocationsChange_SessionHealsWithoutFreshTicket` | same session object heals via reallocation announce + #29 records; new relayed address adopted |
| Differing relay preferences | `DifferingRelayLists_MeetThroughTheCommonRelay` | A=[X,Y], B=[Y,Z] meet through Y under strict permissions |
| Quota/rate-limit refusal | `QuotaRefusal_RetriesAreBoundedAndRecoveryIsImmediate` | ladder gates retries to one attempt per step; immediate recovery once accepted |
| All relays down, then restored | `AllRelaysTemporarilyDown_SessionPendsThenRecoversOnRestoration` | explained pending state (no close, no false health), self-recovery on return |
| Relay DNS failure containment | `UnresolvableIrohHostname_DirectPathUnaffected` | bind stays bounded, direct path unaffected, `HasRelay` honest |

Two engine defects found by these tests and fixed in the same change: relay-leg
flapping (a cross-leg arrival demoting the confirmed leg into a permission livelock)
and condemned relay legs keeping their ready mark forever. The single-relay restart
cell in `TopologyLabTests` (fresh-ticket redial) remains as the pre-1.10 behavior
witness; the in-place heal above supersedes it operationally.

Real-infrastructure coverage: the #26 harness (`docs/TESTING.md` § #26) still runs
iroh-relay and coturn processes on real sockets; a second coturn instance for
cross-server permission behavior is the remaining env-gated gap (COTURN_BIN).


## #31 — resilience: outages, suspend-like pauses, MTU changes

`ResilienceTests.cs`, virtual lab, engine timers compressed below the outage durations
(the long-outage cell's real wait stands in for the issue's five-minute regime by
exceeding every configurable budget):

| Scenario | Test | Proof |
|---|---|---|
| 1 s outage | `BriefOutage_1s_...` | under the validation budget: never left `Open`, no ceremony |
| 30 s outage | `Outage30s_...` | honest wounded state, bounded datagram spend (no storm), same-object heal |
| Outage past every budget | `OutageLongerThanEveryBudget_...` | honest `Dead`, same-object revival when the route returns (crypto counters/replay window intact) |
| Suspend-like pause | `SuspendLikePause_...` | 12 s total silence; timers fire once after wake (no storm, bounded probes), traffic returns |
| No network notifications | `NoNetworkWatch_TotalStunSilence_...` | total STUN silence at the periodic refresh itself drives the bounded revalidation/rebind; reflexives recover with visibility |
| MTU shrinks mid-flow | `MtuShrankMidFlow_...` | RFC 8899 re-verification catches the shrink, falls back to the floor, keeps flowing |
| MTU across migration | `MtuClimbResetsOnPathMigration` | rebind (endpoint change) forgets the old path's confirmed MTU and re-climbs |
| Faulted dial stays dead | `FaultedDial_IsNeverZombieRevived` | a pin-refused dial is never revived into `Open` by later traffic |
| Dispose wins | `DisposeDuringRecovery_...` | disposal mid-recovery silences the node; its peer never comes back to life |

Engine changes that surfaced here: the punch budget is monotonic (suspend-proof), PMTU
re-verification (`PmtuReprobeInterval`, default 5 min) detects a mid-connection MTU shrink
and falls back, path migration resets the PMTU climb, total-STUN-silence at the refresh
triggers recovery when OS notifications are absent, and a `Dead` connection keeps bounded
1/s beacons for five minutes (completed handshakes only — stranger-flood husks never
beacon) so a rebinded peer can be found again.

**Known gap**: a BOTH-sides-`Dead` rebind while the STUN path is dark (stale reflexives)
does not heal in the lab — beacons flow but PACK replies do not return. The single-side
variants (RoamingTests' rebind, the outage ladder above) all heal; the corner is recorded
rather than claimed.
