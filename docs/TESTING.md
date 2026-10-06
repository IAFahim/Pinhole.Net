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


## #32 — transfer recovery and resume

`BlobResumeTests.cs`, virtual lab, one `DownloadAsync` call per scenario — the question
is never "does a retry work" but "does the SAME call finish byte-exact". FlowBytes =
512 KiB through an 8 Mbit/s shaped link unless noted.

| Scenario | Test | Proof |
|---|---|---|
| 30 s total blackout | `ThirtySecondBlackhole_SameCall_RidesOutAndCompletes` | one call sits through an outage past the 30 s stall clock (paused while pathless) and completes; 41 retransmits, 0 conservative resumes |
| Direct path cut mid-transfer | `DirectPathCut_MidTransfer_CompletesThroughTheRelay` | same connection degrades to the relay leg; transfer continues without losing verified progress |
| Provider rebind + 3 s blackout | `ProviderRebindAndBlackout_MidTransfer_SameCallCompletes` | session heals onto the provider's new endpoint mid-transfer |
| Provider process restart | `ProviderRestart_SameTicket_ResumesFromCheckpointInOneCall` | the original call re-dials the same ticket; the successor serves only the tail (374 chunks vs 512 total — checkpointed prefix never re-crosses the wire) |
| Wrong-identity responder | (see below) | a stranger who never answers is indistinguishable from a dead provider — riding out is correct; refusal must actually ARRIVE to be terminal |
| Refused dial (incompatible peer) | `IncompatiblePeer_RefusalIsTerminal_NotRiddenOut` | kepless-peer refusal surfaces in ~30 ms, never riding the 10 min budget |
| Tampered chunks | `TamperedFrame_IsTerminal_NeverRiddenOut` | first bad chunk fails CV verification terminally; no recovery budget spent |
| Cancellation mid-blackout | `Cancellation_DuringBlackout_TerminatesPromptly` | honored in ~3 ms while the route is dark |
| Session key freshness | `SessionRecreations_NeverReuseAKeyOrNoncePair` | provider drops every chunk past 80 on a live path; the stall re-dials; every Welcome's provider nonce is stable within a session and distinct across sessions |

What "terminal" means here: the recovery classifier only rides route facts (closed,
quiet, stalled, dial timed out, send outliving the pathlessness budget). A Bye, a bad
chunk, a root mismatch, or a refused handshake are verdicts and surface at once.

`BlobsTests.ProviderDisposed_...` keeps the other half: a provider that never comes
back exhausts `RecoveryTimeout` and the surfaced `TimeoutException` says exactly that
("could not be re-established within 12 s"), promptly and never a hang.

Deliberate coverage notes: the five-minute regime from the issue is represented by the
30 s blackout exceeding every per-attempt clock — the recovery budget, not the outage
length, is the mechanism under test. Mid-Hello/Welcome interruption is exercised by the
stall-and-redial cell (the second session re-runs Hello/Welcome from scratch);
simultaneous-roam and relay-failover *connection* survival are #31/#30's tables — this
file proves the transfer layer on top of them.


## #20 — blob congestion control: selection, controller, acceptance

The reuse-first survey is in `docs/BLOBS.md` § "Component selection": kcp2k (its own
README recommends leaving KCP congestion control disabled), LiteNetLib (a transport, not
a layer above one, no congestion avoidance), Lidgren (dormant), System.Net.Quic (native
bindings, excluded by the full-managed constraint) — no component fits, so the
receiver-side controller documented in `docs/BLOBS.md` is the smallest justified
adaptation of RFC 6298/8085/9002/6675 ideas. The wire is unchanged.

`CongestionTests.cs` (acceptance) and the re-measured `BottleneckTests`/`LossLadderTests`
(evidence, `docs/BASELINES.md` § "Controller vs fixed window"):

| Claim | Test | Proof |
|---|---|---|
| thin-queue collapse healed | `ThinQueue_ControllerAvoidsTheFixedWindowCollapse` | ≥ 90 KiB/s where the fixed window collapses to ~31 KiB/s (measured 194–353) |
| beats the fixed window, same process | `LossyLink_ControllerOutperformsTheFixedWindow_InProcess` | both modes run back-to-back through identical links; controller finishes strictly faster (measured ~5×) |
| response bytes accounted | `RetransmittedResponses_AreCountedAsWireLoad` | a duplicating provider (1 chunk in 8 twice) lands exactly 64 KiB of duplicate bytes in `BlobTransferStats`, counted as wire load, transfer still completes |
| aggregate budget | `SharedBudget_ConcurrentDownloadsDivideOnePie` | two concurrent downloads share one 96 KiB `BlobFlowBudget`; a 5 ms sampler never observes the ledger past the cap, the pie is exercised, and it drains to zero |
| migration resets conservatively | `ProviderRoamMidTransfer_...` | provider rebinds mid-transfer (fresh port, seamless adoption); ≥ 1 conservative resume recorded, transfer completes verified |
| fixed-window mode re-runnable | `PINHOLE_BLOB_FIXED_WINDOW=1` env | rebuilds the recorded baseline behavior for same-day A/B runs |

Engine-adjacent bugs the controller work surfaced and fixed: re-requests were gated on
the same window whose lost reservations held it shut (a recovery deadlock — the fixed
window could never hit it because it never shrank), the checkpoint cadence change
initially wrote no state for sub-250 ms attempts (resume tests caught it), and
connection-closed detection relied on `Send` throwing rather than an explicit check.


## #34 — bounded resources under churn, hostile input, and load

`BoundedResourceTests.cs`, virtual lab. The discipline is *ledgers, not vibes*: each
test asserts the specific counter that would grow if the layer leaked — the flow
budget's `UsedBytes`, the lab's live-socket ledger (`VirtualNetwork.LiveSockets`,
incremented at socket construction, decremented exactly once on dispose), and the
node's connection table. Process heap appears only as a median-per-cycle slope check,
because parallel tests share the process and their transient garbage is noise, not
signal.

| Scenario | Test | Proof |
|---|---|---|
| Repeated cancel + resume | `RepeatedCancelResume_ReturnsEveryReservation` | 8 cycles, each cancelled mid-transfer (a synchronous progress callback cancels inside the pump itself — no poll→cancel gap to race completion): budget drains to zero *immediately* after every cancel, socket ledger flat, median heap delta ≈ 0 KiB/cycle, and every attempt leaves an honest checkpoint — the final pass resumes byte-exact |
| Concurrent transfers on one budget | `ConcurrentDownloads_OnOneBudget_AllComplete_AndItDrains` | 12 downloads share a 2 MiB pie (real contention — queued reservations); all finish byte-exact, budget drains to zero, no socket leaks |
| Provider restart churn | `ProviderRestartChurn_OneCall_LeavesNoDebt` | 4 provider process restarts inside ONE download call: successor nodes bind and dispose repeatedly; budget used = 0 and sockets settled afterward |
| Failed dials | `FailedDials_LeaveNoConnectionHusks` | 6 sequential + 24 concurrent dials to a dead peer leave `node.Connections` empty — timed-out attempts are reaped, not retained |
| Repeated disposal | `RepeatedNodeDisposal_LeavesTheSocketLedgerFlat` | 12 bind/dispose cycles: live-socket count identical before and after — no pump or timer pins a dead host's socket |
| Hostile ticket-holder barrage | `TicketHolderBarrage_NeverAmplifies_AndHonestPeerCompletes` | authenticated peer floods 200 undecryptable datagrams + 100 Hellos: junk gets zero replies, foreign-session Hellos get zero replies, bound-session Hellos get ≤1 Welcome each — no amplification — while an honest download completes undisturbed |

Two shared-state lessons the tests encode: assertions about `BlobFlowBudget.Shared`
are racy under parallel tests, so concurrent-sensitive checks use a private budget;
and `WelcomeNonceSeen` fires per Welcome, not per session — provider nonces are stable
within a connection by design and distinct across session recreations.

### The soak harness

`MixedWorkloadSoak` is skipped unless `PINHOLE_SOAK_MINUTES` names a duration:

```sh
PINHOLE_SOAK_MINUTES=60 \
  dotnet test --filter "FullyQualifiedName~MixedWorkloadSoak"
```

It runs a mixed workload — shaped-link downloads, brief mid-transfer blackouts,
cancel-and-resume cycles — under a fixed RNG seed (0x50A0; a failing soak is
reproducible by re-running the same duration). Every 60 s it appends a line to
`$TMPDIR/pinhole-soak/<timestamp>-<id>/soak-observations.csv`:
`elapsedSec,heapMiB,threads,handles,liveSockets,budgetUsed,completed,cancelled,errors`.
The file persists pass or fail — it is the evidence the issue asks to attach, not an
anecdote. Assertions on completion: zero errors, nonzero workload, budget drained.

### What this does NOT yet cover (open #34 remainder)

- **24 h / 72 h scheduled soaks** — the harness exists; the long runs are release
  evidence (#35), run on real hardware with the CSV attached.
- **`NodeEngine.MaxConnections` flood** — the cap is a hardcoded 1024 with no test
  seam; filling it needs 1024 distinct peer IDs (~minutes of handshake churn) or a
  constructor-level cap override. Deferring to whether the security review (#24)
  wants the seam.
- **Frame/ticket/manifest fuzz reuse** — the blob layer's hostile-input cell above is
  connection-level; byte-level fuzzing of `BlobWire` parsers should reuse the
  property-test infrastructure once it lands for tickets/manifests.
- **Relay allocation debt** — virtual-lab TURN is emulated on loopback; allocation
  counting against a real coturn belongs to the env-gated #26 harness.
- **Controller starvation at sustained size** — scaling the cancel test's warmup to
  4 MiB on the standard shaped link (8 Mbit/s, 128-packet queue, 20 ms delay) exposed
  a real controller pathology: sustained tail-drop keeps the window pinned near
  minimum while the measured RTT inflates, so the pacer's window÷RTT issue rate
  collapses — observed ~150 KiB/s on an 8 Mbit link with the shaping queue idle
  (depth 0) at timeout. Short transfers finish before the feedback loop bites; this
  needs a dedicated fix under #20's controller work, not a bigger test timeout.
