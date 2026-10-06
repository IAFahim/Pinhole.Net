# Changelog


## 1.10.0 (unreleased) — automatic transfer recovery (#32)

One `DownloadAsync` call now rides out recoverable disruption on its own. While the
engine reports no usable path, the blob layer's stall and first-contact clocks pause
and request growth/retransmission stops — no bursts into a dead route, no stall firing
on a wait that is not ours to end. A connection that actually dies is re-dialed through
the same ticket (authenticated rediscovery included) behind a doubling 500 ms → 5 s
backoff, and the fresh attempt resumes ON THE WIRE: requests anchor at the checkpointed
prefix's first gap, verified bytes never cross the network twice, and progress never
visibly regresses. Directory downloads carry the decoded manifest and completed roots
across re-dials — finished files are skipped, not re-verified. Every recreation mints a
fresh two-sided session key (fresh downloader nonce + fresh provider nonce; counters
restart with them — never continued under recreated keys), proven by the
`WelcomeNonceSeen` seam.

Everything rides down one budget, `BlobDownloadOptions.RecoveryTimeout` (default
10 min — a five-minute outage must be survivable), whose exhaustion throws
`TimeoutException` saying exactly that. `RecoveryTimeout = TimeSpan.Zero` restores the
old first-failure-fatal shape (surfaced as `TimeoutException` naming the dead attempt —
previously `InvalidDataException`). The failure taxonomy is the contract: route loss is
ridden, verdicts are not — a Bye, a tampered chunk, a root mismatch, and a refused
handshake (the dial-stage `InvalidOperationException`) all terminate immediately, and
caller cancellation stays prompt even mid-blackout. Wire unchanged: no new frames, no
version bump, a resumed download just requests a shorter tail from any v3 provider.
Eight scenario tests in `BlobResumeTests.cs` (30 s blackout, direct→relay cut,
rebind+blackout, provider restart, refusal, tamper, cancellation, nonce freshness).


## 1.10.0 (unreleased) — bounded resources: the first ledgers (#34, partial)

Recovery is only release-grade if repeated recovery returns everything it borrowed.
`BoundedResourceTests.cs` asserts ledgers, not vibes: the flow budget's `UsedBytes`
(drains to zero immediately after every cancel and after churn), the lab's new
live-socket ledger (flat across cancel cycles, 12 node bind/dispose cycles, and 4
provider restarts inside one surviving download), and the connection table (30 timed-
out dials leave zero husks). Twelve concurrent downloads on a 2 MiB `BlobFlowBudget`
all complete byte-exact — contention queues reservations, never loses them. A hostile
ticket-holder floods the provider with undecryptable datagrams and foreign-session
Hellos and gets strictly ≤1 answer per answerable request — no amplification — while
an honest peer completes undisturbed.

The soak harness (`MixedWorkloadSoak`) is env-gated:
`PINHOLE_SOAK_MINUTES=<n> dotnet test --filter FullyQualifiedName~MixedWorkloadSoak`
runs a seeded mixed workload (shaped links, blackouts, cancel/resume) and appends a
per-minute CSV (heap, threads, handles, sockets, budget, outcomes) to
`$TMPDIR/pinhole-soak/` — evidence format ready for the scheduled 24 h/72 h runs that
remain the release gate. Still open under #34: a `MaxConnections` flood seam,
byte-level frame/manifest fuzzing, and real-relay allocation accounting.


## 1.10.0 (unreleased) — blob congestion control (#20)

Blob downloads are now congestion-controlled, receiver-side, with the wire unchanged
(no new frames, no version bump — a controller-mode downloader talks to any v3
provider). A byte-based window (32 KiB initial, slow start, AIMD halving on congestion
evidence — expiry bursts or standing delay, never scattered random loss) bounds
outstanding requested-but-unverified chunks; a token-bucket pacer issues request runs at
window rate with run-sized burst caps; the retransmission timer is derived from measured
RTT (SRTT/RTTVAR, Karn's rule, doubling backoff) instead of a flat 900 ms; duplicate
responses are counted as real wire load (BlobTransferStats) rather than assumed away by
request credits; path migration or sustained pathlessness resets the controller to its
initial window with refreshed timers so the resume probes instead of flooding; and every
download joins a process-wide 8 MiB in-flight budget (BlobFlowBudget) so concurrent
downloads divide one pie. New options: MaxWindowBytes, FlowBudget, Stats.

Why not a component: kcp2k's own README recommends leaving KCP congestion control
disabled ("it seems to be broken"), LiteNetLib is a transport rather than a layer above
one and has no congestion avoidance, and System.Net.Quic is native — the full selection
table is in docs/BLOBS.md. Measured against the same-day fixed-window baseline
(docs/BASELINES.md): thin queue 6–11×, 5% loss 3–7×, mixed RTT ~3.7× faster, loss
ladder 1.5–3.5×; the one deficit is a clean fat pipe on a ~6-BDP file (0.89×, the
slow-start climb) in exchange for near-empty queues where the fixed window bufferbloated.
A recovery deadlock the new machinery exposed — re-requests gated on the window whose
lost reservations held it shut — is fixed by letting timer-paced recovery bypass the
window, bounded by the aggregate budget.

## 1.10.0 (unreleased) — connection resilience (#31)

A connection object now survives everything short of disposal honestly: the punch
budget runs on the monotonic clock (a suspend cannot condemn a dial before its
post-wake probe), the confirmed PMTU is re-verified on a cycle (`PmtuReprobeInterval`,
default 5 min) so a mid-connection MTU shrink falls back to the guaranteed floor
instead of black-holing every large datagram, a path migration forgets the old path's
confirmed MTU and re-earns it, a faulted dial can never be zombie-revived into `Open`
by later traffic, total STUN silence at the periodic refresh itself drives bounded
revalidation (for platforms whose network notifications are absent or late), and a
`Dead` connection keeps 1/s beacons for five minutes (completed handshakes only) so a
rebinded peer can still find it. `docs/PROTOCOL.md` gains the full state-transition
table and the suspend-vs-restart distinction; nine scenario tests in
`ResilienceTests.cs`, one known lab gap documented rather than claimed.

## 1.10.0 (unreleased) — relay failover and changed allocations (#30)

A relay is an availability dependency; several independent relays should not be. The
engine now treats the TURN fleet as a pool: slots retry on a doubling jittered ladder
(30 s → 5 min), a maintenance pass re-ensures dead slots even when nobody is dialing,
relay sends route through the allocation on the *same server* as the peer's relayed
address (the only route strict RFC 5766 servers deliver), and a relay (re)allocation
change is blasted to every connected peer — closing the 1.9.0 "TURN restart needs a
fresh ticket" gap. Signed address records (#29) now also carry relayed *addresses*
(never credentials), adopted only for relay servers the resolver itself uses, so a
relay-only pair whose allocations all changed re-finds each other without a new ticket.

Two engine bugs surfaced by the new multi-relay tests and fixed here: a relayed frame
arriving on the peer's *other* relay leg used to demote the confirmed leg and force an
endless permission round trip (a livelock in which data never found the leg ready —
single-relay setups could never show it), and a condemned relay leg kept its ready mark
forever, sending into a relay that no longer owned the peer's address. The fake TURN
server now enforces the RFC receive-side permission gate by default and can inject
quota refusals; the lab runs each relay on its own loopback IP, like real deployments.

Tests: loss of one of two relays, in-place relay restart with both allocations changed
(the old gap, now healed without a fresh ticket), differing relay lists meeting at the
common relay, quota refusals bounded by the ladder, all-relays-down pending then
recovery, unresolvable relay hostnames leaving the direct path untouched. Operational
guidance — self-hosting coturn/iroh-relay, failure domains, capacity honesty, no SLA
claims for free infrastructure — in `docs/RELAYS.md`.
## 1.10.0 (unreleased) — persistent identity, authenticated rediscovery (#29)

One persisted 32-byte seed (`IdentityKeySeed`) now restores the *full* endpoint
identity across restarts: the X25519 static key (the seed itself, as before), an
Ed25519 endpoint key (HKDF-derived, its own domain), and a stable peer ID. Connection
strings gain a v3 payload that pins the endpoint key alongside the static key.

On top of that: signed address records. A node with an endpoint identity publishes
{peer id, endpoint key, monotonic sequence, 90 s expiry, direct/reflexive endpoints},
Ed25519-signed, to any number of lookup providers — the built-in `Pinhole.Rendezvous`
UDP introducer (which now stores and forwards records without validating them) and/or
application-supplied `IPinholeLookupProvider` implementations fronting signed DNS,
pkarr, or an iroh-style directory. A dialer holding a stale v3 ticket races the lookup
alongside its punch; a record is adopted only after it verifies against the ticket's
pinned endpoint key, so a malicious provider — or the introducer itself — can only deny
availability, never impersonate or redirect. The acceptance criterion — two pinned
peers reconnecting after both changed address, without a human exchanging a new
ticket — is `RediscoveryTests.ReconnectAfterRestart_NoNewTicket`, alongside poisoning,
forgery, rollback, staleness, provider-outage, and multi-provider proofs. Design,
threat model, privacy, and seed-storage guidance: `docs/REDISCOVERY.md`.

## 1.9.0 — the topology/loss lab, and the three gaps it found (#20, part 1)

An in-process virtual internet — NATs that really translate and filter, Gilbert-Elliott
loss, delay and reorder — injected under the engine's socket layer through an internal
`IUdpSocket` seam (production behavior unchanged). iroh runs its connectivity claims
through real Linux namespaces; this is the managed equivalent, and it runs identically
on every OS in CI. Documented in `docs/TESTING.md`.

The 16-cell NAT pairing matrix reproduces the classical hole-punching table exactly:
13 pairings punch direct (symmetric sides included, via observed-source adoption), and
symmetric×symmetric, symmetric×port-restricted, port-restricted×symmetric are relay-only
by physics. Scenario coverage adds the UDP-blocked hotel (not one direct datagram
escapes), CGNAT hairpin, silent NAT mapping expiry, a v4→v6 mid-connection roam, a
mid-transfer server roam, and relay restart/outage cells. The loss ladder records the
blob ARQ's goodput baseline (1%→494 KiB/s … 20%→82 KiB/s, bursty 10%→251) — the curve
congestion control (#20, part 2) will be judged against.

Three real gaps surfaced and are fixed here:

- **A mid-transfer roam killed the blob pumps.** `Send` throws while a connection is
  briefly `Punching` through a rebind, and both blob pumps treated that as peer-gone.
  Sends now ride out pathless transitions (`BlobWire.SendRidingOutPathlessness`):
  bounded wait, closed-connection and budget escape hatches intact.
- **A restarted TURN relay left ghost allocations.** `IsAlive` is a local flag, so a
  relay that restarted made every relayed frame black-hole until the minutes-long
  refresh cadence noticed. A failed permission round trip is now evidence the
  allocation is gone: the client is retired and reallocated immediately, and a
  relay-leg path validation (the same idle/probe/suspect machinery the direct path
  always had) notices a silent relay within the path-validation window.
- **Relay-only sessions cannot survive their single relay restarting in place** — both
  peers' relayed addresses live on the dead relay and no channel remains to re-learn
  them. Documented as a known architectural gap (`docs/TESTING.md`); fresh-ticket
  redial now heals end-to-end in ~9 s instead of stalling for a refresh cycle.

## 1.8.0 — blob wire v3: independent provider freshness

The 1.7.1 blob key derivation depended on two random 32-bit routing tokens. Those
tokens can repeat, and the engine's handshake transcript does not authenticate them.
Repeated downloader IDs and token pairs therefore reproduced a blob key even across
independent encrypted engine sessions. A regression against `839e12b` confirmed that
one session opened the other's frames when its routing tokens were repeated.

Blob wire v3 replaces that binding with an independent 256-bit provider nonce. Hello
and Welcome carry explicit versions. Welcome contains the provider nonce and a sealed
Head; the client adopts the nonce, cipher, and counter only after the Head authenticates.
Hello retries and directory streams retain the connection's nonce and counter space.
The downloader now shares its receive watermark across directory streams as well.

Encrypted v1/v2 blob peers are refused without sending ciphertext under old keys;
upgrade both sides. The ticket format and core transport wire are unchanged. Coverage
includes repeated client nonces, retries, tampered Welcomes, nonce swaps, replay across
directory streams, old-version refusal, and blob transfers with core encryption disabled.

## 1.7.1 — blob layer: the session layer's rules, applied to itself

Follow-up to the 1.7.0 review of #19: two blob-layer findings, both the same class
as the session-layer bugs fixed a day earlier.

### The blob watermark moved on failed authentication

`Cipher.TryOpen` reported the frame's claimed counter even when the tag failed, and
both the client and the server wrote that value straight back into their
highest-seen watermark. A forged frame claiming a far-future counter starved every
legitimate frame behind it; a replayed old counter dragged the watermark backward and
re-admitted frames before it. The API now takes the watermark by `ref` and advances
it only after the tag verifies — a rejected frame can move it neither forward nor
back, by construction. Proven by a wire-oracle adversarial test: a hand-rolled
provider injects a counter-10_000 frame with a corrupted tag between the Head and the
first genuine chunk of a real download, and the download completes anyway.

### Session uniqueness no longer rests on the downloader alone

The 1.7.0 v2 key forked on the downloader's session id only — all freshness from one
side, so a downloader that repeated an earlier id reproduced the key while per-
connection counters restarted at 1 (demonstrated in tests: the second "connection"
read the first one's frames). The derivation now also binds the connection's
**transport binding** — the two engine tokens, numerically ordered, fresh from BOTH
endpoints (the provider's token is the provider's contribution). A repeated session
id across connections derives a different key by construction. The blob wire itself
is unchanged (the Hello and frame formats are as shipped in 1.7.0); since 1.7.0 was
never tagged or released, v2 is finalized here rather than versioned again.

### The legacy refusal no longer seals anything

The 1.7.0 refusal sealed a Bye under the pre-v2 fixed per-ticket key — two refusals
would have re-used that key's nonce 1, repeating the very sin the refusal exists to
punish. The provider now hangs up with no blob frame at all, and the legacy
derivation is exposed to production code only as an open-only `LegacyDetector`
(sealing under it is unrepresentable; a separate internal seam exists solely so tests
can *be* a pre-2.0 client). The legacy peer still fails fast, the server keeps
serving others (asserted), and the compatibility notes in BLOBS.md match the code.

## 1.7.0 — authenticate before you commit

Three correctness fixes from the source review (#19). No public API changes; one
wire change (blobs v2, with loud compatibility behavior).

### Sealed frames: state commits only on authenticated frames

`FrameSealer.Open` used to advance the replay window (and the epoch ratchet) before
the AES-GCM tag was verified, and never rolled back. Since the per-connection token
rides the wire in the clear, an on-path forger could present any counter it liked:
one forged far-future counter starved every legitimate frame behind it for up to 2^28
frames, and one forged next-epoch counter ratcheted the receive key forward,
stranding the old epoch entirely — a one-packet kill of the receive direction. The
1.6.0 claim that this was "exactly like IPsec" was backwards: RFC 4303 §3.4.3 marks
a sequence number only after its ICV verifies. Now the window checks eligibility
without mutating, authenticates against a candidate key, and commits replay and key
state only on success; the previous epoch's cipher is retained for the replay window
so frames reordered across an epoch boundary still open; and disposal is safe under
concurrent receives (everything, decryption included, runs under the direction lock).
Regression tests cover forged far-future counters, forged epoch jumps, reorder across
the boundary, corrupted-clone-before-genuine at the wire level, and disposal races.

### Blobs: per-connection keys (wire v2)

The blob cipher was derived once per ticket (`HKDF(psk, root)`), and every connection
restarted its frame counters at 1 — so simultaneous downloads, reconnects, and
resumed downloads of one ticket re-used ChaCha20-Poly1305 (key, nonce) pairs across
connections, potentially over different plaintexts. Wire v2: the downloader's first
Hello carries a fresh 32-byte session id (plaintext by design — it names the salt,
and only the PSK turns it into keys) and both sides fork the connection's cipher
through it (`HKDF(psk, root ‖ sessionId, "pinhole-blobs-v2")`). A v2 provider
recognizes a pre-2.0 downloader's first frame under the old fixed key and refuses it
with a Bye that key can read — the legacy derivation serves that refusal only. Tests
prove two connections on one ticket never read each other's frames, that simultaneous
downloads of one ticket both verify, and that the legacy refusal is fast and serves
nothing.

### Symmetric-NAT hint: scheduling, not suppression

`PunchLoop` dropped every non-relay candidate when the peer's string hinted a
symmetric NAT — which also killed the candidates that stay reachable through one:
same-LAN peers (no NAT in the way) and router-mapped endpoints (punch-anywhere by
construction). The hint now demotes direct candidates to a one-second trickle while
relay candidates keep full pace: LAN and mapped candidates still connect directly,
the truly hopeless public reflexives cost one datagram per second, and the
`ConnectTimeout` budget still bounds the dial. Tests cover direct and reflexive
candidates connecting under a symmetric hint and the budget timeout with nothing
reachable.

## 1.6.0 — the non-goals, demolished

Four things this library said it would never do, done: wire encryption, path-MTU
discovery, LAN discovery, and an optional keepalive. What remains a non-goal remains
one deliberately — no delivery guarantees, ordering, or retransmission (a half-baked
ARQ is worse than none), and no signaling/storage services.

### Wire encryption and authentication (default on)

Every session is now AES-256-GCM per frame over a triple-DH X25519 handshake
(ephemeral-ephemeral + both static-ephemeral combinations — signatures not needed),
folded through HKDF-SHA256 over a canonical transcript hash. Roles derive from peer
IDs, so simultaneous dials converge on one session instead of colliding. Connection
strings are payload v2 and embed the node's static public key; the dialer pins the
answering handshake to that key, and a substituted key kills the connection as a
MITM rather than negotiating. There is no downgrade window at all: a stripped
handshake fails, a plaintext PACK against a crypto dial fails, and `Optional` exists
only for pre-1.6 plaintext peers (`Disabled` reproduces the old wire exactly).

Sealed frames carry a strictly increasing counter (nonce never repeats), the header
+ token + counter as AEAD associated data, a 64-frame IPsec-style replay window, and
an HKDF epoch ratchet every 2^28 frames — key rotation with zero wire negotiation.
Counters a tampered frame burned stay burned, exactly like IPsec.

New surface: `PinholeEncryption` (`Required`/`Optional`/`Disabled`),
`PinholeOptions.IdentityKeySeed` (persistent node identity),
`PinholeNode.StaticPublicKey`, `PinholeConnection.IsEncrypted` / `RemoteStaticKey` /
`FramesRejected`. The key schedule and sealed frames are verified against an
independent python oracle byte for byte; the suite also covers MITM substitution,
downgrade, replay, and tamper kills at the wire level.

### Path MTU discovery (default on)

The 1200-byte payload floor was sized for the worst path a session could land on;
faster paths were dragged down to it. RFC 8899-style padded pings now climb from the
floor in 128-byte steps — a matching pong confirms a size, three unanswered probes
abandon it for a five-minute cooldown — and a confirmed size raises
`PinholeConnection.PathMtu` (and the largest payload `Send` accepts) up to 1435
bytes on an ordinary Ethernet IPv4 path. The dual-mode socket reports v4 peers as
v4-mapped v6 sockaddrs, so the plateau is chosen from the mapped-back endpoint.
Leaving the direct path forgets the climb: a relay hop or rebind may have a smaller
MTU than the last path proved. `EnablePmtud = false` restores the flat budget.

### LAN discovery via mDNS

Two machines on one network can find each other with no server and no clipboard:
`EnableLanDiscovery` (off by default — announcing is a network-visible choice)
announces the node as `<peer-id>._pinhole._udp.local` (RFC 6762/6763 subset: 3×
startup burst, 120 s heartbeat, unicast answers to legacy queriers, TTL-0 goodbye),
and `PinholeNode.DiscoverLanPeersAsync(window)` returns fully dialable v2 connection
strings — the announcement carries the static key, so discovered sessions get the
same MITM proofing as shared-string ones. The DNS codec is strict (compression
pointers must point strictly backwards; truncation/corruption fuzzing over real
packets) and a multicast-less environment never fails the bind.

### Optional keepalive heartbeat

`KeepaliveInterval` (default off, ≥100 ms) sends a caller ping at a fixed cadence on
every live connection — pongs refresh the NAT mapping both ways and feed
`LastRtt`; it counts in caller stats because the app asked for it. A heartbeat, not
reliability: delivery guarantees stay out.

## 1.5.0 — router port mappings and automatic NAT classification

The two techniques the iroh parity review found missing — both now spoken from pure C#,
both enabled by default, both entirely background and best-effort.

### Router port mappings (PCP / NAT-PMP / UPnP)

The same strategy iroh's portmapper uses: at bind (and after every rebind) the node
asks the network's gateway for an explicit UDP mapping to its socket, in order PCP
(RFC 6887), NAT-PMP (RFC 6886), then UPnP IGDv1/v2 (SSDP discovery, device XML,
`AddAnyPortMapping` with a `AddPortMapping` fallback). A granted mapping is
advertised as a reflexive candidate — which turns many hard home NATs into directly
punchable ones before hole punching even starts — renewed at half its lease
(default 2 h), recreated after a rebind, released on close, and retried once a
minute if a previously-working mapping dies. `EnablePortMapping = false` opts out;
`node.PortMappedEndpoint` reports the live mapping. Gateway protocols ride test
seams (in-process fakes for all three protocols) so the suite stays hermetic.

### Automatic NAT classification

The NAT hint in connection strings no longer waits for the app to call
`SetNatHint`: the engine classifies from its ordinary multi-server STUN probes —
identical observed mappings mean a cone NAT, divergent ones a symmetric NAT whose
candidates are useless to dialers — and reclassifies on every STUN refresh as the
network changes. A manual `SetNatHint` override still wins, and one refinement:
while a router mapping is live, the hint is honestly `Cone` even behind a symmetric
NAT, because the mapped endpoint is punchable from anywhere and "skip the punch"
would throw away a working direct path.

## 1.4.0 — blobs: sendme-parity file transfer

One ticket moves a file or a whole directory between machines — the
[sendme](https://github.com/n0-computer/sendme) model on Pinhole connections
([#14](https://github.com/IAFahim/Pinhole.Net/issues/14),
[#15](https://github.com/IAFahim/Pinhole.Net/issues/15)). New package `Pinhole.Blobs`
(net8.0 + net10.0, AOT-compatible), new sample `samples/Pinhole.Send`, full wire
spec in `docs/BLOBS.md`.

### Serving and downloading

- `BlobServer.ServeAsync(path)` hashes once and serves until disposed — file or
  directory tree; `server.Ticket` re-mints per read so a ticket grabbed after a roam
  carries live candidates. `BlobClient.DownloadAsync(ticket, dir, progress?)` connects
  anywhere the core does and returns `(Path, Bytes, Resumed)`.
- Every 1 KiB chunk is BLAKE3-verified on arrival against the provider's outboard
  chunk values, and the full tree root is checked at completion — no unverified byte
  ever reaches the output file. Our BLAKE3 tree is oracle-tested against BouncyCastle
  across 0 B to ~100 kB sizes and piecewise feeding.
- Receiver-driven ARQ: range requests anchored at the lowest unapplied chunk (a hostile
  sender cannot balloon the receive buffer), 900 ms stale re-requests, 30 s honest
  stall failure. Interrupted downloads resume from a `*.pinhole-part` checkpoint —
  prefix-only, because a hash tree cannot skip.
- Directories ship as a binary manifest plus one blob per entry, path-sanitized on
  download so a hostile manifest cannot escape the destination directory.

### Encryption by default

- Tickets carry a fresh pre-shared key; every frame in both directions is
  ChaCha20-Poly1305 under `HKDF-SHA256(psk, salt = root)` with per-direction role
  nonces and per-connection monotonic counters — replays and regressions are refused,
  and the relays forward ciphertext only (there is a test with a tap on the fake relay
  proving no file byte crosses it in the clear). `Encrypt = false` opts out for
  trusted LANs.

### Audit deliverables

- README gained the "when does it connect" matrix — every NAT pairing and which path
  carries it — plus two decisions on record: PMTUD stays a non-goal (1200-byte budget,
  QUIC's conservative initial) and discovery stays a non-goal.

## 1.3.0 — iroh parity pass

Studied n0-computer/iroh end to end and ported the practices that were missing here.
Everything iroh already had that we match — simultaneous-open punching, relay
fallback, roaming survival, one-endpoint-per-app, documented wire formats — stays;
this release closes the gaps.

### Periodic re-discovery: `StunRefreshInterval` (default 1 minute)

- iroh refreshes its network map on a timer because NAT mappings move with *no* OS
  network event (DHCP renew, router reboot). Pinhole now re-probes its STUN servers
  the same way; when the observed reflexive set moved, it is replaced, every peer is
  re-advertised with a gentle announce, and the next `ConnectionString` read carries
  the new candidates.
- Working direct paths are never torn down by a refresh — their endpoints come from
  the peer's own frames, not from STUN. A fully silent probe batch changes nothing;
  full network loss remains the recover/rebind path's call. Zero disables the timer.

### Reconnect pacing: capped exponential backoff with jitter

- iroh relay reconnects no longer retry at a flat 1 s: ~1 s first, doubling per
  consecutive failure up to 30 s, ±10% jitter, reset on the first successful
  authentication — a relay outage never turns into a synchronized retry storm.
  TURN allocation retries get the same jitter treatment (30 s ±20%). A relay that
  answers garbage (rejected auth, malformed frames) now costs a reconnect cycle
  instead of silently killing that relay's client loop forever.

### All-platform reach

- The shipped packages (`Pinhole.Net`, `Pinhole.Turn`, `Pinhole.Providers`) now
  target **net8.0 and net10.0** — managed-only as always, so anything with a UDP
  socket and .NET 8+ runs the library. CI still tests Linux/macOS/Windows; the
  README gained a platforms section and the one net9+-only API
  (`ClientWebSocketOptions.KeepAliveTimeout`) is version-guarded.

### Protocol documentation

- New `docs/PROTOCOL.md`: the full wire contract — frame layout, token
  authentication, lifecycle, candidate TLVs, connection-string encoding, STUN
  subset, and the iroh relay handshake/framing — specified precisely enough to
  re-implement either side, iroh-style.

### Profiled with Linux perf: the receive path stopped allocating

- Baseline profile (`perf stat` + `perf record` with .NET perf maps) on a 20 M-datagram
  loopback run: ~272 B allocated per datagram process-wide — a `SocketAddress` clone plus
  `IPEndPoint` construction on every received frame — and the global engine lock taken on
  both per-frame paths, ping-ponging one cache line between the send and receive threads.
  The run is syscall-bound at its floor (one sendmsg/recvmsg per datagram); everything
  above that floor was ours to remove.
- The receive loop now reuses one scratch `SocketAddress`; the engine clones it only when
  a connection adopts a *changed* endpoint (roaming), detected with a vectorized
  `SequenceEqual` over the public buffer. Sending reads the socket as a volatile
  reference instead of taking the engine lock (a rare rebind races into a caught send
  error and the normal recovery path), and the connection table is a
  `ConcurrentDictionary`, so per-frame demux is lock-free while dial/incoming/close keep
  their exact atomic semantics (idempotent dials, first-PUNC-wins, identity-checked
  closes).
- Result, interleaved A/B on the same machine: +2–4% throughput and whole-process
  allocations down from 272.005 to 0.005 B per datagram — the direct path allocates
  nothing in either direction now. The bench prints the whole-process number alongside
  the sender-thread number so both stay honest; the CI canary greps are unchanged.

### Test-infrastructure hardening

- Two latent test-host crashers fixed, both exposed by timing shifts: the fake TURN
  server's reply path now tolerates a client disposing mid-flight (one ICMP
  unreachable used to kill the whole run), and the fake iroh relay aborts client
  sockets *before* stopping its `HttpListener` (the stop raced in-flight response
  writes inside the runtime's own cleanup).
- Six new tests: moved-mapping refresh and replacement, refresh leaving working
  direct paths alone while teaching peers the new candidates, disabled-by-zero,
  interval floor validation, and the backoff ladder (near-1 s first retry,
  strictly climbing, 30 s cap).

## 1.2.0 — honest about silent death, and green again

Four fixes from the first real-world pass: options that stopped dropping defaults,
path death you cannot see, a receive race the event API cannot close, and CI that
stopped trusting an interactive demo.

### Options customization no longer drops the free infrastructure (#11)

- Customizing any single `PinholeOptions` setting silently disabled STUN probing and
  the public relays: a fresh options object resolved nothing, and `BindAsync` only
  applied defaults when the whole argument was null. `BindAsync` now resolves the
  effective options first, filling in only what was left unspecified.
- Tri-state precedence per infrastructure setting, documented and tested: `null`
  takes the free defaults, an empty list disables that provider, explicit entries
  replace the defaults. Scalars (timeouts, listen, watch flags) are never touched.
- All-infrastructure-off options perform no DNS/catalog lookups at all; TURN catalog
  warming is skipped when no TURN relay is configured. Cancellation halts resolution
  before any engine resource exists. Offline test helpers and the bench now disable
  infrastructure explicitly instead of relying on the old null-list accident.

### Opt-in buffered receiving (#13)

- `ReceiveBufferCapacity` (default 0 = off): a bounded per-connection queue that
  exists from handshake time, closing the accept/subscribe race where a datagram
  arriving between `AcceptAsync` and the first `Received +=` was simply dropped.
- New `ReceiveAsync` (null at EOF) and `ReadAllAsync` on `PinholeConnection`, with
  single-reader enforcement, drop-oldest overflow counted in `DroppedDatagrams`,
  cancellation that ends only the pending read, and drain-before-EOF on close.
  Local queueing over the same unreliable transport — no reliability is added.
- Default callback mode is unchanged, zero allocations included.

### Silent direct-path death is detected (#12)

- UDP sends succeed into a dead NAT mapping or firewall; the direct path used to stay
  "Open" until something errored. The engine now validates the path itself: after
  5 s with nothing *received* on the direct path (only receipts prove anything), the
  per-node maintenance scheduler probes with the existing token-checked ping
  protocol; three consecutive unanswered probes mark the path suspect and the normal
  machinery takes over — relay fallback as `Degraded`, or an honest `Dead`, with
  upgrade-back when UDP returns.
- Probes correlate with the outstanding nonce *and* the endpoint that probe was sent
  to: caller pings, relay traffic, and replies re-pointed mid-flight by the peer's own
  frames never certify a path. Monitoring counters are separate from `Ping`/RTT stats.
  One scheduler per node, monotonic deadlines, nothing on the send path, dead on
  dispose. Opt out with `EnablePathValidation = false`.

### CI green again (#10)

- The bench canary moved out of the now-interactive demo into `samples/Pinhole.Bench`:
  non-interactive, two loopback nodes, no stdin, no public infrastructure, warm-up
  then measure on the sending thread. Gates unchanged: 25k dps floor, <0.1 B/datagram.
- Relay fault injection is deterministic: the fake relay gates new authentications
  before dropping connections, so `RelayReconnect` observes the disconnected state
  without racing the clients' reconnect loop.
- The token-spoofing tests dial through a loopback-only connection string so
  `Path.Remote` cannot legitimately migrate between the multi-homed interfaces CI
  runners have — the anti-spoofing assertions themselves are unchanged and still
  fail if the token gate is removed.

## 1.1.0 — red-team hardening

A full adversarial pass over 1.0.0 (`tests/Pinhole.Tests/AttackTests.cs` locks every
fix in). Wire format change: frames now carry the per-connection token, so 1.1.0
nodes only talk to 1.1.0 nodes.

### Spoofing and hijacking, closed

- Every frame after the handshake now carries the connection's random token
  (`Punc` teaches it, `Pack` delivers it, everything else must prove it). The token
  never appears in the connection string, so holding the string lets a stranger
  dial — but no longer close a session with a forged `Bye`, re-point its path with a
  forged `Data`, or redirect its punch with a forged `Announce`.
- `Pack` now carries both tokens, so the dialer authenticates the responder from
  the first frame.

### Remote-crash and DoS, closed

- A malformed STUN response (attribute length past the message end) could throw the
  receive loop off its thread and permanently deafen a node. Attribute lengths are
  bounds-checked in `PinholeNode` and `PeerSocket`, and the STUN dispatch is guarded.
- A flood of `Punc` frames from forged sender IDs no longer materializes unbounded
  connection state: stranger-initiated connections cap at 1024.
- TURN permission round trips are single-flight per connection; a relayed frame
  burst can no longer spawn one permission request per frame.

### Races and correctness

- Concurrent `ConnectAsync` calls to the same target are atomic: they share one
  connection object instead of overwriting each other, and a close of the stale one
  can no longer tear down the live one.
- `RoamNowAsync`/rebind no longer throws when the peer's relay candidates are
  unreachable (the announce blast skips them and continues on direct candidates).
- A relayed frame arriving for a newer relay address no longer marks a stale
  permission ready.
- `AcceptAsync` on a disposed node now throws `ObjectDisposedException` instead of
  a raw `ChannelClosedException`.

### Format honesty

- `Parse` rejected the worst legal `ToString()`: a 32-relay-candidate string
  encodes to ~7.2k characters; the cap is now 8192 (was 4096) and a test round-trips
  the worst case. The receive buffer grew to 8192 so a max-size announce is not
  silently truncated.
- Base64url decoding is strict: whitespace-padded payloads are rejected instead of
  silently accepted.
- `Send` rejects empty payloads (a zero-length datagram is undeliverable by
  definition). `Ping` never throws.
- Binding to a specific IPv4 endpoint (`PinholeOptions.Bind`) actually works now —
  the dual-mode socket maps the address instead of throwing.

## 1.0.0 — the connection library

## 1.0.0 — the connection library

The bottom layer, nothing else: get a connection between two machines and keep it
open until the app closes it. All free STUN + all free relays as infrastructure,
connection strings as the discovery artifact, unreliable datagrams by design.

### The 1.0 API

- `PinholeNode.BindAsync()` — one UDP socket, free STUN probes, free TURN allocation,
  all internal. Parameterless gets the free-infra defaults; everything overridable.
- `node.ConnectionString` — `pinhole1:…` ticket: stable peer ID + direct/reflexive/relay
  candidates. How it travels between peers is the app's concern.
- `ConnectAsync(string)` / `AcceptAsync()` → `PinholeConnection`. The dial runs the
  fixed chain internally — direct punch → STUN-reflexive → TURN relay — and returns
  connected on whichever path works; forced punch failure still yields a relayed
  connection. N peers, late joins, self-dial refusal, idempotent dials.
- `PinholeConnection`: `Send` (1200-byte `MaxPayload` guard, zero-alloc hot path),
  `Received`, `State`/`StateChanged` (`Punching → Open → Degraded → Dead → Closed`),
  `Path`, `LastRtt`/`AverageRtt`, `Stats` (AOT-safe counters + honest `PingsLost`),
  `Ping()` as a tool — never a keepalive nanny — `CloseAsync()`/`Closed`.
- Roaming: WiFi→mobile, IP change, rebind, path death handled inside on the same
  connection object; `RoamNowAsync()` to force a re-probe; network-change watch.
- `NatDetector`: multi-STUN compare — cone vs symmetric vs unknown, wired to
  `SetNatHint` so symmetric NATs skip the hopeless punch and go relay.

### Pure C#, zero Rust

- `src/Pinhole.Iroh` and the `extern/irohnet` submodule are gone; no cargo anywhere
  in CI. Fresh clone → `dotnet test` is the whole story on all three OSes.
- The mesh canary runs the session API only: three strangers, three rounds of fresh
  verified secrets, weekly schedule + manual dispatch, `MESH_FORCE_RELAY` mode
  exercising relay paths, and a same-runner local-mesh CI job.

### Hardening along the way

- Relay-client deadlock eliminated: no lock is ever held across an await (the
  iterator that held `_gate` over permission round-trips is now a materialized
  snapshot — the class of bug Rust's compiler forbids by construction).
- Rebind honesty: every configured STUN server must go silent before a rebind
  (one rate-limited probe is not network death); post-rebind announces blast every
  peer candidate.
- Mesh harness protocol: per-connection handler attach and a retransmit floor —
  "I heard everyone" is never mistaken for "everyone heard me" on lossy datagrams.

## 0.1.0 — punch, relay, rendezvous

Day-zero scaffold through the safe-layer migration: `PeerSocket` multi-candidate
punch, STUN probe + TURN relay client (RFC 5766) + provider catalog, optional
rendezvous server, the iroh Rust bridge (since removed), loopback suite, 3-OS CI,
bench canary.
