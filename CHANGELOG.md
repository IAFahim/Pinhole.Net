# Changelog

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
