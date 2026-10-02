# Changelog

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
