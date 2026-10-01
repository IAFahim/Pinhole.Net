# Changelog

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
