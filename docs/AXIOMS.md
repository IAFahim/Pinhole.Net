# Pinhole axioms — what the system reduces to, and where each stands

Roadmap R7 deliverable. The axiom set is defined in [Roadmap.md](../Roadmap.md)
section 2; this document restates each axiom and records, honestly, whether the
code realizes it today (2026-10-26) or still only plans to. File pointers are to
`src/` by member name, not line number — the engine files move too much for
line citations to survive.

Status vocabulary used below:

- **landed** — the code exists and is on a production path.
- **landed, unwired** — the code exists as a primitive but nothing on a
  production path calls it yet (it is the extraction landing pad).
- **partial** — some of the axiom holds; the named gap is what remains.
- **planned** — nothing in the tree realizes it; the roadmap phase owns it.

## The axioms

### A1 — Time is an input

**Statement.** A `Tick` is passed to every step; no component reads a clock.

**Replaces.** ~100 reads of `Environment.TickCount64`, `DateTimeOffset.UtcNow`,
and `Task.Delay` pacing across the engine.

**Status: landed, unwired.** `Pinhole.Crypto.Tick` (src/Pinhole.Crypto/Tick.cs)
is the value type: monotonic milliseconds, comparison operators,
`MillisecondsSince`. No machine consumes it yet. The ambient reads the axiom
deletes are still in the tree: `BlobController.AffordableChunks` calls
`Environment.TickCount64` directly (its sibling `TryStartRun` already takes
`nowMs` — the two-clock split of audit D-02 is still visible in one class),
and `NodeEngine` reads ticks throughout its maintenance, punch and PMTU paths.
`BlobWire.SendRidingOutPathlessnessAsync` even starts a `Stopwatch` — the
opposite shape. Passing `Tick` in is R3 work.

### A2 — Datagram

**Statement.** I/O reduces to `(PathId, bytes)` in, `(PathId, bytes)` out.

**Replaces.** `IUdpSocket`, `TurnClient`, `IrohRelay`, `DerpRelay`, `TcpLink`
as five separate I/O styles.

**Status: planned.** The transports remain distinct full implementations in the
tree (src/Pinhole/UdpSocket.cs, src/Pinhole/TcpTransport.cs,
src/Pinhole.Turn/TurnClient.cs, src/Pinhole/IrohRelay.cs,
src/Pinhole/DerpRelay.cs). No `PathId`-keyed datagram seam exists yet; this is
the R3/R6 shell boundary.

### A3 — Machine

**Statement.** Decision logic is `Step(ref State, in Input, Tick,
Span<Effect>) -> int` over unmanaged state — sans-IO, total, effect-driven.

**Replaces.** `NodeEngine`, `StreamDownloader`, `BlobController`,
`PortMappingService`, `PunchLoop` as classes fused to sockets, threads and
clocks.

**Status: partial — nothing has the signature yet; two bodies already have the
shape.**

- `RunVerify` (src/Pinhole.Blobs/RunVerify.cs) is pure functions over values:
  `SiblingPath`, `VerifyRun`, `FoldRun`, `FoldRunsToRoot` allocate on the stack,
  touch no clock, no socket, no file. It is the first landed piece of R2 and the
  closest thing to a machine in the tree; it still returns `bool`/`int`, not
  typed outcomes, and has no state of its own.
- `BlobController` (src/Pinhole.Blobs/BlobController.cs) is nearly pure —
  window, RTT, PTO, pacer and loss state as scalars, most methods taking
  `nowMs` — but `AffordableChunks` reads the wall clock (A1) and it holds
  `BlobFlowBudget` side effects directly rather than emitting reservations as
  effects.
- `NodeEngine` is still the monolith: one ~190 KB file, one `ConnState` class
  whose ~80 mutable fields are documented as "guarded by Gate", with punch,
  PMTU probing and keepalive as private methods (`PunchLoop`, `MaybeKeepalive`,
  the `PmtuWire`/`PmtuProbeSize` fields) rather than machines. The R3
  extraction order (Pacer → Replay → Pmtu → Keepalive → Path → Handshake →
  Punch) has not started.

There is no `Pinhole.Core` assembly and no `Effect` type yet.

### A4 — Codec

**Statement.** Every wire form has a total
`TryRead(span, out T) -> bool` and a `Write(in T, span) -> int`, and exactly
one canonical encoding.

**Replaces.** The throwing, lenient, per-assembly parsers: `ConnectionString`,
`AddressRecord`, `BlobWire.Frame`, `Manifest`/`DnsCodec`, `StunBindingMessage`,
`TurnClient`'s message layer, MoQ wire.

**Status: landed as the reference layer; production parsing not yet
migrated.** `Pinhole.Wire` (commit `ff1e7e4`, nine codecs over shared
primitives) covers connection strings, address records, STUN, TURN, MoQ
control/subgroup/object forms, DNS/mDNS/pkarr, the blob ticket, the directory
manifest and the blob frames v1–v4. Every `TryRead` returns false on any
malformed input and never throws on wire bytes; `Write` throws only on
programmer error. Canonicality is enforced beyond the legacy parsers
(non-minimal varints, padded base64url, non-UTF-8 text, TURN tail bytes — see
[WIRE.md](WIRE.md) for the normative rules). The legacy parsers remain on the
production hot paths (src/Pinhole/ConnectionString.cs,
src/Pinhole/LanDiscovery.cs `DnsCodec`, src/Pinhole.Turn/TurnClient.cs,
src/Pinhole.Moq/MoqWire.cs, src/Pinhole/IrohDiscovery.cs); the blob layer is
the exception — `BlobWire.Frame` and `Pinhole.Wire.BlobFrameCodec` landed
together and agree by construction. Swapping the production parsers for the
canonical codecs is R3+ work.

### A5 — Hash

**Statement.** BLAKE3 as map (per-chunk CVs, independent, parallelizable) then
reduce (parents, log depth). One BLAKE3 in the system.

**Replaces.** `Blake3.Tree` object graphs, per-chunk re-hashing, and
BouncyCastle's `Blake3Digest` as a second implementation.

**Status: landed; one duplicate remains.** `Pinhole.Crypto.Blake3`
(src/Pinhole.Crypto/Blake3.cs) exposes exactly the map/reduce seam:
`HashChunks(data, firstChunkIndex, chunkCvs)`, `HashChunk`,
`ReduceLevel`, `RootFromTopPair`, plus streaming (`Blake3Hasher`,
`UpdateChunks`/`FinishChunks`), keyed and derive-key modes. Three execution
paths share one correctness contract: scalar, AVX2 8-way (`Vector256`) and
SSE4.1/NEON 4-way (`Vector128`) chunk columns; every public span-taking
operation is allocation-free. The blob layer's public `Blake3`/`Blake3.Tree`
(src/Pinhole.Blobs/Blake3.cs) is now a facade that delegates to this core and
keeps its flat per-chunk CV list for serving. BouncyCastle `Blake3Digest` is
still linked by src/Pinhole/IrohRelay.cs for relay auth — deletion ledger
item 4.

### A6 — Window

**Statement.** Replay admission is `Admits(counter)` / `Mark(counter)` on one
128-bit value — one primitive for the session layer's 64-frame window and the
blob layer's watermark discipline.

**Replaces.** `FrameSealer`'s inline bitmap and the blob cipher's strict
watermark as unrelated code.

**Status: landed, unwired.** `Pinhole.Crypto.ReplayWindow`
(src/Pinhole.Crypto/ReplayWindow.cs) is the appendix sketch made real: an
immutable `readonly struct` (`Highest`, `Bitmap`) with `Admits`/`Mark`, a
no-op `Mark` below the window, and value equality for snapshotting. Only the
tests use it so far. Production still runs two private implementations of the
same idea: `FrameSealer` (src/Pinhole/SessionCrypto.cs) keeps a `Window = 64`
bitmap inline alongside its epoch-rekey logic, and `BlobWire.Cipher.TryOpen`
enforces the strictly-increasing watermark. (The two are deliberately not
identical — the blob watermark has no window; see [WIRE.md](WIRE.md) — but
both reduce to the same admit/mark discipline.)

### A7 — Ledger

**Statement.** Shared budgets are credits in, credits out, conserved:
outstanding equals the sum of live reservations and is zero at quiescence.

**Replaces.** The `BlobController` pacer's internal accounting,
`BlobFlowBudget`, the reorder span, `MaxConnections`, rate limits.

**Status: landed, unwired.** `Pinhole.Crypto.Ledger`
(src/Pinhole.Crypto/Ledger.cs) is the struct: `TryReserve` all-or-nothing,
`Release` that refuses to over-return, invariant documented in the source.
Production budgets remain `BlobFlowBudget` (Interlocked CAS loop,
src/Pinhole.Blobs/BlobController.cs, 8 MiB shared pie) plus the pacer's own
`_inFlight`/`_pacerCreditBytes` scalars. The struct's own comment carries the
plan: it relocates to `Pinhole.Core` with the sans-IO machines.

### A8 — Proof

**Statement.** There is always a path from received bytes to a verified root,
and it is checked before any state (disk, memory, progress) commits.

**Replaces.** The chunk-CV self-check ("verified against the sender's own
claim", audit C-02) with no bound on `Head.TotalBytes` and no root binding
until the very end.

**Status: core landed; receiver integration in flight.** The verified-run
machinery is real:

- `RunVerify.VerifyRun` folds a run's leaf CVs and the Proof frame's sibling
  chain up to the ticket root — a receiver holds 64 KiB in memory and writes
  nothing until the fold matches.
- `RunVerify.FoldRunsToRoot` folds per-run CVs to the root at completion, so
  verified data is hashed once, not twice.
- `RunVerify.SiblingPath` derives the sibling chain from `(runIndex,
  totalChunks)` alone — the proof only supplies CV bytes.
- The provider side, `RunTree`, retains the run tree to emit O(depth) proofs.
- The wire carries it: `BlobWire.Proof` frame and protocol v4 (see
  [WIRE.md](WIRE.md)).
- The support window is decided (issue #49): wire v1/v2 are refused by design
  — no provider, encrypted or plaintext, answers their Hello shapes, and the
  open-only `LegacyDetector` hangs up pre-2.0 sealed traffic so nothing is
  ever sealed under the nonce-reusing fixed key; v3 remains the bridge (the
  v4 fallback and the deployed 1.9.0 interop floor), with removal scheduled
  for the next minor release boundary.

`BlobServer`/`BlobClient` are wiring this into the transfer loop as this
document is written (the v4 Hello negotiation, run staging and
fold-before-write ordering live in those two files, currently being edited);
until that lands everywhere, treat "disk only ever holds verified data" as the
v4 contract, not yet a system-wide invariant.

## The machine catalog

Machines are the A3 units. What exists today versus what section 5 of the
roadmap plans:

| Machine | Owns | Today |
|---|---|---|
| Pacer / `PacerMachine` | receiver-driven wire load: window, slow start/AIMD, RTT/PTO, token-bucket pacing | **extracted** (src/Pinhole.Core/PacerMachine.cs, sans-IO); `BlobController` (src/Pinhole.Blobs) remains as the stats/trace/budget shell |
| Replay window | which counters may still commit: `Admits`/`Mark` over a 64-deep window | **wired** (src/Pinhole.Crypto/ReplayWindow.cs inside `FrameSealer` — the hand-rolled copy was folded away) |
| `FrameSealer` | one direction's seal/open: AES-GCM, epoch rekey, replay bitmap | **current** (src/Pinhole/SessionCrypto.cs) — the session layer's working sealer, awaiting decomposition |
| `RunVerify` / `RunTree` | the verified-run fold: leaf CVs → run CV → root, proofs both ways | **current** (src/Pinhole.Blobs/RunVerify.cs) — pure functions; receiver state machine still forming around them |
| Handshake | tokens, ephemeral/static keys, confirm flags, reject counters, mac1 gate, mac2/cookie gate, knock PSK | **extracted** (src/Pinhole.Core/HandshakeMachine.cs) + **armored** (R5 phases 1+2): versioned PUNC/PACK carry a 16-byte mac1, keyed-BLAKE3 under the responder's static key; a carried-but-failed mac1 refuses silently with no key agreement. Under load (per-source 64/10 s or global 512/10 s, direct UDP only) a PUNC without a valid mac2 — `BLAKE3-Keyed(cookie bound to the source address, frame)` — earns only a 30-byte COOKIE reply: no PACK, no state, no DH; an honest dialer echoes the cookie and completes one extra round trip on the same attempt. With an optional knock configured (phase 2 remainder), mac1 keys under `BLAKE3-DeriveKey("pinhole-knock-mac1-v1", staticPub‖knock)`, unversioned PUNCs are ignored outright (the operator closed that node's v3 window), and the session KDF mixes the knock as a labeled PSK slice — string holders only, same silent refusal for everyone else. The sequencing decision lives in the machine (`CookieRequired`/`CookieOk` → `ReplyCookie`); `NodeEngine` remains the shell (load windows, rotating secret, stranger pre-state gate, knock key material) |
| Path | path state and selection, roam adoption, probe deadlines | **extracted** (src/Pinhole.Core/PathSelectorMachine.cs); `NodeEngine` remains the shell |
| Punch | hole-punch scheduling per candidate | **extracted** (src/Pinhole.Core/PunchSchedulerMachine.cs); `NodeEngine.PunchLoop` remains the shell |
| Pmtu | confirmed wire size, probe tries, next probe tick | **extracted** (src/Pinhole.Core/PmtuMachine.cs) |
| Keepalive | keepalive interval and deadline | **extracted** (src/Pinhole.Core/KeepaliveMachine.cs) |
| BaoVerify | receiver run staging, verified-node cache, fold-before-write | planned shape, landing now — `RunVerify` is its landed core; the staging state lives in `BlobClient`'s v4 path |

## The dependency rule and project layout

**Rule:** `Core` and below know nothing about `Net`. A reference that points
up fails the build. Decision logic (`Pinhole.Core`, planned) may depend on
`Pinhole.Wire` and `Pinhole.Crypto`; shells (`Pinhole.Net`, planned) interpret
effects and own every socket, file and clock.

As built today (src/, from the project files and `Pinhole.Net.slnx`):

| Project | References | Role |
|---|---|---|
| `Pinhole.Wire` | none | canonical codecs over shared primitives (A4) |
| `Pinhole.Crypto` | none | BLAKE3 map/reduce, AEAD wrappers, ReplayWindow, Ledger, Tick (A5–A7 primitives) |
| `Pinhole.Turn` | none | TURN client and REST credentials |
| `Pinhole.Providers` | none | STUN/relay catalogs, resolver |
| `Pinhole` | `Pinhole.Turn`, `Pinhole.Providers` | the engine: transports, handshake, session crypto, discovery, host/join facade |
| `Pinhole.Blobs` | `Pinhole`, `Pinhole.Crypto` | provider/downloader, blob wire, tickets, verified runs |
| `Pinhole.Rendezvous` | none | the introducer/code-directory server binary |
| `Pinhole.Moq` | none | MoQ client over an injected transport (outside the solution file) |

Notes against the section 5 diagram: `Pinhole.Crypto` does not reference
`Pinhole.Wire` today — the roadmap draws that arrow, but the landed primitives
need nothing from Wire; the arrow exists so Core's machines can use both.
Several engine-adjacent types (Iroh/DERP relays, MoQ) live inside or beside
the `Pinhole` assembly rather than in shells above it, and `src/Pinhole.Iroh`
is a leftover empty directory, not a project. The dependency rule is not yet
enforceable because `Pinhole.Core`/`Pinhole.Net` do not exist; the
build-level enforcement (analyzers banning `BitConverter`,
`Environment.TickCount64`, `DateTime(Offset).UtcNow`, `Task.Delay`, LINQ and
`lock` in Core) is R7 work that has not started.

## The deletion ledger

Section 9 of the roadmap: deleting each item must shrink the system. Status as
of 2026-10-26:

| # | Item | Status |
|---|---|---|
| 1 | `PeerSocket`/`PeerEngine` (after `NatDetector` moves to `IUdpSocket` + `StunBindingMessage`) | not started — src/Pinhole/PeerSocket.cs still stands, used by `NatDetector` and `RendezvousLookup` |
| 2 | Blob wire v3 bridge: Hello/Welcome version 3, the `"pinhole-blobs-v3"` HKDF info, the v4→v3 fallback | decided (#49) — v1/v2 have no support path to delete: parser recognition of their Hello shapes plus the fixed-key v1 `LegacyDetector` in `BlobWire.Cipher` are refusal posture (nothing is ever sealed under the nonce-reusing key, not even a Bye) and stay permanently; v3 stays as the v4 fallback bridge and the deployed 1.9.0 interop floor — remove at the next minor release boundary, once the interop target speaks v4 |
| 3 | Plaintext handshake variants and `PinholeEncryption.Optional/Disabled` | not started — the enum and both handshake modes are still in src/Pinhole/SessionCrypto.cs |
| 4 | BouncyCastle `Blake3Digest` use (relay auth moves to the own hash) | not started — still linked by src/Pinhole/IrohRelay.cs |
| 5 | BouncyCastle AEAD/HKDF in blobs | not started — `BlobWire.Cipher` still constructs BouncyCastle `ChaCha20Poly1305` per call and `HkdfBytesGenerator` per session; the BCL-backed `Pinhole.Crypto.Aead` landed but is unwired here |
| 6 | Duplicate `ToWire`, `Clone`, XOR-address codecs, socket factories, backoff helpers, server catalogs (O-02) | not started — the canonical XOR codec now exists twice over (`StunCodec`/`TurnCodec` share the same shape); the five production copies remain |
| 7 | Test seams in production types (D-04), replaced by `Ports` and decorators | not started — `BlobTestHooks` (env var + `AsyncLocal`) still ships in src/Pinhole.Blobs/BlobController.cs; `PinholeOptions` seams unchanged |
| 8 | `TreeEntry` tree retention in `Blake3.Tree` | partially done — the node-chain retention is gone; `Pinhole.Blobs.Blake3.Tree` now keeps a flat per-chunk CV list (needed to serve and prove) and delegates folding to `Pinhole.Crypto`; final shape awaits the verified-run provider settling on `RunTree` |
| 9 | Per-chunk `Dictionary` outstanding table (replaced by a window ring) | not started — `BlobClient` still runs `Dictionary<long, …>` for outstanding requests, staging, reorder and received runs |
| 10 | `BlobTestHooks` env-var switch | not started — same item as 7's example; still read at class-load time |

The ledger is the acceptance test for the axioms: when an axiom lands on a
production path, the row it obsoletes should be executable in the same change.
