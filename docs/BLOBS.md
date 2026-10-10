# Pinhole.Blobs wire protocol

`Pinhole.Blobs` is the file-transfer layer above the connection core: serve a file or a
whole directory from one machine, download it from another with a single ticket —
chunk-verified while streaming, resumable across restarts, healed through datagram loss,
and (by default) encrypted so the relays forward nothing but ciphertext. It is the
[sendme](https://github.com/n0-computer/sendme) model, built on Pinhole connections
instead of iroh endpoints.

This document specifies the format precisely enough to re-implement either side. The
core connection wire format lives in [PROTOCOL.md](PROTOCOL.md).

## API surface

```csharp
// Provider: serve until disposed; the ticket is the whole capability.
await using var server = await BlobServer.ServeAsync(path, new BlobServeOptions());
Console.WriteLine(server.Ticket);          // re-minted per read, carries live candidates

// Downloader: anywhere on earth, verified + resumable, progress optional.
var result = await BlobClient.DownloadAsync(ticket, destinationDir,
    progress: new Progress<BlobProgress>(p => Console.WriteLine($"{p.VerifiedBytes}/{p.TotalBytes}")));
// result.Path, result.Bytes, result.Resumed
```

`BlobServeOptions`: `Encrypt` (default **true** — generate a per-ticket pre-shared key
and wrap every frame) and `NodeOptions` (full `PinholeOptions` override for the dedicated
serving node; defaults resolve the free STUN catalog and public iroh relays).

## Tickets

`pinholeblob1:<base64url>` — the scheme word and format version, then a binary payload:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version (`1`) |
| 1 | 1 | flags: bit 0 = kind (`0` file, `1` directory), bit 1 = encrypted (`1` = PSK present) |
| 2 | 1 | name length `n` (UTF-8 bytes, ≤ 255, truncated on encode) |
| 3 | `n` | name (suggested download filename / directory name) |
| 3+n | 32 | content root (BLAKE3) |
| 3+n+32 | 0 or 32 | pre-shared key, present iff the encrypted flag is set |
| … | 2 + `c` | connection string: `u16` little-endian byte length + ASCII (`pinhole1:…`) |

`Parse` is strict (exact-length base64url, exact version, no trailing bytes) and rejects
anything above 16 KiB encoded. The ticket is **the capability**: whoever holds it can
download, exactly once per connection, until the provider is disposed. Keys travel with
capability — the sendme trust model, stated out loud.

## Content addressing

BLAKE3 over 1 KiB chunks. The provider hashes the content once at `ServeAsync` time and
keeps the chunk chaining values (the "outboard" tree):

- chunk CV = `blake3_chunk_cv(chunk_bytes, chunk_index)` — the standard chunk hash with
  the chunk counter, no root finalization;
- content root = the tree over all chunk CVs (empty content hashes to the standard
  BLAKE3 empty hash, `af1349b9…f3262`).

Every chunk frame carries its CV; the downloader verifies each chunk **on arrival** and
re-computes the full tree while applying chunks in order, comparing the final root
against the ticket. A provider can lie about a chunk (caught immediately by its CV) or
about a whole consistent-looking forgery (caught by the root) — there is no state in
which unverified bytes reach the output file.

## Frames

Blob frames ride inside ordinary Pinhole datagrams on a dedicated connection. Plaintext
layout: `[type u8][stream u64 big-endian][body]`. The **stream id** is the first 8 bytes
of the content root, big-endian — one blob per root, several streams may share one
connection (directory downloads).

| Type | Body |
|---|---|
| `1` Hello | `version u8 = 3`, `sessionId[32]` — the downloader's random nonce. Unsealed at the blob layer. An empty body (v1) or 32-byte body (v2) remains parseable for explicit refusal. |
| `2` Head | `totalBytes i64 LE`, `totalChunks i64 LE` |
| `3` Req | `startChunk i64 LE`, `count u16 LE` (1..64) |
| `4` Chunk | `chunkIndex i64 LE`, `cv[32]`, `data[≤1024]` |
| `5` Bye | empty — downloader is done with the stream |
| `6` Welcome | `version u8 = 3`, `sessionId[32]`, `providerNonce[32]`, `sealedHead[49]` — the provider's first response and response to Hello retries on an encrypted ticket. The sealed Head authenticates both nonces through key derivation. |

The largest plaintext frame (Chunk) is 9+8+32+1024 = 1073 bytes, sized to stay under the
connection layer's 1200-byte datagram budget with the AEAD overhead included.

### The transfer loop (downloader-driven ARQ, congestion-controlled)

- The downloader sends Hello until a Head arrives (inside Welcome for encrypted tickets;
  20 s give-up), then requests ranges from the **lowest unapplied chunk** upward, admitted
  by the congestion controller (below). Requests never outrun the sink's reorder horizon:
  a chunk asked for more than the bounded reorder window (512 chunks) past the applied
  cursor would be dropped on the floor on arrival — with its ARQ reservation consumed —
  wasting wire bytes and leaving a hole nothing re-requests (#36). The horizon slides
  forward with the applied prefix, so large windows still fill; they just cannot hold
  out-of-order requests farther than the buffer could keep them.
- Missing chunks are re-requested individually after an RTT-derived retransmission timer.
- A stall — no chunk verified for 30 s — or a connection that closes or goes quiet ends
  the **attempt**, not the download: the recovery loop (below) re-dials the pinned
  provider and resumes from checkpoints. Permanent verdicts — a tampered frame, a root
  mismatch, a refused handshake — still end the call immediately.
- Directory downloads: stream 1 is the manifest (below), then each entry root downloads
  as its own stream over the same connection, sequentially, sharing one frame-counter
  space (see encryption).

### Recovery and resume (#32)

One `DownloadAsync` call rides out recoverable disruptions by itself: while no usable
path exists the stall and first-contact clocks pause (there is no path to verify
progress on — the engine's recovery, not our clock, is what ends the wait), request
growth and retransmission pause, and a connection that dies entirely is re-dialed
through the same ticket — authenticated rediscovery included — after a doubling backoff
(500 ms → 5 s cap). Everything draws down one budget:
`BlobDownloadOptions.RecoveryTimeout` (default 10 min — a five-minute outage must be
survivable). Exhausting it throws `TimeoutException` ("could not be re-established");
zero disables recovery and surfaces the first transport failure as `TimeoutException`
naming the dead attempt. The caller's cancellation token is honored promptly even
mid-blackout. The allowance is shared across all streams, outages, pending dials
and retry backoff in the call. Healthy transfer time does not spend it. A pending
dial is cancelled when its remaining allowance expires, and the stream checks the
allowance even while its ordinary stall clock is paused. With a shorter allowance,
the first-Head and no-progress attempt limits use the remaining time rather than
extending recovery to their usual 20 s / 30 s limits.

A re-dial gets a fresh `DownloadSession`: a fresh downloader nonce, and the provider's
Welcome mints its own fresh nonce — every connection derives a fresh two-sided key and
restarts counters with it; a recovery never continues old counters under recreated
keys. Resume is then real on the wire, not just on disk: the attempt's requests anchor
at the checkpointed prefix's first gap, so verified bytes never cross the network
twice, and reported progress never visibly regresses. Directory downloads carry the
decoded manifest and the set of completed roots across re-dials — finished files are
skipped, not re-verified.

The failure taxonomy is the contract: `TimeoutException` means the route did not come
back inside the budget; `InvalidDataException` means a fact about the content or the
provider (bad chunk, root mismatch, stream cancelled); `OperationCanceledException`
means the caller ended it. A dial the engine *refuses* (incompatible peer, pinning
mismatch) is terminal like the content verdicts — but a stranger who simply never
answers is indistinguishable from a dead provider, and riding that out is what makes
provider restart work.

### The congestion controller (#20)

The receiver drives all wire load — the requests it issues are the only thing that pulls
data — so the controller lives on the downloader and the wire is unchanged (a
controller-mode downloader talks to any v3 provider and vice versa; no frames were added,
no version moved). What it does, all receiver-side:

- **RTT measurement and PTO.** Every first-attempt arrival samples the RTT into
  SRTT/RTTVAR (RFC 6298/9002-shaped); Karn's rule excludes retransmitted requests from
  the estimate. The retransmission timer is `SRTT + max(4·RTTVAR, 50 ms)` clamped to
  [150 ms, 3 s], doubling per retransmission of the same chunk. A duplicate-response
  signal (the timer fired while the data was merely slow) inflates the timer, at most 4×,
  and one clean loss-window relaxes it fully.
- **Byte-based window, slow start, AIMD.** Outstanding requested-but-unverified chunk
  bytes are capped by a window starting at 32 KiB, doubling per RTT in slow start
  (paced against the path's *base* RTT so the climb is not throttled by the queue it is
  building), then growing ~1 chunk per RTT. A congestion event halves it — at most once
  per RTT, and only on congestion evidence: three expiries inside one loss window (a
  burst died together — queue overflow) or standing delay ≥ 1.6× the base RTT. Scattered
  random loss re-requests without halving; a steady 5% rung would otherwise ratchet the
  window to the floor. After a reduction the window sits *below* the new threshold so
  slow start rebounds exponentially instead of crawling.
- **Pacing.** A token bucket fills at window rate (window bytes per RTT) with burst
  credit capped at one run; runs size themselves to the credit actually available. Each
  Req run — a back-to-back provider burst — is bounded by the window (≤ 1/8 of it,
  clamped to [2, 64] chunks). In congestion avoidance the pacing RTT is capped at 4×
  the measured *base* RTT: queueing delay is self-inflicted evidence that already
  halves the window — letting it also stretch the pace collapses the issue rate
  quadratically (found by the #34 sustained-size test: a 4 MiB transfer starved to
  ~150 KiB/s on an 8 Mbit/s link).
- **Recovery is not load.** A lost chunk's reservation holds window room until it
  arrives, and it holds exactly ONE reservation no matter how often it is retried —
  the re-request is the same outstanding bytes, not new ones (an earlier design
  charged a fresh budget reservation per retry, so sustained loss stacked enough
  phantom debt to deny recovery itself). Re-requests bypass the window and pacer,
  bounded by the PTO cadence and the reorder horizon; gating recovery on the window
  it is trying to refill livelocks at the floor rate (measured: pacing re-requests
  through the shared credit bucket collapsed every lossy rung to ~30 KiB/s).
- **Duplicates are wire load.** Bytes that arrive for an index already held count as
  `DuplicateBytes` in `BlobTransferStats` — request credits are never treated as proof
  of a bounded response side.
- **Migration and pathlessness.** An endpoint change (seamless adoption included — the
  remote address is compared directly, since the state never has to leave Open to roam)
  or a return from ≥ 500 ms of pathlessness resets the controller to its initial window
  with clean timers and refreshes every outstanding request's clock: the resume probes
  conservatively instead of flooding a fresh path with a stale window's re-requests.
  Requesting pauses entirely while no path exists.
- **Aggregate budget.** Every download joins `BlobFlowBudget.Shared` (8 MiB process-wide;
  pass a private `BlobFlowBudget` via `BlobDownloadOptions.FlowBudget` to isolate one).
  Opening more simultaneous downloads divides that pie instead of multiplying per-flow
  windows. A stalled or cancelled download releases every reservation it holds.

Tunables: `BlobDownloadOptions.MaxWindowBytes` (default 1 MiB) caps the window;
`BlobDownloadOptions.Stats` fills a live `BlobTransferStats` (verified/duplicate bytes,
retransmits, loss events, RTT, window) for diagnostics.

The honest cost: on a clean fat pipe a *short* transfer (a few BDPs) pays the slow-start
climb (~100 ms) that an instantly-flooded fixed window does not — measured below as the
one rung where the controller trails the fixed window, with near-empty queues where the
fixed window bufferbloated. The selected rules and measured tradeoffs are in
[BASELINES.md](BASELINES.md); the reuse-first evaluation that led to building this
controller instead of adopting a component is next.

### Component selection (the reuse-first answer)

Evaluated for "maintained, fully managed C#, sits above a datagram API" against
maintenance, license, AOT/trimming, cancellation, bounded memory, pacing/loss recovery,
congestion mode, and integration/wire compatibility:

| Candidate | Verdict | Why |
|---|---|---|
| [kcp2k](https://github.com/MirrorNetworking/kcp2k) (MIT, actively maintained, Mirror's default transport) | **not adopted** | Its own README: "Congestion Control should be left disabled. It seems to be broken in KCP." Adopting it means adopting an ARQ whose congestion control is recommended off — the #20 requirements would still need a hand-written controller *plus* KCP's sender-driven byte-stream model, which discards the receiver-driven trust properties (anchored window, verify-on-arrival before buffering). |
| [LiteNetLib](https://github.com/RevenantX/LiteNetLib) (MIT, maintained) | **not adopted** | A transport, not a layer above one: it owns sockets, connections, and its own framing — embedding it under Pinhole would be a second transport stack. Its reliable channel uses fixed-window resends with no congestion avoidance (no cwnd, no AIMD, no pacing). |
| Lidgren / lidgren-genome | **not adopted** | Sparse-to-dormant maintenance; same transport-level mismatch. |
| System.Net.Quic / MsQuic | **excluded** | Native OS bindings (full managed C# is a hard constraint) and a complete transport with its own handshake — it cannot sit above Pinhole's datagram API. |

Conclusion, per the roadmap's escape hatch: no component fits; the controller above is
the smallest justified adaptation of established algorithms (RFC 6298 RTO math, RFC 9002
slow-start/IW/PTO/migration-reset thinking, RFC 8085 UDP congestion guidance, RFC 6675's
one-reduction-per-window rule). It is not QUIC-compatible and claims to be nothing but
itself.

### Directories

A directory is a manifest blob plus one blob per file. The manifest is binary, not JSON —
trivially AOT-safe: `[nameLen u8][name][entryCount u32 LE]` then per entry
`[pathLen u16 LE][path (UTF-8, '/'-separated)][size i64 LE][root 32]`. The ticket root
for a directory is the **manifest's** root (single indirection: ticket → manifest →
entry roots). Entry paths are sanitized on download: absolute paths and `..` segments
are rejected, so a hostile manifest cannot write outside the destination directory.

## Encryption

When the ticket carries a PSK (the default), frames use ChaCha20-Poly1305 under
`HKDF-SHA256(psk, salt = ticket root ‖ sessionId ‖ providerNonce,
info = "pinhole-blobs-v3")`. The root and both nonces are exactly 32 bytes; HKDF
produces a 32-byte key. Each endpoint contributes independent cryptographic freshness:

- **`sessionId`** (32 bytes, from the downloader's unsealed Hello) — the downloader's
  contribution;
- **`providerNonce`** (32 bytes, generated by the provider on the first v3 Hello on
  each connection) — the provider's contribution, independent of routing tokens and
  downloader behavior. The provider retains it for Hello retries and directory streams.

The provider answers Hello with a 123-byte Welcome: its unsealed prefix echoes the
downloader's nonce and carries the provider's nonce; its final 49 bytes are a sealed
25-byte Head. The client checks the echoed nonce and stream, derives a candidate key,
verifies the Head's tag and stream, and only then commits the provider nonce, key, and
receive watermark. A forged Welcome cannot fix the client's key or burn a counter.
After negotiation, a different provider nonce is refused. Every Hello retry returns
a Head with a fresh counter under the existing key; it does not restart the cipher.

A repeated downloader nonce therefore does not force the provider to reuse its key.
Random 256-bit provider nonces make collisions negligible; 32-bit engine routing
tokens are excluded entirely. Honest downloaders also generate a fresh 256-bit nonce
for each attempt so old Welcomes cannot authenticate on a new attempt. Directory
entries use the ticket's manifest root in the key derivation and retain the same
connection state. Blob encryption also works when core session encryption is disabled:
the nonces and stream IDs are visible, while content remains ticket-encrypted.

Ordinary sealed wire form: `[counter u64 LE][ciphertext][tag 16]`. The 12-byte nonce
is `[role u8][counter u64 LE][zero × 3]` where role separates provider (`1`) from
downloader (`0`) — reflected frames cannot decrypt.

The counter is per-connection and per-direction, monotonic, shared across all streams
on the connection (directory downloads move between streams; a per-stream counter
would look like a replay). Receivers run an authenticate-then-commit watermark:
**the highest-authenticated counter moves only when a frame's tag verifies** — a
forged far-future counter cannot starve the frames behind it, and a replayed or
regressed old counter cannot re-admit the frames before it (the same rule the session
layer's replay window enforces; the counter is plaintext on the wire, exactly like
the session token). A tag failure drops the frame silently, costing the sender one
retransmit cycle, and the counter in the clear reveals only rough progress. Replay
safety and integrity hold even against the relay itself.

With `Encrypt = false` (trusted high-speed LANs) frames go out as plaintext — the
verification story is unchanged, only confidentiality is given up.

### Compatibility (wire v3)

- An encrypted v3 provider closes connections presenting a v1/v2 Hello. It also
  recognizes sealed v1 traffic through the fixed-key open-only detector, then closes
  without sending any blob ciphertext under that key. No fallback to old encryption.
- A v1/v2 provider cannot parse the explicitly versioned v3 Hello, so a v3 downloader
  against one reaches the ordinary first-contact timeout. Upgrade both sides. The
  ticket format is unchanged; the blob wire version is explicit in Hello and Welcome.
- Plaintext serving (`Encrypt = false`) accepts all documented Hello shapes and
  answers with an ordinary Head. It requires no key negotiation.

**Changed defaults (#32).** Pre-recovery, a connection that closed or went quiet
mid-transfer failed the call with `InvalidDataException` at once, and a 30 s stall was
outright fatal. Both are now *attempt* failures the recovery loop rides out; the call
fails only when `RecoveryTimeout` (default 10 min) is spent, as `TimeoutException`.
Wire compatibility is untouched — no new frames, no version bump, and a resumed
download simply requests a shorter tail, which any v3 provider already serves.
Migration for the old behavior: `RecoveryTimeout = TimeSpan.Zero`.

## Resume

Interrupted downloads leave `<target>.pinhole-part/` behind:

- `data` — the raw chunk data written at final offsets, in arrival order;
- `state` — `magic "PBPART01" ‖ content root ‖ totalBytes ‖ appliedPrefixCount`.

Only the contiguous **applied prefix** counts (the hashing tree cannot skip): the next
attempt replays those chunks through the tree and resumes at the gap. A state file whose
root or size does not match, or whose `data` is shorter than the prefix claims, restarts
from zero. On success the part file is truncated to the exact size, promoted over the
target, and the part directory is deleted. Checkpoints are written on the transfer's
50 ms control cadence — resuming never redoes more than a fraction of a second.

The same machinery drives *within-call* recovery (#32): when a connection dies
mid-transfer the recovery loop re-dials and the fresh attempt's sink reloads the
checkpoint — so a provider restart resumes the surviving prefix automatically, not
just a caller-initiated retry.

## Sample

```
dotnet run --project samples/Pinhole.Send -- send ~/photos.tar    # prints ticket, serves until Ctrl-C
dotnet run --project samples/Pinhole.Send -- recv <ticket> ~/dl   # verified, resumable download
```
