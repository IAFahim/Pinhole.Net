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

### The transfer loop (downloader-driven ARQ)

- The downloader sends Hello until a Head arrives (inside Welcome for encrypted tickets;
  20 s give-up), then requests ranges
  from the **lowest unapplied chunk** upward — at most 4×64 chunks in flight, at most 64
  per Req. A hostile sender cannot make the downloader buffer the far end of the file:
  anything past a bounded reorder window (512 chunks) ahead of the applied cursor is
  dropped and re-requested in order.
- Missing chunks are re-requested individually after 900 ms without a verified arrival.
- The whole download fails if **no chunk verifies** for 30 s (stall) — loss is healed,
  silence is fatal, honestly.
- Directory downloads: stream 1 is the manifest (below), then each entry root downloads
  as its own stream over the same connection, sequentially, sharing one frame-counter
  space (see encryption).

### Congestion control (1.9.0)

The rules above describe the ARQ's shape; this section is the control law that sizes it.
Congestion control lives **entirely in the downloader** — a deliberate consequence of the
receiver-driven design: requests are the provider's only permission to send, so the
downloader's request window *is* the data path's send window, and no provider change is
needed (a 1.9.0 downloader against a 1.8.0 provider gets full CC; the wire carries
nothing new).

**Why not the fixed window.** 256 KiB of in-flight chunks with a fixed 900 ms re-request
timer is fine on an empty lab link and wrong everywhere else: it fills a bottleneck's
queue in one burst (loss that is the sender's own fault), re-requests on a cadence blind
to the actual round trip, and two downloads sharing a link fight by queue-overflow luck.

**The control law — paced AIMD over request credits:**

- **RTT estimation** (RFC 6298 shape): every chunk that arrives on its *first* request
  samples `now − requestedAt`; re-requested chunks are excluded (Karn's rule — their
  samples include the retransmission and would inflate the estimate). `srtt ← 7/8 srtt +
  1/8 sample`, `rttvar ← 3/4 rttvar + 1/4 |sample − srtt|`, seeded 100 ms / 50 ms.
- **Retransmission timer**: a missing chunk is re-requested after `rto = clamp(srtt +
  4·rttvar, 200 ms, 2 s)` — replacing the fixed 900 ms. Fast paths recover fast; stalled
  paths stop feeding a fixed-cadence flood.
- **Congestion window (`cwnd`)**, in chunks: outstanding requested-but-unreceived chunks
  never exceed it. Initial 32 (a modest slow start), minimum 8 (the timer floor — one
  probe run keeps healing alive), maximum 512. It replaces the fixed 4×64 window.
- **Pacing**: every request — new or re-request — consumes a token from a bucket refilled
  at `cwnd chunks / srtt` (≈ `cwnd·1 KiB / srtt` bytes/s), burst allowance 4 requests.
  The control loop tick drops from 250 ms to 50 ms so pacing is meaningful. Pacing is
  what keeps a temporarily-too-high window from overflowing the queue in a burst.
- **Loss response — multiplicative decrease, once per RTT epoch**: firing a re-request
  is the loss signal. If no decrease happened within the last `srtt`, the window drops
  to `⌈cwnd · 3/4⌉` (floor 8) and that point becomes the **slow-start threshold**
  (`ssthresh`). The 3/4 factor (not TCP's 1/2) is deliberate: re-requests also fire
  under random loss that has nothing to do with congestion, and halving on every 5 %-loss
  round would pin the window near the floor. AIMD still converges to a fair share with
  any decrease factor; only convergence speed changes.
- **Growth**: a loss-free epoch doubles `cwnd` while it is below `ssthresh` — fast
  recovery back to the pre-loss operating point — and adds one chunk per epoch above it
  (additive probing, cap 512). Without the threshold, one slow-start overshoot would
  cost minutes of +1-per-epoch crawling; with it, a random-loss dip heals in two or
  three RTTs.

**How retries avoid amplifying congestion.** Six rules, each closing a specific flood
path: (1) re-requests are *selective* — exactly the missing chunk, never the run; (2)
re-requested chunks occupy the same `cwnd` budget, so a loss shrinks the window *before*
the next requests leave; (3) re-requests draw from the same pacer bucket as new requests
— there is no separate retransmit lane to burst on; (4) the RTO is RTT-derived, so a slow
path stretches its retries instead of re-flooding every 900 ms; (5) a chunk that has
already been re-requested backs off exponentially (2×, 4× the RTO) — a chunk that is
merely slow deep in a paced pipeline must not re-fire every timer tick, and only a
chunk's *first* re-request counts as a loss signal; (6) the stall clock and the
pathlessness ride-out bound the whole loop — a dead path ends the download honestly
rather than spinning the request pump.

**Fairness argument.** Two paced AIMD flows with equal RTT sharing one bottleneck is the
classical fixed point: each flow's losses scale with its share of the queue overflow,
each backs off multiplicatively once per epoch, each grows additively — shares converge
to equal. Pacing removes the window-quantization bursts that make unpaced AIMD unfair in
practice. The lab's two-flow bottleneck test (below) measures this as a Jain index.

**Validation discipline** (`tests/Pinhole.Tests/CongestionTests.cs`, lab in
`docs/TESTING.md`): longer transfers (2 MiB per flow), multiple recorded seeds per rung,
comparing CC against the fixed-window baseline (kept reachable through an internal test
seam) on four axes: goodput, mean/max bottleneck queue wait, redundant retransmissions,
and Jain fairness across two competing flows. The bar is *not* "faster at every loss
level" — on a clean uncongested link the fixed window can win outright. The bar is: at
equal goodput under congestion, materially lower queue delay and fewer wasted
retransmissions; and a near-even split between competing flows that the fixed window
does not achieve.

The whole-download stall rule (30 s without verified progress) is unchanged, and the
reorder-window bound (512 chunks past the applied cursor) still applies — `cwnd` never
exceeds it.

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

## Resume

Interrupted downloads leave `<target>.pinhole-part/` behind:

- `data` — the raw chunk data written at final offsets, in arrival order;
- `state` — `magic "PBPART01" ‖ content root ‖ totalBytes ‖ appliedPrefixCount`.

Only the contiguous **applied prefix** counts (the hashing tree cannot skip): the next
attempt replays those chunks through the tree and resumes at the gap. A state file whose
root or size does not match, or whose `data` is shorter than the prefix claims, restarts
from zero. On success the part file is truncated to the exact size, promoted over the
target, and the part directory is deleted. Checkpoints are written on the transfer's
natural 250 ms pacing — resuming never redoes more than the last fraction of a second.

## Sample

```
dotnet run --project samples/Pinhole.Send -- send ~/photos.tar    # prints ticket, serves until Ctrl-C
dotnet run --project samples/Pinhole.Send -- recv <ticket> ~/dl   # verified, resumable download
```
