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
| `1` Hello | `sessionId[32]` — a fresh random id per connection; the frame rides **plaintext** (it names the salt the cipher derives from, so it cannot be sealed under it; the id is a salt, not a secret — only the PSK turns it into keys). Answered with Head every time, so a lost first Head costs one retransmit. An empty body is the pre-2.0 shape, kept parseable only so an encrypting provider can refuse it (below) |
| `2` Head | `totalBytes i64 LE`, `totalChunks i64 LE` |
| `3` Req | `startChunk i64 LE`, `count u16 LE` (1..64) |
| `4` Chunk | `chunkIndex i64 LE`, `cv[32]`, `data[≤1024]` |
| `5` Bye | empty — downloader is done with the stream |

The largest plaintext frame (Chunk) is 9+8+32+1024 = 1073 bytes, sized to stay under the
connection layer's 1200-byte datagram budget with the AEAD overhead included.

### The transfer loop (downloader-driven ARQ)

- The downloader sends Hello until a Head arrives (20 s give-up), then requests ranges
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

### Directories

A directory is a manifest blob plus one blob per file. The manifest is binary, not JSON —
trivially AOT-safe: `[nameLen u8][name][entryCount u32 LE]` then per entry
`[pathLen u16 LE][path (UTF-8, '/'-separated)][size i64 LE][root 32]`. The ticket root
for a directory is the **manifest's** root (single indirection: ticket → manifest →
entry roots). Entry paths are sanitized on download: absolute paths and `..` segments
are rejected, so a hostile manifest cannot write outside the destination directory.

## Encryption

When the ticket carries a PSK (the default), every frame except the Hello is sealed in
both directions with ChaCha20-Poly1305 under `HKDF-SHA256(psk, salt = content root ‖
sessionId ‖ transportBinding, info = "pinhole-blobs-v2")`. Two salts fork the key per
connection, each contributing freshness from a different place:

- **`sessionId`** (32 bytes, from the downloader's plaintext Hello) — the downloader's
  contribution;
- **`transportBinding`** (8 bytes) — the connection's two engine tokens, numerically
  ordered: each endpoint generates a fresh random token per connection and learns the
  peer's during the engine handshake. The **provider contributes freshness here** — a
  buggy or hostile downloader that repeats an earlier session id still derives a
  different key, because the new connection's token pair is new.

So two tickets never share a stream cipher even when a caller reuses a key, two
connections sharing one ticket never share a cipher, and per-connection counters
restarting at 1 are safe by construction. (The pre-v2 wire had no per-connection
fork at all; the unreleased first cut of v2 forked on the session id alone — both are
refused, below.) Wire form: `[counter u64 LE][ciphertext][tag 16]`. The 12-byte nonce
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

### Compatibility (wire v2)

- A v2 provider **refuses a pre-2.0 downloader by hanging up**: the first frame that
  opens under the old fixed per-ticket key (`pinhole-blobs-v1`) closes the connection
  immediately. Nothing is ever *sealed* under the legacy key — not even a refusal Bye,
  which would re-use its nonce 1 across two refusals; the old derivation exists only
  as an open-only detector. The legacy peer fails fast (connection went quiet)
  instead of timing out at first contact, and the server keeps serving others.
- A pre-2.0 provider cannot parse the v2 Hello, so a v2 downloader against one fails
  with the ordinary first-contact timeout — upgrade both sides.
- Plaintext serving (`Encrypt = false`) accepts any Hello body: with no cipher there
  is nothing to fork.

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
