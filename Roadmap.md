# Pinhole Roadmap: from engine to axioms

Authored 2026-10-21 from a static read of the code dump (`Pinhole`, `Pinhole.Blobs`, `Pinhole.Moq`, `Pinhole.Providers`, `Pinhole.Rendezvous`, `Pinhole.Turn`).
Nothing was built, run, benchmarked or profiled. Tests, csproj files, docs and `extern/` were not read.

Every finding carries a tag:

- **[read]** follows directly from the source as dumped.
- **[confirm]** plausible, needs the named test or measurement before anyone acts on it.

Sizes are S (days), M (1-2 weeks), L (several weeks). They are guesses for ordering, not promises.

---

## 1. Thesis

Pinhole's value is decision logic: which path wins, when a handshake is valid, how fast to pull data, which bytes are authentic. Today that logic is fused to its effects: sockets, threads, wall clocks, files, `Task.Delay`, exceptions as control flow. That fusion is what makes it hard to put in a Unity ECS hot path, hard to test without flakes (`AGENTS.md` already records two), and hard to reason about.

Three moves unlock everything else:

1. **Sans-IO.** Time and bytes come in, bytes and timers go out. No machine reads a clock, opens a socket, or sleeps.
2. **Unmanaged state.** Per-connection state becomes plain structs. No object graph, no `lock`, no `Dictionary` of tuples.
3. **Total edges.** Codecs return `bool`, machines return typed outcomes. No `Try*` that throws, no failure classification by exception type.

The direct-UDP send path (`stackalloc` frame, in-place seal, `SendTo(span)`) already satisfies all three in miniature. Treat it as the template for everything else.

---

## 2. The axioms (smallest set the system reduces to)

| # | Axiom | Statement | Replaces today |
|---|-------|-----------|----------------|
| A1 | Time is an input | `Tick` is passed to every step; never read | ~100 reads of `Environment.TickCount64`, `DateTimeOffset.UtcNow`, `Task.Delay` pacing |
| A2 | Datagram | `(PathId, bytes)` in, `(PathId, bytes)` out | `IUdpSocket`, `TurnClient`, `IrohRelay`, `DerpRelay`, `TcpLink` as five I/O styles |
| A3 | Machine | `Step(ref State, in Input, Tick, Span<Effect>) -> int` | `NodeEngine`, `StreamDownloader`, `BlobController`, `PortMappingService`, `PunchLoop` |
| A4 | Codec | total `TryRead(span, out T) -> bool`, `Write(in T, span) -> int`, canonical | `ConnectionString`, `AddressRecord`, `BlobWire.Frame`, `Manifest`, `DnsCodec`, `StunBindingMessage`, TURN, MoQ wire |
| A5 | Hash | BLAKE3 as map (chunk CV) then reduce (parents) | `Blake3.Tree`, per-chunk `ChunkCv`, `Manifest` root |
| A6 | Window | `Admits(counter)`, `Mark(counter)` on a 128-bit value | `FrameSealer` window and the blob layer's strict watermark, as one primitive |
| A7 | Ledger | credits in, credits out, conserved | `BlobController` pacer, `BlobFlowBudget`, reorder span, `MaxConnections`, rate limits |
| A8 | Proof | a path to a verified root, checked before any state change | `ChunkCv` self-check (today), Bao (target) |

Everything else is composition. Deleting a feature must delete code, not break unrelated code. Section 9 lists what the axioms let you delete.

---

## 3. The magic this unlocks

1. **Deterministic simulation.** One seed gives one replayable world: NATs, loss, reorder, duplication, clock skew. Thousands of topologies per second in CI. Flaky timing tests disappear by construction. The existing in-process topology lab becomes the default test substrate instead of a special one.
2. **Burst-parallel hashing.** BLAKE3 chunk CVs are independent, so hashing is `IJobParallelFor` over chunks plus a log-depth parent reduction. A multi-GB asset hashes in the time of a disk read, with zero GC.
3. **Verified streaming that is actually verified.** Proofs against the root before any byte is written. Bounded disk and memory against a hostile provider, O(1) resume, partial and ranged reads, and interop with iroh-blobs-style Bao.
4. **An ECS data plane.** Sessions as entities; `Open -> Route -> App -> Seal -> Transmit` as systems; AEAD open and seal as `IJobEntity` over batches. Zero managed allocation in steady state.
5. **One transport seam for engines.** A Unity Transport `INetworkInterface` provider so Netcode for GameObjects/Entities gets NAT traversal and relay fallback with no dedicated server. A NativeAOT C ABI (`pinhole_step`) for Godot, Unreal, Bevy or a custom engine.
6. **Silent to strangers.** WireGuard-style `mac1`/cookie in the handshake. No reflection, no CPU burned on forged handshakes, no candidate disclosure to port scanners.
7. **Free redundancy.** `FrameSealer` already dedupes by counter. Sending one sealed frame on two paths (relay and direct) during migration therefore gives zero-loss handoff with a one-line change to routing, because the second copy is rejected as a replay.
8. **Provable properties.** Codec round-trips, totality under fuzz, budget conservation, and "same seed implies same effect-log hash" as CI gates.

---

## 4. Audit

### 4.1 Correctness and security

**C-01 [read] Directory download silently drops duplicate-content files.**
`BlobClient.DownloadAsync` keeps `completedRoots` keyed by content root and `continue`s for any entry whose root is already in the set. Within one attempt the second file with the same bytes is never written, yet `filesDone` advances. Empty files all share one root, so a tree with several `.gitkeep` or `__init__.py` files loses all but the first.
Fix: key completion by destination path. For a repeated root, materialize by copy or reflink from the first written path. Test: serve a tree with three identical files and assert all three exist, byte-identical.

**C-02 [read] "Verified streaming" is verified against the sender's own claim.**
`ReceiveChunk` compares the chunk's hash with the CV carried in the same frame. Nothing ties that CV to the root until `Complete()` at the very end. Consequences:
- `Head.TotalBytes` is unbounded and not pinned by the ticket, so a hostile provider makes the receiver write until the disk is full.
- `MemorySink` (directory manifest) accepts unsolicited chunks at any index below the claimed size and retains them forever. Unbounded memory, and the manifest has no size cap.
- `VerifiedBytes`, progress and checkpoints mean "self-consistent", not "authentic". Resume compensates by re-hashing the whole prefix every time.

Interim fix: pin size in the ticket, cap manifest size, drop chunks that are not outstanding. Real fix: R2.

**C-03 [read] The blob layer drops reordered authentic frames.**
`Cipher.TryOpen` requires a strictly increasing counter. Any reorder (relay-to-direct migration, multipath, ordinary jitter) discards genuine chunks. ARQ re-requests them and the controller reads the result as loss or duplicates. The session layer already holds the right primitive (64-frame window in `FrameSealer`). Reuse it (A6).

**C-04 [read] Culture-sensitive manifest order.**
`Directory.EnumerateFiles(...).Order()` uses the default string comparer. The same tree yields different manifest bytes, hence a different directory root, under different cultures or ICU vs invariant globalization. Content addressing is not reproducible. Use `StringComparer.Ordinal` and specify the order in `docs/BLOBS.md`.

**C-05 [read] Host-endian encodings in wire and hashed formats.**
`BitConverter` is used in `Manifest.Encode` (hashed), `BlobTicket`, `ConnectionString.WriteU64`, `AddressRecord.WriteU64`, `NodeEngine.WriteHeader/BuildPunc` and ping timestamps, while reads elsewhere use `BinaryPrimitives...LittleEndian`. On a big-endian host (s390x) writes and reads disagree and manifest roots diverge. Use `BinaryPrimitives` only; ban `BitConverter` with an analyzer.

**C-06 [read] `Try*` functions that throw (partial functions).**
- `AddressRecord.TryParseVerified` calls `DateTimeOffset.FromUnixTimeSeconds(expires)` on an unverified `long` before checking the signature. An out-of-range value throws `ArgumentOutOfRangeException`. The caller `ResolveViaLookupAsync` is fire-and-forget and catches a narrower set. Compare Unix seconds as integers.
- `IrohDiscovery.ParsePayload` uses a throwing UTF-8 decoder; `DecoderFallbackException` escapes as an `ArgumentException`.
- `BlobTicket.TryParse(null)` calls `Parse(null)`, which throws `ArgumentNullException`, contradicting "false on any malformed input".

**C-07 [read] Rendezvous token generation is accidentally correct.**
`Token.New` writes 24 base64 characters into a 26-char `stackalloc` span, then `TrimEnd('=')` trims nothing because the span ends in two `'\0'`. Tokens are 22 chars + `==` + two NULs. Both ends echo bytes verbatim, so it works. If anyone adds `[SkipLocalsInit]` (a common perf tweak) the NULs become stack garbage and every refresh and delete fails with `TokB`. Also, token comparison is `==` rather than constant-time. Generate 22-char base64url, compare with `CryptographicOperations.FixedTimeEquals`. [confirm] whether the csproj sets `SkipLocalsInit`.

**C-08 [read] Code-directory replies are accepted from any source.**
`CodeDirectory.SendExpectAsync` takes the first matching reply from any sender on an ephemeral port with no request id. An off-path attacker spraying UDP during the 2 s window can inject `OKCC <forged invitation>` and make the joiner dial the attacker. The documented defence is the out-of-band confirmation code (C-09), which is currently unusable. Validate the source against configured servers and echo a 64-bit request id.

**C-09 [read] `ConfirmationCode` compares different things.**
It fingerprints the entire connection string at host construction. `FullInvitation` returns the live string. Candidates change on STUN refresh or roam, so host and joiner fingerprints diverge. The joiner API (`JoinAsync`) returns only a connection and exposes no comparable value. Fingerprint `H(domain || PeerId || StaticKey || EndpointKey)` and expose it on the joined connection.

**C-10 [read] Host registration cannot self-heal.**
`KeepaliveAsync` ignores the result of `RefreshAsync`. After a directory restart, eviction or TTL lapse, every `PUTC code record token` gets `TokB` forever and the host stays unlisted. Make registration a reconcile loop: desired = "code maps to my string"; on a distinct `NOCODE` reply, claim again.

**C-11 [read] Responder spends DH and discloses candidates before any proof.**
`OnPunc` runs three X25519 operations and HKDF for any well-formed crypto PUNC from any source, answers with PACK, then `AnnounceTo(c, target: arrival)` sends a sealed announce to the unverified source address.
- Reflection: a 77-byte PUNC from a spoofed source yields a 97-byte PACK plus an announce. Roughly 10-20x amplification for a typical candidate set, and the codec permits several KB. [confirm] by measuring frame sizes in the sim.
- Disclosure: the announce carries relay candidates including TURN `Username` and `Credential` (`CandidateCodec.Write`). A LAN neighbor learns the port from mDNS and harvests them with no ticket. Connection strings carry them by design, but the announce removes even the need to hold the string.
Fix: R5 (`mac1`/cookie), plus withholding credentials until HSCK-confirmed, plus a 3x-before-validation size rule.

**C-12 [read] Raw `PeerSocket` accepts signalling from anyone.**
`RecvLoop` routes any datagram with first byte `>= 0x20` to `OnSignal`, which accepts `OBS` and `INTRO` lines without checking the sender is a configured rendezvous. An off-path host can set `PublicAddress` or make the socket punch at an arbitrary address for 10 s. Delete the layer (O-01) or source-check.

**C-13 [read] Key hygiene.**
- One Ed25519 endpoint key signs address-record bodies (raw), iroh pkarr packets and relay challenge digests with no domain separation. Prefix a label per use.
- `PeerId` in a v3 connection string is not checked against `H(EndpointKey)[..8]`; only the iroh relay path enforces it. Validate at parse.
- `StreamId` is the first 8 bytes of the root. A directory author can craft two files with colliding ids in ~2^32 hashes and make the provider serve the wrong entry for one of them (denial of that tree). Use the manifest index or the full root.

**C-14 [read] MoQ client.**
- **C-14a** `ReadDataAsync` handles inbound streams sequentially, and wraps each stream's whole lifetime in a 15 s deadline. A subgroup stream open longer than 15 s throws, which `Fail`s the entire session. A slow stream blocks all other tracks (head-of-line blocking that QUIC was designed to avoid).
- **C-14b** `Subscription.Enqueue` uses `TryWrite` on a bounded channel; a full queue (16 objects) throws `MoqProtocolException` and kills every track.
- **C-14c** `CheckPeerRequest` rejects relay request ids `>= 256` and the client never sends `MAX_REQUEST_ID`. A session survives at most 128 relay-originated requests, then dies.
- **C-14d [confirm]** `SendObjectAsync` awaits `WritesClosed` per object and `PublishAsync` serializes publishes, likely bounding a publisher to one object per RTT. Measure against a 100 ms path.

**C-15 [read] Minor.**
`BlobTicket.ToString` truncates `Name` at 255 bytes mid-UTF-8; `Parse` ignores unknown flag bits, so one ticket has several valid encodings. Reject unknown bits and truncate on a code-point boundary.

### 4.2 Availability and resource safety

**A-01 [read, confirm] Stranger husks are never reaped, so the cap becomes a lockout.**
`CreateIncoming` inserts a `ConnState` for any well-formed PUNC. For crypto strangers it is not queued, and no `PunchLoop` runs (only dials, announces and relay events call `KickPunch`). Nothing in the dump removes a `Punching` husk. After `MaxConnections` (1024) junk peer ids the node drops every new inbound stranger, including legitimate peers, until restart. The cap protects memory and then denies service.
Test: with `MaxConnectionsOverride = 8`, send 8 PUNCs with random ids, wait past `ConnectTimeout`, then dial in with a real peer. Fix: idle reaper in the maintenance tick plus a handshake ledger (A7) per source and global.

**A-02 [read] Blob provider has no auth deadline and no request budget.**
`ServeConnectionAsync` waits on `ReceiveAsync` indefinitely. Any peer that completes the (unauthenticated-dialer) Pinhole handshake holds a task and file handles forever. `Req` frames have no rate limit; each can trigger 64 reads. Close if no valid sealed frame within N seconds; add a per-connection ledger.

**A-03 [read] Accept loop dies on the first unexpected exception.**
`BlobServer.AcceptLoopAsync` catches only `OperationCanceledException` and `ObjectDisposedException`. `PinholeNode.AcceptAsync` can throw `TimeoutException` or `InvalidOperationException` (faulted handshake). The loop faults, the provider silently stops accepting, and `DisposeAsync` rethrows from `await _acceptLoop`.

**A-04 [read] `BlobServer` construction race.**
The constructor starts `AcceptLoopAsync` before `_kind`, `_root`, `_name`, `_psk` (object initializer) and `_streams` (later statements) are set. A dial in that window sees null fields or a dictionary being written. Build an immutable catalog first, start the loop in a separate `Start()`.

**A-05 [read]** `ChunksServed++` and `ConnectionsAccepted++` run from concurrent tasks without `Interlocked`.

**A-06 [read] TURN client leak.**
`TurnClient.CloseSocket` (called after three failed refreshes) never cancels `_shutdown`, so `RefreshLoop` keeps ticking on a closed socket. `AllocateSlotAsync` then overwrites `slot.Client` without disposing the retired client. One leaked loop and one `Received` subscription per allocation loss.

**A-07 [read] Rendezvous server.**
- `ReceiveLoop` exits on any exception other than `SocketException`/`ObjectDisposedException`. Concrete triggers: the `foreach` over a `_wants` list in `REG` racing the sweeper's `RemoveAll`; `_nodes[id]` after `EvictOldestNode` on equal timestamps. The introducer stops for everyone.
- Amplification: `GETC` returns up to 8 KiB for a ~20-byte request from a spoofable source; each `REG` can fan out up to 64 `INTRO` pairs.
- Eviction-by-age lets a flood of `PUTC`/`REG` evict real entries.
Fix: per-datagram catch-all with a counter; address validation (cookie) before replies larger than the request; per-source ledger; evict unrefreshed entries first.

**A-08 [read] Bind blocks on DNS.**
`PinholeOptions.ResolveAsync` resolves the STUN catalog (5 lookups, no timeout) before `BindProbeBudget` starts. A dead resolver stalls `PinholeNode.BindAsync` for the OS resolver timeout. `Resolver.TryResolve` swallows `OperationCanceledException`, contradicting the comment "cancellation halts the bind". Bound resolution by the same budget and return what resolved in time.

**A-09 [read] Candidate rebuild on every snapshot.**
When interface candidates are enabled (default), `LocalCandidatesSnapshot()` calls `RefreshLocalCandidatesNoLock()` on every call, which runs `NetworkInterface.GetAllNetworkInterfaces()` while holding the engine's global `_gate`. Callers include `AnnounceTo` (from `OnPunc` on the receive thread), `ConnectionString`, `BuildSignedRecord`, and LAN address polling every 2 s. Publish an immutable `CandidateSet` atomically on change events instead (a memoized pure function of its inputs). [confirm] with a benchmark of snapshot cost.

**A-10 [read] Checkpoint storm.**
`StreamDownloader` calls `_sink.Checkpoint()` every 50 ms with no dirty check. `FileSink.Checkpoint` performs two fsyncs and a rename each time, even when `Applied` has not moved, including while stalled.

**A-11 [read] Pacer credit leak.**
`BlobController.TryStartRun` deducts pacer credit before `_budget.TryReserve`. If the shared budget refuses, the credit is gone and nothing was sent. Under contention on the 8 MiB shared pie, the pacer starves itself. Reserve first, or refund.

**A-12 [read] Serve-side TOCTOU.**
`BuildOneAsync` hashes the file, then sets `TotalBytes = fs.Length` (not `tree.TotalBytes`), and serves later by re-reading. A file that changes between hash and serve produces chunks that fail the receiver's check with no diagnostic on the provider. Snapshot length and mtime; verify before serving; fail fast.

**A-13 [read]** mDNS: record TTL equals the heartbeat (120 s), so neighbor caches expire exactly when the refresh is due; replies are unicast to the querier's port regardless of the source port rule.

### 4.3 Determinism

**D-01 [read] Wall clock and RNG are ambient.**
`Environment.TickCount64` appears in `NodeEngine`, `BlobClient`, `BlobController.AffordableChunks`, `PortMappingService`, `LanDiscovery`, `TcpTransport`; `DateTimeOffset.UtcNow` in `TurnClient`, `IrohDiscovery`, `RendezvousServer`; `Task.Delay` is the pacing primitive almost everywhere. `RecoveryBudget` accepts a clock parameter that nothing supplies. `AGENTS.md` documents the consequence (`PcpClientTests.Mapping_Retries...`, `CryptoTests.WireOracle_LatePunch...` flake on first pass).

**D-02 [read]** `BlobController` has two clocks: `TryStartRun(bytes, nowMs)` takes one, `AffordableChunks` reads another.

**D-03 [read]** C-04 (culture) and C-05 (endianness) are determinism bugs in content addressing.

**D-04 [read] Test seams live in the production surface.**
`PinholeOptions` carries `UdpSocketFactory`, `MaxConnectionsOverride`, `StunCatalog`, `RelayCatalog`, `GatewayOverride`, `SsdpUnicastOverride`, `LanChannelFactory`, websocket factories. `BlobServer` has `DropChunk`/`CorruptChunk`/`DuplicateChunk`. `BlobTestHooks` reads an env var plus an `AsyncLocal`. `ConnState` has `BlackholeDirect` and `DropAboveBytes`. Move them behind one explicit `Ports` record and decorators.

**D-05 [read]** Process-global state: `BlobFlowBudget.Shared`, `BlobWire.WelcomeNonceSeen`, `TraceEnabled` read from environment variables.

### 4.4 Hot-path cost (allocation ledger)

Counts are from reading the code; sizes assume 64-bit .NET (`uint[16]` = 88 B, `uint[8]` = 56 B). [confirm] with `BenchmarkDotNet` `MemoryDiagnoser` before and after.

| ID | Path | Cost per unit | Cause | Target |
|----|------|---------------|-------|--------|
| H-01 | `Blake3.Compress` | 10 allocations, ~850 B per compress; ~160 allocations and ~13.6 KB per 1 KiB chunk; ~14 GB garbage per GiB hashed | `new uint[16]` state, `block.ToArray()`, a new `uint[16]` per round x7, `state[..8]` | `stackalloc`/`Span<uint>`, in-place permutation, `Vector128` 4-way compress, zero allocation |
| H-02 | Download verify | each chunk hashed twice | `ReceiveChunk` computes `ChunkCv`, then `FileSink.Feed` -> `Tree.Update` computes it again; resume loop hashes the prefix a third time with `new byte[1024]` per chunk | feed the already-computed CV (`Tree.PushChunkCv`); with Bao, resume does not rehash |
| H-03 | `Blake3.Tree` retention | whole tree retained | `TreeEntry` L/R chains kept when `retainOutboard` (default for `new Tree()`), though only the top pair is read; plus `byte[32]` per chunk (56 B with header) | flat `byte[]` of 32 B per chunk (32 MB per GiB), no node objects |
| H-04 | Blob AEAD | ~10 allocations per frame each way | BouncyCastle `ChaCha20Poly1305` constructed per call, `AeadParameters`, `nonce.ToArray()`, `plaintext.ToArray()`, output buffers | BCL `ChaCha20Poly1305` where `IsSupported`; spans; one cipher per session. Note this is a second AEAD inside the already-sealed Pinhole session (see the design note after this table) |
| H-05 | Blob framing | ~4 allocations per frame | `BlobWire.Chunk` copies; `Frame.TryParse` allocates CV and data arrays | `ref struct` views over the datagram |
| H-06 | Provider and sink I/O | 2 syscalls per 1 KiB chunk, each way | `Seek` + `Read`/`Write` on a 1 KiB-buffered `FileStream`; `FileOptions.Asynchronous` with synchronous calls; `new byte[len]` per chunk | `RandomAccess.Read/Write` (pread/pwrite) of whole runs, slice into frames |
| H-07 | Download control loop | 200 wakeups/s per download, a `Task` + timer per idle wait; `SweepStale` scans all outstanding every 5 ms | `WaitToReadAsync().AsTask().WaitAsync(5 ms)`; `Dictionary<long, tuple>` | compute next deadline (oldest PTO, pacer, checkpoint, stall) and sleep to it; ring-buffer window with parallel arrays |
| H-08 | TURN relay path | ~6 arrays per sent packet; ~4 per received | `Message`/`Attr`/`Concat`/`XorAddress`; `buf[..n]` copy, `Attributes()` list of `ToArray()` | write in place into a pooled buffer; implement `ChannelBind`/`ChannelData` (4-byte header vs ~36 B Send Indication) |
| H-09 | Iroh/DERP relay path | 4-5 arrays per datagram; SHA-256 of the source key per iroh frame | `new byte[4096]` per `ReadAsync`, `ToArray()` copies, `body[..32]`/`body[32..]`, `HandleKeyedRelayData` hashing | pooled read buffer, spans, cache key-to-peer-id |
| H-10 | Engine send | one `lock (c.Gate)` and two `Interlocked` per datagram | `Send` reads `PmtuWire` under `Gate` | `volatile int PmtuWire`; per-connection counters single-writer |
| H-11 | Engine receive | `c.Gate` taken twice per datagram; one thread decrypts for all peers | `Dispatch` opens under `Gate`, then `DirectPathConfirmed` locks again; single `pinhole-node-recv` thread; no `recvmmsg`/GRO | state split so the established path is lock-free; batch I/O shell |
| H-12 | Punch loop | `PeerCandidates.ToArray()` under `_gate` every 200 ms per connection | per-iteration snapshot | copy-on-write immutable candidate array |
| H-13 | MoQ | `new byte[8]` per varint, `MemoryStream` + `OrderBy` + boxed tuples per control message, `new byte[]` per object | `MoqStreamWire`, `MoqWriter.Parameters` | spans and `stackalloc` on the data path; control plane may stay allocating |
| H-14 | Rendezvous | `GetString` + `Trim` + `Split` per datagram | string parsing | span parsing, fixed-capacity tables |

What is already good: the direct-UDP send path, `FrameSealer`, `StunBindingMessage`, `DatagramBuffer`'s drop-oldest bounded channel, `RecoveryBudget`'s single shared allowance, and the sealed-frame replay discipline (authenticate before committing window state).

Design note on blob encryption (decision needed): with `PinholeEncryption.Required` (default) every blob frame is sealed twice (ChaCha20-Poly1305 inside AES-GCM). The blob PSK still has value as a downloader capability. Options: (a) keep the PSK as a MAC-only gate bound to the session transcript hash; (b) seal only when `!conn.IsEncrypted`. Both remove a full AEAD pass per datagram.

### 4.5 Orthogonality and duplication

**O-01** `PeerSocket`/`PeerEngine` (~500 lines, unauthenticated, own STUN parser) is still needed only by `NatDetector.DetectAsync`. Reimplement it on `IUdpSocket` + `StunBindingMessage` and delete the layer. Fixes C-12 and removes a serialized-probe bottleneck (`StunGate`).

**O-02** Duplicated primitives:
- `ToWire` x5 (PeerEngine, NodeEngine, CodeDirectory, RendezvousLookup, and `SystemUdpSocket` mapping logic).
- `Clone(SocketAddress)` x2.
- STUN/TURN XOR-address codec x3 (`PeerEngine.TryDecodeAddress`, `StunBindingMessage.TryAddress`, `TurnClient.XorAddress/DecodeAddress`).
- Dual-mode UDP socket construction x4.
- `WriteU64` x2; endpoint codec x3 (`CandidateCodec`, `AddressRecord`, `PortPrediction`).
- Backoff-with-jitter x3 (`IrohRelay.RetryDelay`, `NodeEngine.Jitter`, the two publish loops).
- STUN server catalog x3 (`StunServers`, `Resolver.FreeStunAsync`, `PinholeOptions`) and TURN catalog x2.

**O-03** Legacy branches: blob protocol v1/v2 Hello parsing and `LegacyDetector`; plaintext PUNC/PACK (`Encryption.Optional/Disabled`). Pick a support window and delete; each is attack surface.

**O-04** Two BLAKE3s (BouncyCastle `Blake3Digest` for relay auth, own `Blake3` for blobs) and two AEAD/HKDF stacks (BouncyCastle and BCL). One of each. BouncyCastle stays for X25519, Ed25519 and TLS only.

**O-05** `NodeEngine` (~2,500 lines) and `ConnState` (~80 mutable fields annotated "guarded by Gate") encode a locking discipline in comments. Split by component (section 5), driven by the machine contract (axiom A3).

**O-06** Mutable and heap-heavy models in hot types: `IPEndPoint` inside records (its `Address` is settable; `ToEndpoint` mutates it), `PinholeCandidate` as a class record, LINQ in `CandidateSelection`. Use `readonly struct Endpoint` and fixed-capacity candidate sets.

**O-07** Failure classification by exception type: `BlobClient.IsTransportLoss` treats every `InvalidOperationException` after dialing as transport loss. Replace with a closed outcome set: `Lost`, `Refused`, `Tampered`, `Cancelled`, `Exhausted`.

### 4.6 Documentation that does not match the code

- "verifies every chunk as it lands" / "corrupt chunk aborts immediately" (C-02).
- "Cancellation during resolution propagates before any engine resource exists" (A-08).
- "`TryParse` ... false on any malformed input" (C-06).
- "Hosts and joiners display it and compare" (C-09; joiners cannot obtain it).
- "a hostile scan cannot exhaust memory" is true, but the same bound permanently blocks inbound strangers (A-01).
- `BlobProgress.VerifiedBytes` means self-consistent, not authentic (C-02).

---

## 5. Target architecture

```
Pinhole.Wire        total codecs, LE spans, varints, endpoint, canonical forms         (no deps)
Pinhole.Crypto      Blake3 (map/reduce), Aead, Hkdf, X25519/Ed25519 adapters, Replay    (Wire)
Pinhole.Core        machines: Handshake, Path, Punch, Pmtu, Keepalive, Pacer, BaoVerify  (Wire, Crypto)
                    state = unmanaged structs; Step(ref State, in Input, Tick, Span<Effect>)
                    netstandard2.1, no Task, no LINQ, no exceptions on the hot path, no statics
Pinhole.Sim         SimClock, SimNet (NAT, loss, reorder, dup), seeds, effect-log hashing (Core)
Pinhole.Net         shells: UDP, TCP, TURN, iroh/DERP, files, DNS, HTTP; interpreters of Effect   (Core)
Pinhole.Blobs       provider/downloader shells over BaoVerify + Pacer ledger                     (Core, Net)
Pinhole.Moq         MoQ shell                                                                    (Wire, Net)
Pinhole.Unity.*     ECS components/systems/jobs; Unity Transport INetworkInterface             (Core)
Pinhole.Native      NativeAOT C ABI: pinhole_step, pinhole_poll                                  (Core)
```

Dependency rule: `Core` and below know nothing about `Net`. A reference that points up fails the build.

Per-connection state split (replaces `ConnState`):

| Component | Contents | Written by |
|-----------|----------|------------|
| `Identity` | peer id, pinned static/endpoint key refs | dial/accept |
| `Handshake` | tokens, ephemeral/static keys, confirm flags, reject counters | Handshake machine |
| `Keys` | epoch, send/recv key material (fixed bytes), nonce salts | Handshake machine |
| `Replay` | `ReplayWindow` | Open |
| `PathState` | state, kind, remote endpoint, since, last-rx tick | Path machine |
| `Probe` | outstanding nonce, deadline, unanswered count | Path machine |
| `Pmtu` | confirmed wire, probe size, tries, next tick | Pmtu machine |
| `Counters` | sent, received, bytes, pings | Open/Seal |

---

## 6. Phased roadmap

Phases are ordered by risk and unblock chain; R0 and R1 can run in parallel with everything.

### R0: Ship-now fixes (M, no redesign)

Each item is local and gets a regression test written first.

| Item | Change | Test |
|------|--------|------|
| C-01 | completion keyed by path; copy for repeated roots | tree with 3 identical files, plus empty files |
| C-04 | ordinal manifest order | same tree under `tr-TR` and invariant culture yields the same root |
| C-05 | `BinaryPrimitives` everywhere; analyzer bans `BitConverter` | golden bytes for ticket, manifest, record, PUNC |
| C-06 | total `TryParseVerified`, `TryParse(null)`, strict-UTF-8 handling | hostile expiry `long.MaxValue`, invalid UTF-8 TXT, null ticket |
| C-07 | 22-char base64url token; `FixedTimeEquals` | token charset and length; works under `SkipLocalsInit` |
| C-08/C-10 | source check, request id, `NOCODE`, reconcile loop | forged reply from wrong source ignored; directory restart re-registers |
| C-09 | key-only fingerprint; `RemoteConfirmationCode` | host and joiner values equal across a roam |
| A-01 | reaper for unestablished husks | the lockout test above |
| A-03/A-04/A-05 | supervised accept loop; immutable catalog before `Start()`; `Interlocked` | accept after injected `TimeoutException`; dial during construction |
| A-06 | `CloseSocket` cancels `_shutdown`; dispose retired client | refresh loop stops after 3 failures |
| A-07 | per-datagram catch-all; address validation for large replies | sweeper/REG race injected; GETC reply size vs request |
| A-08 | bounded DNS; cancellation propagates | black-holed resolver: bind within budget; cancelled token cancels |
| A-10/A-11/A-12 | dirty-checked checkpoint; reserve-then-deduct; snapshot size/mtime | fsync count while stalled; credit conserved under refused reserve |
| C-14a/b/c | per-stream tasks with idle (not total) deadline; per-track backpressure; send `MAX_REQUEST_ID` as consumed | 20 s subgroup stream; slow subscriber leaves other tracks alive; 200 relay requests |

Gate: full suite green; no new public API; `AGENTS.md` flake list shrinks or is unchanged.

### R1: Primitives (M-L)

- `Pinhole.Wire`: canonical codecs for every wire type, each with `TryRead`/`Write`, property tests for round trip and canonical rejection, fuzz harness per codec.
- `Blake3`: zero-allocation scalar compress, `Vector128` 4-way chunk hashing, `HashChunks(ReadOnlySpan<byte>, Span<uint>)` and `Reduce(Span<uint>)` as separate pure steps (parallelizable), no retained tree.
- `Aead`: span wrappers over BCL `AesGcm`/`ChaCha20Poly1305`.
- `ReplayWindow` struct (appendix), `Ledger` struct, `Tick`.

Gates: official BLAKE3 test vectors (lengths 0 to >100 KiB) plus differential against `Blake3Digest`; 0 allocations per op; at least 10x current throughput on a 1 GiB buffer (re-measure the baseline first); Wycheproof vectors for AEAD.

### R2: Verified runs (Bao-style) (L)

Design that reuses what is already on the wire:

- A **run** is an aligned subtree of 2^k chunks, k = 6 (64 chunks = `MaxRequestCount`). Any aligned range `[a*2^j, min((a+1)*2^j, n))` is a node of the BLAKE3 tree, including the ragged tail.
- Chunk frames already carry the leaf CV. Add a `Proof` frame: sibling CVs from the run's root up to the nearest *verified* cached node (or the root). Receiver stages the run's 64 KiB in memory, folds the 64 leaf CVs into the run CV, folds with the siblings, compares to the verified ancestor/root, and only then `pwrite`s. Corruption in a chunk is caught per chunk by its CV; a lying CV is caught at run completion.
- Receiver caches verified nodes; sequential runs need ~2 siblings amortized. First proof for 1 TiB is ~24 siblings (768 B).
- Unverified bytes in memory are bounded by the congestion window (1 MiB cap = 16 runs). Disk only ever holds verified data.
- Ticket (or authenticated `Head`) carries size. Manifest has a hard cap. Unsolicited chunk indices are dropped.
- Resume persists the applied-run bitmap and verified-node cache; no prefix rehash. Optional `--paranoid` full re-hash.
- Hash once: verified CVs feed the tree; no second pass.
- Protocol v4 with version negotiation; then delete v1/v2/v3 paths (O-03).

Gates: forged chunk rejected before any disk write; hostile `Head` bounded; resume cost O(1); property "any adversary output yields exact content or typed failure, never a partial publish"; vectors cross-checked against a reference Bao implementation when online.

### R3: Sans-IO core and simulation (L)

- Extract machines in this order (each shippable alone): `Pacer`/`BlobController` (already nearly pure) -> `Replay` -> `PmtuProber` -> `Keepalive` -> `PathSelector` -> `Handshake` -> `PunchScheduler`.
- Introduce `Tick` and `IRandom` as inputs; `Ports` record for I/O; move the D-04 seams there.
- `Effect` = `Transmit | Deliver | Arm | Notify | Close`; interpreters live in `Pinhole.Net`.
- Elevate the topology lab into `Pinhole.Sim`. Record the effect log; hash it.

Properties as CI gates:
- P1 No application datagram is delivered twice or without a valid seal.
- P2 With a path that is eventually good, state reaches `Open` (or `Degraded` on relay) within a bounded number of ticks; after loss, within T.
- P3 Ledger conservation: reserved equals outstanding at every step; zero at quiescence.
- P4 Same seed gives identical effect-log hash.
- P5 Blob resume is idempotent: `Resume(Resume(x)) = Resume(x)`.

Gates: existing tests pass unchanged against the shell; no wall-clock sleeps in unit tests; a 1,000-seed sweep completes in under a minute; flake rate 0.

### R4: ECS and Burst (L)

Components/systems from section 5, plus:

| System | Does | Parallel |
|--------|------|----------|
| `ReceiveSystem` | drain transport into per-session `InDatagram` buffers | single (I/O boundary) |
| `OpenSystem` | AEAD open + `Replay` in `IJobEntity` | per session |
| `PathSystem` | `PathState`/`Probe` steps | per session |
| `AppSystem` | user code reads `DynamicBuffer<Delivered>` | user |
| `SealSystem` | seal outgoing | per session |
| `TransmitSystem` | hand `OutDatagram` to the shell | single (I/O boundary) |

Constraints: `Pinhole.Core` as a `netstandard2.1` assembly definition; unmanaged components only (`FixedBytes32` for keys); no managed fallback in the Burst inspector; no exceptions on hot paths (result codes); no `static` mutable (use `SharedStatic` if unavoidable).

Open question [confirm]: which scripting runtime your Unity version ships. If it is Mono/IL2CPP on `netstandard2.1`, `AesGcm`, `ChaCha20Poly1305` and `System.Net.Quic` are not available there. The core then needs BouncyCastle for AEAD (it has a `netstandard2.0` build) and Burst-friendly intrinsics for ChaCha20. Decide this before R4 starts.

Gates: 0 GC allocation per frame in the Editor profiler under 1,000 sessions; Burst compiles with no managed references; deterministic replay (recorded inputs reproduce the identical effect hash); a throughput target set from the R1 benchmark baseline.

### R5: Handshake v4 and DoS armor (L, parallel to R3/R4)

- `mac1` keyed to the responder's static public key; silence on failure (no PACK, no announce, no state). `mac2` cookie under load, bound to the source address.
- Responder does no DH and creates no state until `mac1` verifies; stranger husks bounded by the ledger (A7) and reaped (A-01).
- Announce withheld until HSCK-confirmed; credentials never in an unauthenticated announce (C-11).
- Optional per-string secret ("knock") mixed in as a PSK, so a string holder is distinguishable from a scanner.
- ID/key binding (`PeerId = H(EndpointKey)[..8]` checked at parse), domain-separated signatures, v2 address records.
- Wire version negotiation; delete legacy plaintext handshake after the support window.
- Optional hybrid X25519 + ML-KEM key exchange (BCL exposes ML-KEM from .NET 10) as a feature flag.
- Rendezvous: address validation before large replies; 3x rule; per-source ledger.

Gates: 24 h fuzz clean on all codecs; sim of spoofed-source floods shows zero responder output and bounded CPU; no relay credential in any frame sent before HSCK.

### R6: Transport shells (M each, independent)

- Linux `recvmmsg`/`sendmmsg` shell with UDP GSO/GRO; per-core `SO_REUSEPORT` sockets; one decrypt thread per core.
- TURN `ChannelBind`/`ChannelData`.
- Unity Transport `INetworkInterface` provider (verify the interface shape against the installed package version).
- NativeAOT C ABI export of `Core`; header generation; sample in a non-.NET engine.
- Multipath redundancy mode: duplicate sealed frames on relay and direct while `Degraded`/migrating; receiver dedupes through `Replay`.
- Pluggable congestion control (`NewReno` baseline, `Cubic`/`BBR`-style behind one interface), validated in the sim for utilization and fairness.

### R7: Delete and document (S, continuous)

Execute section 9. Write `docs/AXIOMS.md` (A1-A8 and the machine catalog), `docs/WIRE.md` generated from the codecs, update `docs/BLOBS.md`. Analyzers: ban `BitConverter`, `Environment.TickCount64`, `DateTime(Offset).UtcNow`, `Task.Delay`, LINQ and `lock` in `Pinhole.Core`.

---

## 7. Verification strategy

| Layer | Method |
|-------|--------|
| Codecs | property tests (round trip, canonical rejection, totality), coverage-guided fuzzing on `Frame.TryParse`, `ConnectionString.Parse`, `BlobTicket.Parse`, `Manifest.Decode`, `DnsCodec`, `StunBindingMessage.TryRead`, `AddressRecord.TryParseVerified`, `IrohDiscovery.ParsePayload`, MoQ wire |
| Crypto | official BLAKE3 vectors; Wycheproof (AEAD, X25519, Ed25519); differential vs BouncyCastle; handshake transcript oracle (exists: `WireOracle`) |
| Machines | deterministic sim with seeds; shrinking of failing seeds; effect-log hash equality |
| Blobs | adversarial provider model: arbitrary bytes, truncation, duplication, reordering, wrong `Head`; assert exact content or typed failure |
| Interop | iroh tickets/pkarr vectors generated by the reference implementation; Bao vectors; STUN/TURN captured vectors; mDNS RFC 6763 examples |
| Perf | `BenchmarkDotNet` with `MemoryDiagnoser`; CI gates on allocations per op and ns per datagram; regression threshold 10% |
| Model checking (optional) | TLA+ or P for handshake + path state machine |

Environment facts from `AGENTS.md` still apply for physical-network trials: adb path, UFW port 53317, one-peer-per-host rule, kernel counters as ground truth. Simulation replaces *logic* flakes; it does not replace phone trials for NAT/firewall reality.

---

## 8. Success metrics

| Metric | Today (estimate, to be measured) | Target |
|--------|----------------------------------|--------|
| GC allocation per received blob chunk | ~300 objects, ~28 KB | 0 |
| BLAKE3 throughput | scalar + heavy allocation | >= 10x, parallel map/reduce |
| Hashing passes per downloaded byte | 2 (+1 on resume) | 1 |
| Disk written before verification | unbounded | 0 bytes (verified runs only) |
| Resume cost | O(prefix) rehash | O(1) |
| Wall-clock sleeps in unit tests | many | 0 |
| Flaky tests (first-pass) | 2 named in `AGENTS.md` | 0 |
| Responder output to unauthenticated source | PACK + announce | 0 |
| Lock acquisitions per established datagram | 3 | 0 |

---

## 9. Deletion ledger

Deleting each item must shrink the system, not break it:

1. `PeerSocket`, `PeerEngine` (after `NatDetector` moves to `IUdpSocket`).
2. Blob protocol v1/v2/v3 hello paths and `LegacyDetector` (after v4).
3. Plaintext handshake variants and `PinholeEncryption.Optional/Disabled` (after the support window).
4. BouncyCastle `Blake3Digest` use (relay auth moves to the own hash).
5. BouncyCastle AEAD/HKDF in blobs.
6. Duplicate `ToWire`, `Clone`, XOR-address codecs, socket factories, backoff helpers, server catalogs (O-02).
7. Test seams in production types (D-04), replaced by `Ports` and decorators.
8. `TreeEntry` tree retention in `Blake3.Tree`.
9. Per-chunk `Dictionary` outstanding table (replaced by a window ring).
10. `BlobTestHooks` env-var switch.

---

## 10. Risks and open questions

- **Unity runtime** (section R4): confirm the scripting runtime and available BCL surface before committing to `netstandard2.1`.
- **Bao interop vs simplicity:** verified runs keep today's frame shape and add one frame type, but are not byte-compatible with iroh-blobs' pre-order encoding. Decide whether wire interop with iroh-blobs is a goal; if yes, R2 grows by a chunk-group-16 mode.
- **Blob encryption layering:** removing the second AEAD changes the threat model for `Encrypt=false` tickets and plaintext sessions; decide explicitly (section 4.4 note).
- **Support window** for legacy peers (O-03) is a product decision, not a technical one.
- **Candidate credential model:** moving to coordinator-issued short-lived TURN credentials (as `WorkerCoordinator` already does) removes the long-lived-credential-in-string problem entirely; decide whether the free-credential presets stay.
- **Not examined:** tests, csproj/analyzers, `docs/`, `extern/`, the Android device-test harness, the Tiny sample, CI config. Findings tagged [confirm] depend on them.

---

## Appendix: sketches (illustrative, not compiled)

The window, as one reusable immutable value:

```csharp
public readonly struct ReplayWindow
{
    public readonly ulong Highest;
    public readonly ulong Bitmap;

    public ReplayWindow(ulong highest, ulong bitmap)
    {
        Highest = highest;
        Bitmap = bitmap;
    }

    public bool Admits(ulong counter) =>
        counter > Highest || (Highest - counter < 64 && ((Bitmap >> (int)(Highest - counter)) & 1UL) == 0);

    public ReplayWindow Mark(ulong counter) => counter > Highest
        ? new ReplayWindow(counter, (counter - Highest >= 64 ? 0UL : Bitmap << (int)(counter - Highest)) | 1UL)
        : new ReplayWindow(Highest, Bitmap | (1UL << (int)(Highest - counter)));
}
```

The machine contract:

```csharp
public readonly struct Tick
{
    public readonly long Milliseconds;
    public Tick(long milliseconds) { Milliseconds = milliseconds; }
}

public enum EffectKind : byte { Transmit, Deliver, Arm, Notify, Close }

public struct Effect
{
    public EffectKind Kind;
    public int Path;
    public int Offset;
    public int Length;
    public long Value;
}

public static class PathMachine
{
    public static int Step(ref PathState state, in PathInput input, Tick now, Span<Effect> effects);
}
```

Zero-allocation BLAKE3 compression core:

```csharp
public static void Compress(ReadOnlySpan<uint> cv, ReadOnlySpan<uint> block, ulong counter, uint blockLength, uint flags, Span<uint> output)
{
    Span<uint> s = stackalloc uint[16];
    Span<uint> m = stackalloc uint[16];
    Span<uint> t = stackalloc uint[16];
    cv[..8].CopyTo(s);
    s[8] = 0x6A09E667; s[9] = 0xBB67AE85; s[10] = 0x3C6EF372; s[11] = 0xA54FF53A;
    s[12] = (uint)counter; s[13] = (uint)(counter >> 32); s[14] = blockLength; s[15] = flags;
    block.CopyTo(m);
    for (int round = 0; round < 7; round++)
    {
        Round(s, m);
        if (round < 6)
        {
            Permute(m, t);
            t.CopyTo(m);
        }
    }
    for (int i = 0; i < 8; i++)
    {
        s[i] ^= s[i + 8];
        s[i + 8] ^= cv[i];
    }
    s.CopyTo(output);
}
```

Hashing as map then reduce:

```csharp
public static class Blake3Tree
{
    public static void HashChunks(ReadOnlySpan<byte> data, ulong firstChunkIndex, Span<uint> chunkCvs);
    public static void ReduceLevel(ReadOnlySpan<uint> children, Span<uint> parents);
    public static void Root(ReadOnlySpan<uint> topPair, Span<byte> digest);
}
```

Run verification, the only function that stands between the wire and the disk:

```csharp
public static bool VerifyRun(
    ReadOnlySpan<uint> leafCvs,
    ReadOnlySpan<uint> siblings,
    long runIndex,
    long totalChunks,
    ReadOnlySpan<uint> verifiedAncestor,
    int ancestorLevel);
```
