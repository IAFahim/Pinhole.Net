using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Pinhole.Blobs;

public sealed record BlobServeOptions
{
    public bool Encrypt { get; init; } = true;

    public PinholeOptions? NodeOptions { get; init; }
}

public sealed class BlobServer : IAsyncDisposable
{
    private readonly PinholeNode _node;
    private readonly Dictionary<ulong, Served> _streams = new();
    private readonly BlobServeOptions _options;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _acceptLoop;
    private readonly object _servingGate = new();
    private readonly HashSet<Task> _serving = new();

    private BlobServer(PinholeNode node, BlobServeOptions options, Served root, byte[]? psk)
    {
        // The full immutable catalog is in place before the accept loop can run (A-04):
        // the serving node is already bound when this constructor starts, so a dial that
        // lands in the first milliseconds must find _kind/_root/_name/_psk/_streams set.
        _node = node;
        _options = options;
        _kind = root.IsManifest ? BlobKind.Directory : BlobKind.File;
        _root = root.Root;
        _name = root.DisplayName;
        _psk = psk;
        _streams[BlobWire.StreamId(root.Root)] = root;
        foreach (Served entry in root.Entries)
        {
            _streams[BlobWire.StreamId(entry.Root)] = entry;
        }

        _acceptLoop = Task.Run(() => AcceptLoopAsync(_stop.Token));
    }

    public BlobTicket Ticket => new()
    {
        Kind = _kind,
        Root = _root,
        Name = _name,
        ConnectionString = _node.ConnectionString,
        PreSharedKey = _psk,
    };

    private readonly BlobKind _kind;
    private readonly byte[] _root;
    private readonly string _name;
    private readonly byte[]? _psk;

    private long _chunksServed;

    public long ChunksServed => Interlocked.Read(ref _chunksServed);

    internal PinholeNode Node => _node;

    internal int ActiveServingTasks
    {
        get { lock (_servingGate) return _serving.Count; }
    }

    private long _connectionsAccepted;

    public long ConnectionsAccepted => Interlocked.Read(ref _connectionsAccepted);

    internal Func<long, bool>? DropChunk { get; set; }

    internal Action<long, byte[]>? CorruptChunk { get; set; }

    internal Func<long, bool>? DuplicateChunk { get; set; }

    // v4 seams: proofs are honest unless a test says otherwise. DropProof suppresses
    // the frame (loss), CorruptProof hands the test the mutable sibling bytes, and
    // ReworkChunkCv lets a lying provider ship a self-consistent CV (the per-chunk
    // check passes; only the run's root proof can catch it) — returning null keeps
    // the honest outboard CV.
    internal Func<long, bool>? DropProof { get; set; }

    internal Action<ulong, long, byte[]>? CorruptProof { get; set; }

    internal Func<long, byte[], byte[]?>? ReworkChunkCv { get; set; }

    // Reorder the wire: send a covered run's proof before its chunks instead of after.
    internal bool DeliverProofsBeforeChunks { get; set; }

    // Emulate a pre-v4 provider: answer v3 Hellos, close on version 4.
    internal bool LegacyV3Only { get; set; }

    public static async Task<BlobServer> ServeAsync(string path, BlobServeOptions? options = null, CancellationToken ct = default)
    {
        options ??= new BlobServeOptions();
        string absolute = Path.GetFullPath(path);
        var builder = new ServeBuilder(absolute);
        Served root;
        if (Directory.Exists(absolute))
        {
            root = await builder.BuildDirectoryAsync(ct).ConfigureAwait(false);
        }
        else if (File.Exists(absolute))
        {
            root = await builder.BuildFileAsync(ct).ConfigureAwait(false);
        }
        else
        {
            throw new FileNotFoundException("nothing to serve at that path", absolute);
        }

        var nodeOptions = (options.NodeOptions ?? new PinholeOptions()) with { };
        nodeOptions = ForceServingDefaults(nodeOptions);

        PinholeNode node = await PinholeNode.BindAsync(nodeOptions, ct).ConfigureAwait(false);
        try
        {
            byte[]? psk = options.Encrypt ? BlobWire.Cipher.FreshKey() : null;
            return new BlobServer(node, options, root, psk);
        }
        catch
        {
            await node.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static PinholeOptions ForceServingDefaults(PinholeOptions o) => o with
    {
        Listen = true,
        ReceiveBufferCapacity = Math.Max(o.ReceiveBufferCapacity, 4096),
    };

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            PinholeConnection conn;
            try
            {
                conn = await _node.AcceptAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (Exception ex) when (ex is TimeoutException or InvalidOperationException)
            {
                // One dialer whose handshake never completed (or faulted mid-handshake)
                // is that dialer's problem: the loop keeps serving everyone else instead
                // of silently stopping the provider (A-03). The pause keeps a repeatedly
                // faulting source from spinning the loop.
                try
                {
                    await Task.Delay(100, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                continue;
            }

            Interlocked.Increment(ref _connectionsAccepted);
            Task serving = Task.Run(() => ServeConnectionAsync(conn, ct), CancellationToken.None);
            lock (_servingGate)
            {
                _serving.Add(serving);
            }

            _ = serving.ContinueWith(completed =>
            {
                // Observe failures and retain only active workers, never a history of
                // ticket holders. Completion includes releasing the worker's files.
                _ = completed.Exception;
                lock (_servingGate)
                {
                    _serving.Remove(completed);
                }
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }

    private async Task ServeConnectionAsync(PinholeConnection conn, CancellationToken ct)
    {
        var sendCounter = new Counter();
        ulong recvCounter = 0;   // per connection: every downloader gets a fresh replay window
        ulong legacyRecv = 0;    // the refusal path's watermark — never serves, just refuses
        BlobWire.Cipher? cipher = null;
        byte[]? boundSession = null;
        byte[]? providerNonce = null; // generated once per accepted blob connection, retained for retries
        byte sessionVersion = 0;      // the Hello version this connection negotiated (3 or 4)
        BlobWire.Cipher.LegacyDetector? legacy = _psk is null ? null : BlobWire.Cipher.ForLegacy(_psk, _root);
        var files = new Dictionary<ulong, FileStream>();
        try
        {
            while (!ct.IsCancellationRequested
                && await conn.ReceiveAsync(ct).ConfigureAwait(false) is { } payload)
            {
                BlobWire.Frame f;
                if (_psk is null)
                {
                    // Plaintext serving: any Hello body is fine — there is no cipher to bind.
                    if (!BlobWire.Frame.TryParse(payload.Span, out f))
                    {
                        continue;
                    }
                }
                else
                {
                    // Hello and the nonce prefix of Welcome bootstrap the ticket cipher.
                    // They carry explicit versions; v1/v2 are refused without sealing anything.
                    // A v4 Hello binds the v4 HKDF info string and a version-4 Welcome;
                    // LegacyV3Only emulates a pre-v4 provider that closes on version 4.
                    if (BlobWire.Frame.TryParse(payload.Span, out f)
                        && f.Type == BlobWire.TypeHello)
                    {
                        bool versionOk = LegacyV3Only
                            ? f.Version == BlobWire.ProtocolVersion
                            : f.Version is (BlobWire.ProtocolVersion or BlobWire.CurrentVersion);
                        if (!versionOk)
                        {
                            await conn.CloseAsync().ConfigureAwait(false);
                            return;
                        }

                        if (boundSession is null)
                        {
                            boundSession = f.SessionId!;
                            providerNonce = BlobWire.Cipher.FreshSessionId();
                            sessionVersion = f.Version;
                            cipher = BlobWire.Cipher.For(_psk, _root, boundSession, providerNonce, sessionVersion);
                        }
                        else if (!boundSession.AsSpan().SequenceEqual(f.SessionId) || f.Version != sessionVersion)
                        {
                            continue; // a session or version swap mid-connection: confused or hostile, ignored
                        }
                    }
                    else if (cipher is not null
                        && cipher.TryOpen(fromProvider: false, payload.Span, ref recvCounter, out byte[] plain)
                        && BlobWire.Frame.TryParse(plain, out f))
                    {
                    }
                    else if (legacy is not null
                        && legacy.TryOpen(fromProvider: false, payload.Span, ref legacyRecv, out byte[] legacyPlain))
                    {
                        // A pre-2.0 downloader: it seals under the fixed per-ticket key,
                        // which re-used (key, nonce) pairs across connections. Refuse by
                        // hanging up — nothing is ever sealed under that key, not even a
                        // Bye (two refusals would reuse its nonce 1).
                        await conn.CloseAsync().ConfigureAwait(false);
                        return;
                    }
                    else
                    {
                        Telemetry.FrameRejected("blob", "undecryptable");
                        continue; // nothing decryptable: garbage costs one datagram
                    }
                }

                switch (f.Type)
                {
                    case BlobWire.TypeHello:
                        if (_streams.TryGetValue(f.Stream, out Served? served))
                        {
                            byte[] head = BlobWire.Head(f.Stream, served.TotalBytes, served.TotalChunks);
                            if (cipher is null)
                            {
                                await SendFrameAsync(conn, head).ConfigureAwait(false);
                            }
                            else
                            {
                                // Every retry keeps the same provider nonce but seals a
                                // new Head with a fresh counter, including directory streams.
                                // The Welcome (and the key under which it was sealed) carry
                                // the version the Hello negotiated.
                                byte[] sealedHead = cipher.Seal(asProvider: true, sendCounter.Next(), head);
                                await SendFrameAsync(conn, BlobWire.Welcome(f.Stream, boundSession!, providerNonce!, sealedHead,
                                    sessionVersion)).ConfigureAwait(false);
                            }
                        }

                        break;
                    case BlobWire.TypeReq:
                        if (_streams.TryGetValue(f.Stream, out Served? item))
                        {
                            await ServeRangeAsync(conn, cipher, sessionVersion == BlobWire.CurrentVersion, item,
                                f.StartChunk, f.Count, files, sendCounter).ConfigureAwait(false);
                        }

                        break;
                    case BlobWire.TypeBye:
                        if (files.Remove(f.Stream, out FileStream? closed))
                        {
                            await closed.DisposeAsync().ConfigureAwait(false);
                        }

                        break;
                }
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or InvalidOperationException or IOException)
        {
            // The downloader vanished mid-transfer, or the served source failed its
            // snapshot check (A-12): the next ticket holder starts clean either way.
        }
        finally
        {
            foreach (FileStream fs in files.Values)
            {
                await fs.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private ValueTask SendSealedAsync(PinholeConnection conn, BlobWire.Cipher? cipher, byte[] plain, Counter counter)
    {
        byte[] wire = cipher is null ? plain : cipher.Seal(asProvider: true, counter.Next(), plain);
        return SendFrameAsync(conn, wire);
    }

    private ValueTask SendFrameAsync(PinholeConnection conn, byte[] wire) =>
        BlobWire.SendRidingOutPathlessnessAsync(conn, wire, _stop.Token);

    // Any request that delivers a run's last chunk also delivers that run's proof —
    // whether it covered the whole run in one go or merely completed it piecewise (a
    // young pacer window splits runs across requests). Proofs are idempotent on the
    // receiver; retransmit requests that land on a run boundary carry one again. On a
    // v4 connection the receiver stages chunks and commits a run only once this proof
    // chains it to the ticket root.
    private async Task ServeRangeAsync(PinholeConnection conn, BlobWire.Cipher? cipher, bool v4, Served item, long start, int count,
        Dictionary<ulong, FileStream> files, Counter counter)
    {
        long end = Math.Min(start + count, item.TotalChunks);
        if (v4 && cipher is not null && item.TotalChunks >= 2 && DeliverProofsBeforeChunks)
        {
            await SendProofsForCompletedRunsAsync(conn, cipher, item, start, end, counter).ConfigureAwait(false);
        }

        for (long idx = start; idx < end; idx++)
        {
            if (DropChunk?.Invoke(idx) == true)
            {
                continue;
            }

            byte[] data = await item.ReadChunkAsync(idx, files, _stop.Token).ConfigureAwait(false);
            CorruptChunk?.Invoke(idx, data);
            byte[]? reworked = ReworkChunkCv?.Invoke(idx, data); // null keeps the honest outboard CV
            byte[] cv = reworked ?? item.Cvs[idx];
            byte[] frame = BlobWire.Chunk(BlobWire.StreamId(item.Root), idx, cv, data);
            await SendSealedAsync(conn, cipher, frame, counter).ConfigureAwait(false);
            if (DuplicateChunk?.Invoke(idx) == true)
            {
                await SendSealedAsync(conn, cipher, BlobWire.Chunk(BlobWire.StreamId(item.Root), idx, cv, data), counter).ConfigureAwait(false);
            }

            Interlocked.Increment(ref _chunksServed);
            if (v4 && cipher is not null && item.TotalChunks >= 2 && !DeliverProofsBeforeChunks
                && idx == RunLastChunk(item, idx / RunVerify.RunChunks))
            {
                await SendRunProofAsync(conn, cipher, item, idx / RunVerify.RunChunks, counter).ConfigureAwait(false);
            }
        }
    }

    private static long RunLastChunk(Served item, long run) =>
        Math.Min((run + 1) * RunVerify.RunChunks, item.TotalChunks) - 1;

    private async Task SendProofsForCompletedRunsAsync(PinholeConnection conn, BlobWire.Cipher cipher, Served item,
        long start, long end, Counter counter)
    {
        for (long run = start / RunVerify.RunChunks; run <= (end - 1) / RunVerify.RunChunks; run++)
        {
            if (start <= RunLastChunk(item, run) && RunLastChunk(item, run) < end)
            {
                await SendRunProofAsync(conn, cipher, item, run, counter).ConfigureAwait(false);
            }
        }
    }

    private async Task SendRunProofAsync(PinholeConnection conn, BlobWire.Cipher cipher, Served item, long runIndex, Counter counter)
    {
        if (DropProof?.Invoke(runIndex) == true)
        {
            return;
        }

        var scratch = new byte[RunVerify.MaxSiblings * RunVerify.CvSize];
        int count = item.RunProof(runIndex, scratch);
        if (count < 0)
        {
            return; // no proof exists for this run (single-chunk files have no folds)
        }

        byte[] siblings = scratch.AsSpan(0, count * RunVerify.CvSize).ToArray();
        CorruptProof?.Invoke(BlobWire.StreamId(item.Root), runIndex, siblings);
        await SendSealedAsync(conn, cipher, BlobWire.Proof(BlobWire.StreamId(item.Root), runIndex, siblings), counter)
            .ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        try
        {
            await _acceptLoop.ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
        {
        }

        await _node.DisposeAsync().ConfigureAwait(false);
        Task[] serving;
        lock (_servingGate)
        {
            serving = _serving.ToArray();
        }

        await Task.WhenAll(serving).ConfigureAwait(false);
    }

    private sealed class Counter
    {
        private ulong _value;
        public ulong Next() => ++_value;
    }

    // ---------------------------------------------------------------- served content

    private sealed class Served
    {
        public required byte[] Root { get; init; }
        public required byte[][] Cvs { get; init; }
        public required long TotalBytes { get; init; }
        public required long TotalChunks { get; init; }
        public required string DisplayName { get; init; }
        public string? FilePath { get; init; } // disk-backed blob
        public byte[]? InMemory { get; init; } // manifest blob
        public bool IsManifest => InMemory is not null;
        public List<Served> Entries { get; } = new();

        // A-12 snapshot: the exact on-disk state the tree was computed over. A file
        // that does not match it at serve time can never verify against the ticket's
        // root, so serving it would only produce receiver-side failures.
        public long SourceLength { get; init; } = -1;
        public DateTime SourceModifiedUtc { get; init; }

        private readonly object _runTreeGate = new();
        private RunTree? _runTree;

        // Lazy and per-file: a directory catalog builds this only when a v4 peer
        // actually asks for a proof, so plain v3 traffic never pays for it.
        public int RunProof(long runIndex, Span<byte> siblings)
        {
            RunTree? tree = _runTree;
            if (tree is null)
            {
                lock (_runTreeGate)
                {
                    tree = _runTree ??= new RunTree(Cvs, TotalChunks);
                }
            }

            return tree.Proof(runIndex, TotalChunks, siblings);
        }

        public async Task<byte[]> ReadChunkAsync(long idx, Dictionary<ulong, FileStream> files, CancellationToken ct)
        {
            int len = (int)Math.Min(Blake3.ChunkSize, TotalBytes - idx * Blake3.ChunkSize);
            if (InMemory is { } mem)
            {
                return mem.AsSpan((int)(idx * Blake3.ChunkSize), len).ToArray();
            }

            long currentLength;
            DateTime currentModified;
            try
            {
                var info = new FileInfo(FilePath!);
                currentLength = info.Length; // a vanished file throws: that fails fast too
                currentModified = info.LastWriteTimeUtc;
            }
            catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
            {
                Telemetry.FrameRejected("blob", "source-changed");
                throw new IOException($"{DisplayName} disappeared after it was hashed; the ticket's tree can no longer be served", ex);
            }

            if (currentLength != SourceLength || currentModified != SourceModifiedUtc)
            {
                Telemetry.FrameRejected("blob", "source-changed");
                throw new IOException(
                    $"{DisplayName} changed after it was hashed ({SourceLength} B -> {currentLength} B); refusing to serve chunks that cannot verify against the ticket's root");
            }

            ulong stream = BlobWire.StreamId(Root);
            if (!files.TryGetValue(stream, out FileStream? fs))
            {
                fs = new FileStream(FilePath!, FileMode.Open, FileAccess.Read, FileShare.Read, Blake3.ChunkSize,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                files[stream] = fs;
            }

            var chunk = new byte[len];
            fs.Seek(idx * Blake3.ChunkSize, SeekOrigin.Begin);
            await fs.ReadExactlyAsync(chunk, ct).ConfigureAwait(false);
            return chunk;
        }
    }

    private sealed class ServeBuilder(string root)
    {
        public async Task<Served> BuildFileAsync(CancellationToken ct) => await BuildOneAsync(root, Path.GetFileName(root), ct).ConfigureAwait(false);

        public async Task<Served> BuildDirectoryAsync(CancellationToken ct)
        {
            string name = Path.GetFileName(root.TrimEnd(Path.DirectorySeparatorChar));
            var entries = new List<(string Rel, Served Served)>();
            foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
            {
                string rel = Path.GetRelativePath(root, file).Replace('\\', '/');
                entries.Add((rel, await BuildOneAsync(file, Path.GetFileName(file), ct).ConfigureAwait(false)));
            }

            byte[] manifest = Manifest.Encode(name, entries.Select(e => new Manifest.Entry(e.Rel, e.Served.TotalBytes, e.Served.Root)).ToList());
            var dir = new Served
            {
                Root = Blake3.Hash(manifest),
                Cvs = ChunkCvs(manifest),
                TotalBytes = manifest.Length,
                TotalChunks = (manifest.Length + Blake3.ChunkSize - 1) / Blake3.ChunkSize,
                DisplayName = name,
                InMemory = manifest,
            };
            foreach ((_, Served s) in entries)
            {
                dir.Entries.Add(s);
            }

            return dir;
        }

        private static async Task<Served> BuildOneAsync(string path, string display, CancellationToken ct)
        {
            await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, Blake3.ChunkSize,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var tree = new Blake3.Tree();
            var buffer = new byte[64 * Blake3.ChunkSize];
            int read;
            while ((read = await fs.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
            {
                tree.Update(buffer.AsSpan(0, read));
            }

            // Fail fast when the file moved under the hash itself (POSIX does not
            // enforce FileShare.Read): the tree the ticket would advertise never existed.
            long length = fs.Length;
            if (tree.TotalBytes != length)
            {
                throw new IOException($"{display} changed while it was being hashed ({tree.TotalBytes} bytes hashed, {length} bytes on disk)");
            }

            DateTime modifiedUtc = File.GetLastWriteTimeUtc(path);
            byte[] rootHash = tree.RootHash();
            IReadOnlyList<byte[]> cvs = tree.ChunkCvs;
            return new Served
            {
                Root = rootHash,
                Cvs = cvs.ToArray(),
                TotalBytes = length,
                TotalChunks = (length + Blake3.ChunkSize - 1) / Blake3.ChunkSize, // 0 for the empty file
                DisplayName = display,
                FilePath = path,
                SourceLength = length,
                SourceModifiedUtc = modifiedUtc,
            };
        }

        private static byte[][] ChunkCvs(byte[] data)
        {
            var tree = new Blake3.Tree();
            tree.Update(data);
            return tree.ChunkCvs.ToArray();
        }
    }
}
