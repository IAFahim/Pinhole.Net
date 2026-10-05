using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Pinhole.Blobs;

/// <summary>Options for serving content. <see cref="NodeOptions"/> overrides the serving
/// node's configuration entirely (offline test setups pass infrastructure-empty options);
/// listen and receive buffering are forced on regardless, because a serving node that
/// cannot accept or that drops the handshake race is not a serving node.</summary>
public sealed record BlobServeOptions
{
    /// <summary>Wrap every blob frame in ChaCha20-Poly1305 with a ticket-borne key
    /// (default true). Public relays forward ciphertext only; integrity is double-covered
    /// by BLAKE3. Disable for trusted high-speed LANs.</summary>
    public bool Encrypt { get; init; } = true;

    /// <summary>Full <see cref="Pinhole.PinholeOptions"/> override for the dedicated
    /// serving node. Defaults (null) resolve the free STUN catalog and public relays.</summary>
    public PinholeOptions? NodeOptions { get; init; }
}

/// <summary>The sendme model, Pinhole edition: a temporary dedicated node that serves one
/// file or one directory tree to whoever presents the ticket, verified chunk by chunk,
/// until disposed. Dispose stops serving and releases the node; the ticket dies with it.</summary>
public sealed class BlobServer : IAsyncDisposable
{
    private readonly PinholeNode _node;
    private readonly Dictionary<ulong, Served> _streams = new();
    private readonly BlobServeOptions _options;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _acceptLoop;

    private BlobServer(PinholeNode node, BlobServeOptions options)
    {
        _node = node;
        _options = options;
        _acceptLoop = Task.Run(() => AcceptLoopAsync(_stop.Token));
    }

    /// <summary>Mints a fresh ticket each call — the embedded connection string reflects
    /// the node's current candidates, so a ticket grabbed after a roam is the one to share.</summary>
    public BlobTicket Ticket => new()
    {
        Kind = _kind,
        Root = _root,
        Name = _name,
        ConnectionString = _node.ConnectionString,
        PreSharedKey = _psk,
    };

    private BlobKind _kind = default!;
    private byte[] _root = default!;
    private string _name = default!;
    private byte[]? _psk;

    /// <summary>Total verified chunks sent across all connections — a live activity counter.</summary>
    public long ChunksServed { get; private set; }

    /// <summary>The serving node, exposed so lab tests can roam it mid-transfer.</summary>
    internal PinholeNode Node => _node;

    /// <summary>Total downloader connections accepted so far.</summary>
    public long ConnectionsAccepted { get; private set; }

    /// <summary>Deterministic loss seam for tests: called with each chunk index about to
    /// be sent; returning true silently drops that chunk (the client's re-request machinery
    /// must heal it).</summary>
    internal Func<long, bool>? DropChunk { get; set; }

    /// <summary>Deterministic corruption seam for tests: receives (index, bytes) right
    /// before send; mutating the bytes simulates a lying provider whose chunk no longer
    /// hashes to the CV it was advertised with.</summary>
    internal Action<long, byte[]>? CorruptChunk { get; set; }

    /// <summary>Hashes the file or directory tree at <paramref name="path"/> once, binds a
    /// dedicated serving node, and starts serving whoever presents the ticket — until this
    /// server is disposed. Throws <see cref="FileNotFoundException"/> when the path is
    /// neither a file nor a directory.</summary>
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
            var server = new BlobServer(node, options)
            {
                _kind = root.IsManifest ? BlobKind.Directory : BlobKind.File,
                _root = root.Root,
                _name = root.DisplayName,
                _psk = options.Encrypt ? BlobWire.Cipher.FreshKey() : null,
            };
            server._streams[BlobWire.StreamId(root.Root)] = root;
            foreach (Served entry in root.Entries)
            {
                server._streams[BlobWire.StreamId(entry.Root)] = entry;
            }

            return server;
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

            ConnectionsAccepted++;
            _ = Task.Run(() => ServeConnectionAsync(conn, ct), ct);
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
                    if (BlobWire.Frame.TryParse(payload.Span, out f)
                        && f.Type == BlobWire.TypeHello)
                    {
                        if (f.Version != BlobWire.ProtocolVersion)
                        {
                            await conn.CloseAsync().ConfigureAwait(false);
                            return;
                        }

                        if (boundSession is null)
                        {
                            boundSession = f.SessionId!;
                            providerNonce = BlobWire.Cipher.FreshSessionId();
                            cipher = BlobWire.Cipher.For(_psk, _root, boundSession, providerNonce);
                        }
                        else if (!boundSession.AsSpan().SequenceEqual(f.SessionId))
                        {
                            continue; // a session swap mid-connection: confused or hostile, ignored
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
                                conn.Send(head);
                            }
                            else
                            {
                                // Every retry keeps the same provider nonce but seals a
                                // new Head with a fresh counter, including directory streams.
                                byte[] sealedHead = cipher.Seal(asProvider: true, sendCounter.Next(), head);
                                conn.Send(BlobWire.Welcome(f.Stream, boundSession!, providerNonce!, sealedHead));
                            }
                        }

                        break;
                    case BlobWire.TypeReq:
                        if (_streams.TryGetValue(f.Stream, out Served? item))
                        {
                            await ServeRangeAsync(conn, cipher, item, f.StartChunk, f.Count, files, sendCounter).ConfigureAwait(false);
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
        catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or InvalidOperationException)
        {
            // The downloader vanished mid-transfer; the next ticket holder starts clean.
        }
        finally
        {
            foreach (FileStream fs in files.Values)
            {
                await fs.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private Task SendSealedAsync(PinholeConnection conn, BlobWire.Cipher? cipher, byte[] plain, Counter counter)
    {
        byte[] wire = cipher is null ? plain : cipher.Seal(asProvider: true, counter.Next(), plain);
        // Task.Run keeps the pump off the accept loop's thread; the ride-out keeps a roam
        // or relay outage on THIS side from killing the transfer permanently.
        return Task.Run(() => BlobWire.SendRidingOutPathlessness(conn, wire, _stop.Token), _stop.Token);
    }

    private async Task ServeRangeAsync(PinholeConnection conn, BlobWire.Cipher? cipher, Served item, long start, int count, Dictionary<ulong, FileStream> files, Counter counter)
    {
        long end = Math.Min(start + count, item.TotalChunks);
        for (long idx = start; idx < end; idx++)
        {
            if (DropChunk?.Invoke(idx) == true)
            {
                continue;
            }

            byte[] data = await item.ReadChunkAsync(idx, files, _stop.Token).ConfigureAwait(false);
            CorruptChunk?.Invoke(idx, data);
            await SendSealedAsync(conn, cipher, BlobWire.Chunk(BlobWire.StreamId(item.Root), idx, item.Cvs[idx], data), counter).ConfigureAwait(false);
            ChunksServed++;
        }
    }

    /// <summary>Stops serving and releases the node; in-flight downloaders see their
    /// streams end. The ticket dies with the server.</summary>
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
    }

    /// <summary>Mutable frame counter shared by a connection's send path.</summary>
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

        public async Task<byte[]> ReadChunkAsync(long idx, Dictionary<ulong, FileStream> files, CancellationToken ct)
        {
            int len = (int)Math.Min(Blake3.ChunkSize, TotalBytes - idx * Blake3.ChunkSize);
            if (InMemory is { } mem)
            {
                return mem.AsSpan((int)(idx * Blake3.ChunkSize), len).ToArray();
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
            foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories).Order())
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

            byte[] rootHash = tree.RootHash();
            IReadOnlyList<byte[]> cvs = tree.ChunkCvs;
            return new Served
            {
                Root = rootHash,
                Cvs = cvs.ToArray(),
                TotalBytes = fs.Length,
                TotalChunks = (fs.Length + Blake3.ChunkSize - 1) / Blake3.ChunkSize, // 0 for the empty file
                DisplayName = display,
                FilePath = path,
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
