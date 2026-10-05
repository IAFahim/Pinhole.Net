using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Threading.Channels;

namespace Pinhole.Blobs;

/// <summary>Live transfer progress: bytes whose chunks verified, the total pinned by the
/// ticket, and file counts for directory tickets.</summary>
public readonly record struct BlobProgress(long VerifiedBytes, long TotalBytes, int FilesDone, int FilesTotal);

/// <summary>Outcome of a finished download: where the verified content landed, how many
/// bytes verified, and whether an interrupted earlier attempt's checkpoint was reused.</summary>
public sealed record BlobDownloadResult(string Path, long Bytes, bool Resumed);

/// <summary>Options for a download. <see cref="NodeOptions"/> overrides the downloading
/// node's configuration entirely; listen is forced off — a downloader dials, it does not
/// accept.</summary>
public sealed record BlobDownloadOptions
{
    /// <summary>Full <see cref="Pinhole.PinholeOptions"/> override for the dedicated
    /// downloading node (offline tests pass infrastructure-empty options).</summary>
    public PinholeOptions? NodeOptions { get; init; }

    /// <summary>Ceiling for this download's congestion window (default 1 MiB). The window
    /// is a bound on outstanding requested-but-unverified chunk bytes — it starts small
    /// and grows only as chunks verify. Must be at least 8 KiB.</summary>
    public long MaxWindowBytes { get; init; } = 1024 * 1024;

    /// <summary>The aggregate in-flight budget this download joins. Null (the default)
    /// joins <see cref="BlobFlowBudget.Shared"/>, the process-wide 8 MiB pie; pass a
    /// private budget to isolate a download's wire footprint from everything else.</summary>
    public BlobFlowBudget? FlowBudget { get; init; }

    /// <summary>Optional accumulator filled live during the transfer: verified vs
    /// duplicate bytes, retransmits, loss events, RTT. Diagnostics and tests; null for
    /// everyday downloads.</summary>
    public BlobTransferStats? Stats { get; init; }
}

/// <summary>The receiving half of the ticket: dial the provider from the embedded
/// connection string, drive range requests, verify every chunk as it lands (a corrupt
/// chunk aborts immediately; a forged-but-consistent one cannot survive the final root
/// check), and resume from on-disk part state when present. No unverified byte is ever
/// written past the temporary part file. One node per download, disposed with it.</summary>
public static class BlobClient
{
    /// <exception cref="TimeoutException">connect or first contact timed out, or the
    /// transfer stalled with no verified progress.</exception>
    /// <exception cref="InvalidDataException">a chunk failed verification, the completed
    /// root does not match the ticket, or the provider cancelled the stream.</exception>
    public static async Task<BlobDownloadResult> DownloadAsync(
        BlobTicket ticket,
        string destinationDirectory,
        IProgress<BlobProgress>? progress = null,
        BlobDownloadOptions? options = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        ArgumentNullException.ThrowIfNull(destinationDirectory);
        Directory.CreateDirectory(destinationDirectory);

        PinholeOptions nodeOptions = (options?.NodeOptions ?? new PinholeOptions()) with
        {
            Listen = false,
            ReceiveBufferCapacity = 4096,
        };

        await using var node = await PinholeNode.BindAsync(nodeOptions, ct).ConfigureAwait(false);
        await using PinholeConnection conn = await node.ConnectAsync(ticket.ConnectionString, ct).ConfigureAwait(false);

        // Provider freshness is authenticated in Welcome. One session and replay watermark
        // cover every file on this connection; neither depends on the engine's routing tokens.
        var session = new BlobWire.DownloadSession(ticket.PreSharedKey, ticket.Root);

        if (ticket.Kind == BlobKind.File)
        {
            string fileName = string.IsNullOrWhiteSpace(ticket.Name) ? "pinhole-download" : ticket.Name;
            string target = SafeJoin(destinationDirectory, fileName);
            var sink = new FileSink(target, ticket.Root);
            var fileSend = new SendCounter();
            StreamDownloader? downloader = null;
            downloader = new StreamDownloader(conn, sink,
                v => progress?.Report(new BlobProgress(v, downloader!.TotalBytes, 0, 1)), fileSend, session, ticket.Root,
                options: options);
            long bytes;
            try
            {
                bytes = await downloader.RunAsync(ct).ConfigureAwait(false);
            }
            catch
            {
                sink.Abandon();
                throw;
            }

            return new BlobDownloadResult(target, bytes, sink.Resumed);
        }

        var send = new SendCounter();
        var manifestSink = new MemorySink();
        var manifestDownloader = new StreamDownloader(conn, manifestSink, _ => { }, send, session, ticket.Root,
            options: options);
        try
        {
            await manifestDownloader.RunAsync(ct).ConfigureAwait(false);
        }
        catch
        {
            manifestSink.Abandon();
            throw;
        }
        (string name, List<Manifest.Entry> entries) = Manifest.Decode(manifestSink.Data);
        string rootDir = SafeJoin(destinationDirectory, string.IsNullOrWhiteSpace(name) ? "pinhole-download" : name);
        long total = entries.Sum(e => e.Size);
        long verified = 0;
        bool anyResumed = false;
        for (int i = 0; i < entries.Count; i++)
        {
            var sink = new FileSink(SafeJoin(rootDir, entries[i].Path), entries[i].Root);
            StreamDownloader entryDownloader = new(conn, sink, _ => { }, send, session, entries[i].Root, entries[i].Root,
                options: options);
            long bytes;
            try
            {
                bytes = await entryDownloader.RunAsync(ct).ConfigureAwait(false);
            }
            catch
            {
                sink.Abandon();
                throw;
            }
            verified += bytes;
            anyResumed |= sink.Resumed;
            progress?.Report(new BlobProgress(verified, total, i + 1, entries.Count));
        }

        return new BlobDownloadResult(rootDir, verified, anyResumed);
    }

    /// <summary>One monotonic frame counter for the whole connection: every stream shares
    /// it so the provider's per-connection replay check never sees a regression when a
    /// directory download moves to its next file.</summary>
    private sealed class SendCounter
    {
        private ulong _value;
        public ulong Next() => ++_value;
    }

    // ---------------------------------------------------------------- stream downloader

    /// <summary>Receiver-driven ARQ over one blob stream, paced by the congestion
    /// controller: requests anchored at the lowest unapplied chunk (a hostile sender
    /// cannot make us buffer the far end of the file), per-chunk CV verification on
    /// arrival, RTT-derived re-requests, and a stall clock that only verified progress
    /// resets.</summary>
    private sealed class StreamDownloader
    {
        private static readonly TimeSpan ControlTick = TimeSpan.FromMilliseconds(5);
        private static readonly TimeSpan HelloPace = TimeSpan.FromMilliseconds(250);
        private static readonly TimeSpan CheckpointPace = TimeSpan.FromMilliseconds(50);
        private static readonly TimeSpan FirstHeadTimeout = TimeSpan.FromSeconds(20);
        private static readonly TimeSpan StallTimeout = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan BriefFlap = TimeSpan.FromMilliseconds(500);

        private readonly PinholeConnection _conn;
        private readonly Sink _sink;
        private readonly Action<long> _onVerified;
        private readonly BlobWire.DownloadSession _session;
        private readonly byte[] _expectedRoot;
        private readonly ulong _stream;
        private readonly BlobController _controller;
        private readonly Dictionary<long, (long SentAtMs, int Retransmits, int PendingRecoveries)> _outstanding = new();
        private readonly SendCounter _send;
        private long _maxRequested = -1;
        private long _helloSince = -1;
        private long _helloLastTicks;
        private long _lastCheckpointTicks;
        private IPEndPoint? _pathRemote;
        private long _pathlessSinceMs = -1;

        private long _totalBytes = -1;
        private long _totalChunks = -1;
        private long _verified;
        private long _lastVerifiedTicks;

        public long TotalBytes => _totalBytes < 0 ? 0 : _totalBytes;

        public StreamDownloader(PinholeConnection conn, Sink sink, Action<long> onVerified, SendCounter send,
            BlobWire.DownloadSession session, byte[] expectedRoot, byte[]? streamRoot = null,
            BlobDownloadOptions? options = null)
        {
            _conn = conn;
            _sink = sink;
            _onVerified = onVerified;
            _send = send;
            _session = session;
            _expectedRoot = expectedRoot;
            _stream = BlobWire.StreamId(streamRoot ?? expectedRoot);
            options ??= new BlobDownloadOptions();
            _controller = new BlobController(options.MaxWindowBytes, options.FlowBudget ?? BlobFlowBudget.Shared,
                options.Stats, BlobTestHooks.ForceFixedWindow);
        }

        public async Task<long> RunAsync(CancellationToken ct)
        {
            // The connection allows exactly one reader: a dedicated pump owns it for the
            // whole stream and forwards parseable frames; the control loop consumes the
            // channel with timeouts and may abandon channel waits freely. The pump gets its
            // own linked token so finishing (or failing) one stream releases the read slot
            // before the next stream's pump claims it — directory downloads run several
            // streams back-to-back over one connection.
            var frames = Channel.CreateUnbounded<BlobWire.Frame>(new UnboundedChannelOptions { SingleReader = true });
            using var pumpCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            Task pump = Task.Run(() => PumpAsync(frames.Writer, pumpCts.Token), CancellationToken.None);
            try
            {
                return await RunLoopAsync(frames.Reader, ct).ConfigureAwait(false);
            }
            finally
            {
                frames.Writer.TryComplete();
                pumpCts.Cancel();
                try
                {
                    await pump.ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or InvalidOperationException)
                {
                }
            }
        }

        private async Task PumpAsync(ChannelWriter<BlobWire.Frame> writer, CancellationToken ct)
        {
            while (true)
            {
                ReadOnlyMemory<byte>? payload;
                try
                {
                    payload = await _conn.ReceiveAsync(ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException)
                {
                    return;
                }

                if (payload is not { } mem)
                {
                    return; // connection closed; the control loop notices the quiet
                }

                if (!_session.TryOpen(mem.Span, _stream, out BlobWire.Frame f))
                {
                    continue; // garbage, tampered ciphertext, or another stream's frame
                }

                await writer.WriteAsync(f, ct).ConfigureAwait(false);
                if (f.Type == BlobWire.TypeBye)
                {
                    return;
                }
            }
        }

        private async Task<long> RunLoopAsync(ChannelReader<BlobWire.Frame> frames, CancellationToken ct)
        {
            _lastVerifiedTicks = Environment.TickCount64;
            try
            {
                while (true)
                {
                    ct.ThrowIfCancellationRequested();
                    if (_conn.State == PinholeConnectionState.Closed)
                    {
                        // Pathlessness is a wait; Closed is a verdict. The provider hung
                        // up or the engine retired the connection — nothing rides out.
                        throw new InvalidDataException("the connection went quiet before the transfer finished");
                    }

                    long now = Environment.TickCount64;
                    bool pathPresent = WatchPath(now);

                    if (_totalChunks < 0)
                    {
                        if (_helloSince < 0)
                        {
                            _helloSince = now;
                        }

                        if (now - _helloSince > (long)FirstHeadTimeout.TotalMilliseconds)
                        {
                            throw new TimeoutException("the provider did not answer the ticket");
                        }

                        // Retries reuse the same downloader nonce. Welcome carries the
                        // provider nonce and a Head authenticated with the resulting key.
                        if (pathPresent && now - _helloLastTicks >= (long)HelloPace.TotalMilliseconds)
                        {
                            _helloLastTicks = now;
                            BlobWire.SendRidingOutPathlessness(_conn, BlobWire.Hello(_stream, _session.SessionId), CancellationToken.None);
                        }
                    }
                    else
                    {
                        if (_sink.Applied >= _totalChunks)
                        {
                            break;
                        }

                        if (pathPresent)
                        {
                            TopUpRequests(now);
                            SweepStale(now);
                        }

                        // The checkpoint is idempotent and tiny; a 50 ms gate keeps the
                        // syscall rate sane, and the exit path below writes one final
                        // checkpoint so a cancelled attempt always leaves its prefix —
                        // resuming never depends on timer luck.
                        if (now - _lastCheckpointTicks >= (long)CheckpointPace.TotalMilliseconds)
                        {
                            _lastCheckpointTicks = now;
                            _sink.Checkpoint();
                        }
                    }

                    // Availability wait, not a consuming read: an abandoned WaitToReadAsync can
                    // steal a signal but never an item — TryRead below is the only consumer.
                    if (!frames.TryRead(out BlobWire.Frame f))
                    {
                        bool more;
                        try
                        {
                            more = await frames.WaitToReadAsync(ct).AsTask().WaitAsync(ControlTick, ct).ConfigureAwait(false);
                        }
                        catch (TimeoutException)
                        {
                            CheckStall(now);
                            continue;
                        }

                        if (!more || !frames.TryRead(out f))
                        {
                            throw new InvalidDataException("the connection went quiet before the transfer finished");
                        }
                    }

                    switch (f.Type)
                    {
                        case BlobWire.TypeHead:
                            if (_totalChunks < 0)
                            {
                                _totalBytes = f.TotalBytes;
                                _totalChunks = f.TotalChunks;
                                _sink.Init(_totalBytes, _totalChunks);
                            }

                            break;
                        case BlobWire.TypeChunk:
                            ReceiveChunk(f, now);
                            break;
                        case BlobWire.TypeBye:
                            throw new InvalidDataException("the provider cancelled this stream");
                    }

                    CheckStall(now);
                }
            }
            finally
            {
                // A stream that verified anything but is not finishing (cancelled,
                // stalled, connection lost) writes one last checkpoint — resume must
                // never depend on where the periodic timer happened to land.
                if (_totalChunks > 0 && _sink.Applied is > 0 and var applied && applied < _totalChunks)
                {
                    _sink.Checkpoint();
                }

                // Every reservation the budget still holds for this stream must come back:
                // a stalled or cancelled download must not leak its share of the
                // process-wide pie.
                foreach (long idx in _outstanding.Keys)
                {
                    long len = ChunkLength(idx);
                    _controller.ReleaseReservation(len);
                    for (int i = 0; i < _outstanding[idx].PendingRecoveries; i++)
                    {
                        _controller.OnRecoverySettled(len);
                    }
                }

                _outstanding.Clear();
            }

            byte[] root = _sink.Complete();
            if (!root.AsSpan().SequenceEqual(_expectedRoot))
            {
                throw new InvalidDataException("downloaded content failed the root check — the transfer is incomplete or was tampered with");
            }

            return _totalBytes;
        }

        /// <summary>Path watching: returns whether a usable path exists right now. A path
        /// change (endpoint moved — roam, relay failover) or a return from sustained
        /// pathlessness resets the controller conservatively and refreshes every
        /// outstanding request's timer, so the resume probes instead of flooding a fresh
        /// path with a stale window's worth of re-requests.</summary>
        private bool WatchPath(long now)
        {
            bool present = _conn.State is PinholeConnectionState.Open or PinholeConnectionState.Degraded;
            if (!present)
            {
                _pathlessSinceMs = _pathlessSinceMs < 0 ? now : _pathlessSinceMs;
                return false;
            }

            long pathlessFor = _pathlessSinceMs >= 0 ? now - _pathlessSinceMs : 0;
            _pathlessSinceMs = -1;
            Pinhole.PinholePath path = _conn.Path;
            // The endpoint itself, not the engine's "since" stamp: a seamless adoption
            // (the peer roamed while our state never left Open) moves the remote without
            // ever transitioning, and that is exactly the migration to detect.
            bool endpointChanged = path.Remote is { } remote && _pathRemote is { } known && !remote.Equals(known);
            if (_pathRemote is null)
            {
                _pathRemote = path.Remote; // first observation: nothing to reset
            }
            else if (endpointChanged || pathlessFor >= (long)BriefFlap.TotalMilliseconds)
            {
                _pathRemote = path.Remote;
                _controller.OnPathChanged();
                long[] refresh = [.. _outstanding.Keys];
                foreach (long idx in refresh)
                {
                    _outstanding[idx] = (now, _outstanding[idx].Retransmits, _outstanding[idx].PendingRecoveries);
                }
            }

            return true;
        }

        private void ReceiveChunk(BlobWire.Frame f, long now)
        {
            if (f.Index >= _totalChunks)
            {
                return;
            }

            int len = (int)Math.Min(Blake3.ChunkSize, _totalBytes - f.Index * Blake3.ChunkSize);
            if (f.ChunkData!.Length != len)
            {
                throw new InvalidDataException($"chunk {f.Index} has the wrong length");
            }

            // Immediate verification: the received bytes must hash to the sender's outboard
            // CV. The final root check still guards against a fully consistent forgery.
            if (!Blake3.ChunkCv(f.ChunkData, (ulong)f.Index, root: false).AsSpan().SequenceEqual(f.ChunkCv))
            {
                throw new InvalidDataException($"chunk {f.Index} failed verification");
            }

            bool hadReservation = _outstanding.Remove(f.Index, out (long SentAtMs, int Retransmits, int PendingRecoveries) entry);
            bool fresh = _sink.Apply(f.Index, f.ChunkData);
            if (hadReservation && entry.Retransmits == 0)
            {
                // Karn's rule: only a first-attempt arrival measures the path's RTT — a
                // retransmitted request's arrival time no longer bounds the original send.
                _controller.ObserveRtt(TimeSpan.FromMilliseconds(Math.Max(now - entry.SentAtMs, 1)));
            }

            for (int i = 0; hadReservation && i < entry.PendingRecoveries; i++)
            {
                _controller.OnRecoverySettled(len);
            }

            _controller.OnChunkArrived(len, hadReservation, fresh, now);
            if (fresh)
            {
                _verified += len;
                _lastVerifiedTicks = now;
                _onVerified(_verified);
            }
        }

        private long ChunkLength(long index) =>
            (long)Math.Min(Blake3.ChunkSize, _totalBytes - index * Blake3.ChunkSize);

        private void TopUpRequests(long now)
        {
            // The token-bucket pacer admits as many runs as its credit allows inside one
            // control tick — the pacer's rate, not the tick cadence, is the limit. Runs
            // size themselves to the credit actually available, so issuance tracks the
            // pacing rate smoothly instead of jumping in whole-run quanta.
            while (_maxRequested + 1 < _totalChunks)
            {
                long start = _maxRequested + 1;
                int desired = (int)Math.Min(_controller.MaxRunChunks, _totalChunks - start);
                int count = Math.Min(desired, _controller.AffordableChunks(desired));
                if (count < 1)
                {
                    return; // pacer credit exhausted; retry next tick
                }

                long bytes = 0;
                for (long idx = start; idx < start + count; idx++)
                {
                    bytes += ChunkLength(idx);
                }

                if (!_controller.TryStartRun(bytes, now))
                {
                    return; // window or the shared budget is full; retry next tick
                }

                for (long idx = start; idx < start + count; idx++)
                {
                    _outstanding[idx] = (now, 0, 0);
                }

                Send(BlobWire.Request(_stream, start, count));
                _maxRequested = start + count - 1;
            }
        }

        private void SweepStale(long now)
        {
            foreach ((long idx, (long sentAt, int retransmits, int pending)) in _outstanding)
            {
                if (now - sentAt < (long)_controller.PtoFor(retransmits).TotalMilliseconds)
                {
                    continue;
                }

                long bytes = ChunkLength(idx);
                if (!_controller.TryStartRecovery(bytes))
                {
                    continue; // the aggregate budget is full; retry next tick
                }

                _controller.OnRetransmit(now);
                _outstanding[idx] = (now, retransmits + 1, pending + 1);
                Send(BlobWire.Request(_stream, idx, 1));
            }
        }

        private void CheckStall(long now)
        {
            if (now - _lastVerifiedTicks > (long)StallTimeout.TotalMilliseconds)
            {
                throw new TimeoutException($"the download stalled: no chunk verified for {StallTimeout.TotalSeconds:0}s");
            }
        }

        private void Send(byte[] plain)
        {
            // A downloader-side roam flips the connection through Punching mid-transfer;
            // the ARQ's next frame waits out the transition rather than dying. No token:
            // disposal closes the connection, which the ride-out treats as terminal.
            BlobWire.SendRidingOutPathlessness(_conn, _session.Seal(_send.Next(), plain), CancellationToken.None);
        }
    }

    // ---------------------------------------------------------------- sinks

    private abstract class Sink
    {
        public long Applied { get; protected set; }
        public abstract void Init(long totalBytes, long totalChunks);
        public abstract bool Apply(long index, byte[] data);
        public abstract byte[] Complete();
        public virtual void Checkpoint() { }
        public virtual void Abandon() { }
    }

    /// <summary>Writes chunks to `<c>target.pinhole-part/data</c> in any arrival order,
    /// feeds the hashing tree strictly in order from a bounded reorder buffer, and
    /// checkpoints the applied-prefix length — an interrupted download resumes exactly at
    /// that prefix. Completion: truncate to the exact size, final root, promote to the
    /// real path, remove every trace of the part directory.</summary>
    private sealed class FileSink(string target, byte[] root) : Sink
    {
        private const string Magic = "PBPART01";
        private static readonly byte[] MagicBytes = System.Text.Encoding.ASCII.GetBytes(Magic);
        private const long ReorderWindow = 512;

        private readonly string _partDir = target + ".pinhole-part";
        private readonly Dictionary<long, byte[]> _reorder = new();
        private FileStream _data = null!;
        private Blake3.Tree _tree = new();
        private bool[] _have = Array.Empty<bool>();
        private long _totalBytes;
        private long _totalChunks;

        public bool Resumed { get; private set; }

        public override void Init(long totalBytes, long totalChunks)
        {
            _totalBytes = totalBytes;
            _totalChunks = totalChunks;
            _have = new bool[totalChunks];
            Directory.CreateDirectory(_partDir);

            long prefix = TryLoadPrefix();
            Resumed = prefix > 0;
            _data = new FileStream(Path.Combine(_partDir, "data"), FileMode.OpenOrCreate, FileAccess.ReadWrite,
                FileShare.None, Blake3.ChunkSize, FileOptions.Asynchronous);

            for (long i = 0; i < prefix; i++)
            {
                var chunk = new byte[(int)Math.Min(Blake3.ChunkSize, _totalBytes - i * Blake3.ChunkSize)];
                _data.Seek(i * Blake3.ChunkSize, SeekOrigin.Begin);
                _data.ReadExactly(chunk);
                _tree.Update(chunk);
                _have[i] = true;
            }

            Applied = prefix;
        }

        public override bool Apply(long index, byte[] data)
        {
            if (index < Applied || _have[index])
            {
                return false; // duplicate below the applied prefix or already buffered
            }

            _data.Seek(index * Blake3.ChunkSize, SeekOrigin.Begin);
            _data.Write(data, 0, data.Length);

            if (index == Applied)
            {
                Feed(data);
                while (_reorder.Remove(Applied, out byte[]? buffered))
                {
                    Feed(buffered);
                }
            }
            else if (index < Applied + ReorderWindow)
            {
                _reorder[index] = data; // ahead of the cursor but inside the window
            }
            else
            {
                return false; // far ahead: dropped, the anchored window re-requests in order
            }

            _have[index] = true;
            return true;
        }

        private void Feed(byte[] data)
        {
            _tree.Update(data);
            Applied++;
        }

        public override byte[] Complete()
        {
            _data.SetLength(_totalBytes);
            _data.Flush(flushToDisk: true);
            _data.Dispose();
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(target))!);
            File.Move(Path.Combine(_partDir, "data"), target, overwrite: true);
            Directory.Delete(_partDir, recursive: true);
            return _totalBytes == 0 ? Blake3.Hash([]) : _tree.RootHash();
        }

        public override void Abandon()
        {
            // Cancelled mid-transfer: release the handle but keep the part directory —
            // the checkpointed prefix is exactly what the next attempt resumes from.
            _data?.Dispose();
        }

        public override void Checkpoint()
        {
            if (Applied == 0 || Applied >= _totalChunks)
            {
                return;
            }

            var state = new byte[8 + 32 + 16];
            System.Text.Encoding.ASCII.GetBytes(Magic).CopyTo(state, 0);
            root.CopyTo(state, 8);
            BinaryPrimitives.WriteInt64LittleEndian(state.AsSpan(8 + 32), _totalBytes);
            BinaryPrimitives.WriteInt64LittleEndian(state.AsSpan(8 + 32 + 8), Applied);
            File.WriteAllBytes(Path.Combine(_partDir, "state"), state);
        }

        /// <summary>The resumable prefix: only the contiguous run of applied chunks from
        /// zero — the hashing tree cannot skip, so anything past the first gap restarts
        /// there. A foreign or corrupt state file restarts the whole download.</summary>
        private long TryLoadPrefix()
        {
            string statePath = Path.Combine(_partDir, "state");
            if (!File.Exists(statePath) || !File.Exists(Path.Combine(_partDir, "data")))
            {
                return 0;
            }

            try
            {
                byte[] state = File.ReadAllBytes(statePath);
                if (state.Length != 8 + 32 + 16 || !state.AsSpan(0, 8).SequenceEqual(MagicBytes)
                    || !state.AsSpan(8, 32).SequenceEqual(root.AsSpan()))
                {
                    return 0;
                }

                long totalBytes = BinaryPrimitives.ReadInt64LittleEndian(state.AsSpan(8 + 32));
                long prefix = BinaryPrimitives.ReadInt64LittleEndian(state.AsSpan(8 + 32 + 8));
                if (totalBytes != _totalBytes || prefix <= 0 || prefix >= _totalChunks)
                {
                    return 0;
                }

                // The data file must actually hold the claimed prefix, minus the last
                // (possibly partial) chunk — anything shorter restarts from zero.
                long onDisk = new FileInfo(Path.Combine(_partDir, "data")).Length;
                return onDisk >= (prefix - 1) * Blake3.ChunkSize ? prefix : 0;
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                return 0;
            }
        }
    }

    /// <summary>Small in-memory sink for the directory manifest. The applied cursor only
    /// advances contiguously — same rule as the file sink, so "all chunks applied" means
    /// every index is present, with no holes a hostile sender could skip past.</summary>
    private sealed class MemorySink : Sink
    {
        private readonly Dictionary<long, byte[]> _received = new();
        private readonly Dictionary<long, byte[]> _applied = new();
        private long _totalBytes = -1;
        public byte[] Data { get; private set; } = Array.Empty<byte>();

        public override void Init(long totalBytes, long totalChunks) => _totalBytes = totalBytes;

        public override bool Apply(long index, byte[] data)
        {
            if (_applied.ContainsKey(index) || _received.ContainsKey(index))
            {
                return false;
            }

            _received[index] = data;
            while (_received.Remove(Applied, out byte[]? next))
            {
                _applied[Applied] = next;
                Applied++;
            }

            return true;
        }

        public override byte[] Complete()
        {
            var tree = new Blake3.Tree();
            var mem = new MemoryStream();
            for (long i = 0; i < Applied; i++)
            {
                byte[] chunk = _applied[i];
                tree.Update(chunk);
                mem.Write(chunk);
            }

            Data = mem.ToArray();
            return _totalBytes == 0 ? Blake3.Hash([]) : tree.RootHash();
        }
    }

    // ---------------------------------------------------------------- path safety

    private static string SafeJoin(string root, string relative)
    {
        var parts = new List<string>();
        foreach (string raw in relative.Split('/'))
        {
            string part = Sanitize(raw);
            if (part.Length > 0 && part is not ("." or ".."))
            {
                parts.Add(part);
            }
        }

        return parts.Count == 0 ? root : Path.Combine([root, .. parts]);
    }

    private static string Sanitize(string name)
    {
        foreach (char c in Path.GetInvalidFileNameChars())
        {
            name = name.Replace(c, '_');
        }

        return name.TrimEnd('.');
    }
}
