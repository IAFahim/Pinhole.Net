using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Threading.Channels;

namespace Pinhole.Blobs;

public readonly record struct BlobProgress(long VerifiedBytes, long TotalBytes, int FilesDone, int FilesTotal);

public sealed record BlobDownloadResult(string Path, long Bytes, bool Resumed);

public sealed record BlobDownloadOptions
{
    public PinholeOptions? NodeOptions { get; init; }

    public long MaxWindowBytes { get; init; } = 1024 * 1024;

    public BlobFlowBudget? FlowBudget { get; init; }

    public BlobTransferStats? Stats { get; init; }

    public TimeSpan RecoveryTimeout { get; init; } = TimeSpan.FromMinutes(10);
}

internal class BlobTransportLostException(string message) : Exception(message);

// A v3-only provider closes the connection on a version-4 Hello before answering.
// The recovery loop turns exactly this into a single immediate v3 re-dial.
internal sealed class BlobV4RefusedException(string message) : BlobTransportLostException(message);

public static class BlobClient
{
    // v4 bound: a Head larger than this is refused before any staging or file
    // allocation happens — a hostile Head can never size the receiver's memory.
    internal const long MaxDeclaredTotalBytes = 1L << 40;
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

        TimeSpan recovery = options?.RecoveryTimeout ?? TimeSpan.FromMinutes(10);
        ArgumentOutOfRangeException.ThrowIfLessThan(recovery, TimeSpan.Zero);
        var recoveryBudget = new RecoveryBudget(recovery);
        int backoffMs = 500;

        // State that legitimately survives a re-dial: the decoded manifest (never fetched
        // twice in one call), per-path completion (a file that finished stays finished —
        // its bytes were root-verified before the connection died), and the Hello version
        // the transfer settled on. Completion is keyed by destination path, never by
        // content root: a tree may legitimately contain several files with the same
        // bytes, and each must be materialized.
        var negotiation = new BlobNegotiation(ticket.PreSharedKey is not null);
        (string Name, List<Manifest.Entry> Entries)? manifest = null;
        var completedPaths = new HashSet<string>(StringComparer.Ordinal);
        var verifiedFileByRoot = new Dictionary<string, string>(StringComparer.Ordinal);
        bool anyResumed = false;

        if (ticket.Kind == BlobKind.File)
        {
            // Idempotent resume (R3/P5): a destination that already holds the ticket's
            // exact content IS the completed transfer — the checkpoint's fixed point.
            // Re-calling on a finished download mints no node, dials no provider, and
            // requests no bytes; content identity is proven by hashing, so a tampered
            // or foreign file falls through to a normal re-download.
            string fileName = string.IsNullOrWhiteSpace(ticket.Name) ? "pinhole-download" : ticket.Name;
            string target = SafeJoin(destinationDirectory, fileName);
            if (TryReadRootVerifiedFile(target, ticket.Root, out long existingBytes))
            {
                return new BlobDownloadResult(target, existingBytes, Resumed: true);
            }
        }

        await using var node = await PinholeNode.BindAsync(nodeOptions, ct).ConfigureAwait(false);
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            recoveryBudget.Check();
            negotiation.ConnectionStarted();

            bool dialing = true;
            try
            {
                // Bound each dial by the remaining shared recovery allowance. Cancelling
                // the actual dial also removes its pending connection; timing out only
                // its await would leave an attempt running behind the next retry.
                PinholeConnection connected;
                using (var dialStop = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    if (recovery > TimeSpan.Zero)
                    {
                        recoveryBudget.Begin();
                        TimeSpan remaining = recoveryBudget.Remaining;
                        if (remaining.TotalMilliseconds <= uint.MaxValue - 1) dialStop.CancelAfter(remaining);
                    }
                    try
                    {
                        connected = await node.ConnectAsync(ticket.ConnectionString, dialStop.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException ex) when (!ct.IsCancellationRequested && dialStop.IsCancellationRequested)
                    {
                        throw recoveryBudget.Exhausted(ex);
                    }
                }
                await using PinholeConnection conn = connected;
                recoveryBudget.End();
                dialing = false;

                // A fresh session per connection: a fresh downloader nonce, and the
                // provider's Welcome mints its own fresh nonce — keys are always
                // two-sided-new and counters restart with them. A recovery never
                // continues old counters under recreated keys.
                var session = new BlobWire.DownloadSession(ticket.PreSharedKey, ticket.Root);

                if (ticket.Kind == BlobKind.File)
                {
                    string fileName = string.IsNullOrWhiteSpace(ticket.Name) ? "pinhole-download" : ticket.Name;
                    string target = SafeJoin(destinationDirectory, fileName);
                    var sink = new FileSink(target, ticket.Root);
                    StreamDownloader? downloader = null;
                    downloader = new StreamDownloader(conn, sink,
                        v => progress?.Report(new BlobProgress(v, downloader!.TotalBytes, 0, 1)), new SendCounter(), session,
                        ticket.Root, recoveryBudget, negotiation, options: options);
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
                if (manifest is null)
                {
                    var manifestSink = new MemorySink();
                    var manifestDownloader = new StreamDownloader(conn, manifestSink, _ => { }, send, session, ticket.Root, recoveryBudget,
                        negotiation, options: options);
                    try
                    {
                        await manifestDownloader.RunAsync(ct).ConfigureAwait(false);
                    }
                    catch
                    {
                        manifestSink.Abandon();
                        throw;
                    }

                    manifest = Manifest.Decode(manifestSink.Data);
                }

                (string name, List<Manifest.Entry> entries) = manifest!.Value;
                string rootDir = SafeJoin(destinationDirectory, string.IsNullOrWhiteSpace(name) ? "pinhole-download" : name);
                long total = entries.Sum(e => e.Size);
                long verified = 0;
                int filesDone = 0;
                foreach (Manifest.Entry entry in entries)
                {
                    if (completedPaths.Contains(entry.Path))
                    {
                        verified += entry.Size;
                        filesDone++;
                        continue;
                    }

                    string target = SafeJoin(rootDir, entry.Path);
                    if (TryReadRootVerifiedFile(target, entry.Root, out _))
                    {
                        // A file that finished stays finished — including across calls:
                        // a re-download of a completed directory skips root-verified
                        // entries wholesale instead of re-fetching them (R3/P5).
                        completedPaths.Add(entry.Path);
                        verifiedFileByRoot[Convert.ToHexString(entry.Root)] = target;
                        verified += entry.Size;
                        filesDone++;
                        progress?.Report(new BlobProgress(verified, total, filesDone, entries.Count));
                        continue;
                    }

                    if (verifiedFileByRoot.TryGetValue(Convert.ToHexString(entry.Root), out string? written))
                    {
                        // Identical content is already on disk under another path and was
                        // root-verified when it landed; copying it is exact, not a shortcut.
                        string? parent = Path.GetDirectoryName(target);
                        if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                        File.Copy(written, target, overwrite: true);
                        completedPaths.Add(entry.Path);
                        verified += entry.Size;
                        filesDone++;
                        progress?.Report(new BlobProgress(verified, total, filesDone, entries.Count));
                        continue;
                    }

                    var sink = new FileSink(target, entry.Root);
                    StreamDownloader entryDownloader = new(conn, sink,
                        v => progress?.Report(new BlobProgress(verified + v, total, filesDone, entries.Count)), send, session,
                        entry.Root, recoveryBudget, negotiation, entry.Root, options: options);
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

                    completedPaths.Add(entry.Path);
                    verifiedFileByRoot[Convert.ToHexString(entry.Root)] = target;
                    verified += bytes;
                    filesDone++;
                    anyResumed |= sink.Resumed;
                    progress?.Report(new BlobProgress(verified, total, filesDone, entries.Count));
                }

                return new BlobDownloadResult(rootDir, verified, anyResumed);
            }
            catch (Exception ex) when (IsTransportLoss(ex, dialing))
            {
                if (ex is BlobV4RefusedException && negotiation.FallBackToV3())
                {
                    // A v3-only provider hung up on our version-4 Hello before answering
                    // anything: one immediate re-dial at v3, remembered for the whole
                    // transfer, without spending an outage backoff on it.
                    continue;
                }

                if (recovery <= TimeSpan.Zero || recoveryBudget.Remaining <= TimeSpan.Zero)
                {
                    throw recoveryBudget.Exhausted(ex);
                }

                // The transport went away mid-transfer (or an attempt stalled past its
                // own clock): verified checkpoints stay on disk, the pinned provider is
                // re-dialed through the same ticket — authenticated rediscovery included
                // — and the next attempt resumes exactly from those checkpoints.
                recoveryBudget.Begin();
                await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(backoffMs, recoveryBudget.Remaining.TotalMilliseconds)), ct)
                    .ConfigureAwait(false);
                backoffMs = (int)Math.Min(backoffMs * 2, 5000);
            }
        }
    }

    private static bool IsTransportLoss(Exception ex, bool dialing) =>
        ex is BlobTransportLostException or TimeoutException or ObjectDisposedException
        || (ex is InvalidOperationException && !dialing);

    // True when the file at path exists and hashes to the ticket root — the
    // download's own definition of "already complete". Only local bytes are read:
    // zero wire traffic. The empty file's root is the hash of no input, matching
    // FileSink.Complete; a file that is locked or unreadable is simply not
    // verified, and the normal download path decides its fate.
    private static bool TryReadRootVerifiedFile(string path, byte[] root, out long bytes)
    {
        bytes = 0;
        try
        {
            if (!File.Exists(path))
            {
                return false;
            }

            using FileStream stream = File.OpenRead(path);
            bytes = stream.Length;
            if (bytes == 0)
            {
                return Blake3.Hash([]).AsSpan().SequenceEqual(root);
            }

            var tree = new Blake3.Tree(retainOutboard: false);
            var buffer = new byte[64 * 1024];
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                tree.Update(buffer.AsSpan(0, read));
            }

            return tree.RootHash().AsSpan().SequenceEqual(root);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    // Per-transfer negotiation state. The Hello version persists across re-dials (once
    // a provider proved itself v3-only, the whole transfer stays at v3); the Welcome
    // version and head-seen flag describe the current connection only.
    internal sealed class BlobNegotiation
    {
        public BlobNegotiation(bool encrypted)
        {
            Encrypted = encrypted;
            // Plaintext tickets have no Welcome to negotiate through: v3 semantics.
            HelloVersion = encrypted ? BlobWire.CurrentVersion : BlobWire.ProtocolVersion;
        }

        public bool Encrypted { get; }
        public byte HelloVersion { get; private set; }
        public byte SessionVersion { get; private set; } // 0 until a Welcome is adopted
        public bool HeadSeen { get; private set; }

        public void ConnectionStarted()
        {
            SessionVersion = 0;
            HeadSeen = false;
        }

        public void AdoptWelcomeVersion(byte version)
        {
            if (SessionVersion == 0)
            {
                SessionVersion = version;
            }
        }

        public void MarkHeadSeen() => HeadSeen = true;

        public bool FallBackToV3()
        {
            if (HelloVersion != BlobWire.CurrentVersion)
            {
                return false;
            }

            HelloVersion = BlobWire.ProtocolVersion;
            return true;
        }
    }

    private sealed class SendCounter
    {
        private ulong _value;
        public ulong Next() => ++_value;
    }

    internal sealed class RecoveryBudget(TimeSpan timeout, Func<long>? clock = null)
    {
        private readonly long _limitMs = (long)Math.Ceiling(timeout.TotalMilliseconds);
        private long _spentMs;
        private long _sinceMs = -1;
        private long Now => clock?.Invoke() ?? Environment.TickCount64;

        public TimeSpan Remaining => TimeSpan.FromMilliseconds(Math.Max(0,
            _limitMs - _spentMs - (_sinceMs < 0 ? 0 : Now - _sinceMs)));

        public void Begin(long? since = null)
        {
            if (_sinceMs < 0) _sinceMs = since ?? Now;
        }

        public void End()
        {
            if (_sinceMs < 0) return;
            _spentMs += Now - _sinceMs;
            _sinceMs = -1;
            Check();
        }

        public void Check()
        {
            if ((timeout > TimeSpan.Zero || _sinceMs >= 0) && Remaining <= TimeSpan.Zero) throw Exhausted();
        }

        public long StallLimit(long ordinaryLimitMs) => timeout == TimeSpan.Zero
            ? ordinaryLimitMs : Math.Min(ordinaryLimitMs, (long)Remaining.TotalMilliseconds);

        public TimeoutException Exhausted(Exception? inner = null) => new(
            $"the transfer could not be re-established within {timeout.TotalSeconds:0.###}s of disruptions", inner);
    }

    // How long an answer to a sweep re-request is assumed to need when no RTT
    // sample exists yet, and the shortest patience a dying transfer re-arms its
    // sweeps at — fast enough to matter before the death clock, slow enough
    // that a hopeless tail cannot spin the loop.
    internal const long SweepAnswerFloorMs = 250;
    internal const long SweepFloorMs = 250;

    // A queued link pegs srtt at the PTO ceiling, so one loss event in the
    // request-horizon tail leaves the next natural re-request several backoff
    // periods out — 12s at rtx=2 — while the stall clock kills the attempt at
    // min(30s, the remaining recovery allowance), a fraction of that. Nothing
    // related the two clocks, so the transfer died in total wire silence on a
    // path that never went down: TopUp was horizon-blocked, the sweep was
    // patiently waiting, and the stall clock ran out first. Whatever the PTO
    // says, a re-request must still be able to fire, be answered, and verify
    // before the death clock does; inside that shrinking window the sweep
    // accelerates instead of idling. Healthy transfers never notice: a fresh
    // 30s limit against a young sentAt never bites, so the arm stays exactly
    // the PTO's.
    internal static long SweepArmMs(long ptoMs, long sentAtMs, long lastVerifiedMs, long limitMs, long answerMs)
    {
        long armMs = Math.Min(ptoMs, lastVerifiedMs + limitMs - answerMs - sentAtMs);
        return Math.Max(armMs, Math.Min(SweepFloorMs, ptoMs));
    }

    // Iteration gaps shorter than this many control ticks are ordinary scheduling
    // jitter around the idle-wait cadence and must credit nothing: a healthy
    // flight keeps aging through them. The margin must also clear Windows' ~16 ms
    // timer granularity — an idle loop's WaitAsync(5 ms) wakes land ~16 ms apart
    // there, and a threshold at that boundary would credit every idle iteration
    // and stretch every PTO ~3x on an otherwise quiet connection.
    internal const long LocalStallGapTicks = 10;

    // Wire-time clocks may only count time the control loop was actually running.
    // An inter-iteration gap beyond LocalStallGapTicks ticks means the loop itself
    // was blocked — a verifier callback stalling on the loop's own thread, a
    // whole-process GC pause, descheduling on a loaded runner — which is not path
    // loss: the answers the PTO would expire are buffered or still in flight, and
    // retransmitting into them manufactures duplicate load the wire never asked
    // for. Such a gap credits back gap - one tick, so a flight already at its PTO
    // edge when the stall hit still expires promptly and a genuinely lost flight
    // is never forgiven. The pathological production case — a pause long enough
    // that the responses were paused with it — errs toward delaying a retransmit
    // by the pause length; late healing is the safe direction, a retransmit storm
    // is not.
    internal static long LocalStallCreditMs(long gapMs, long tickMs) =>
        gapMs > LocalStallGapTicks * tickMs ? gapMs - tickMs : 0;

    // ---------------------------------------------------------------- stream downloader

    private sealed class StreamDownloader
    {
        private readonly record struct ReceivedFrame(BlobWire.Frame Frame, long ArrivedAtMs);

        // Verified-run staging: at most this many incomplete runs are held in memory
        // (16 * 64 KiB = 1 MiB). The request horizon is the same distance past the
        // lowest incomplete run, so staging can never outrun it.
        private const int MaxStagedRuns = 16;

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
        private readonly Dictionary<long, (long SentAtMs, int Retransmits, bool SampleRtt, bool HoldReleased)> _outstanding = new();
        private readonly SendCounter _send;
        private readonly RecoveryBudget _recovery;
        private readonly BlobNegotiation _negotiation;
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
        private long _traceStartTicks;
        private long _lastTraceTicks;

        private bool _v4; // verified-run path, active once a version-4 Welcome delivered the Head
        private long _runCount;
        private long _lowestIncomplete;
        private readonly Dictionary<long, RunStage> _staging = new();

        private sealed class RunStage(int length)
        {
            public readonly byte[]?[] Chunks = new byte[length][];
            public readonly byte[]?[] Cvs = new byte[length][];
            public int Staged;
            public byte[]? Proof;                 // sibling CVs, bottom-up; length 0 for single-run files
            public long ProofSentAt = -1;         // when a covering request last left
            public long FullyStagedAt = -1;         // when the last chunk staged without a proof yet
            public int ProofRetransmits;
            public bool CoveringRequested;        // a full-run Req went out (proof expected from it)
        }

        public long TotalBytes => _totalBytes < 0 ? 0 : _totalBytes;

        public StreamDownloader(PinholeConnection conn, Sink sink, Action<long> onVerified, SendCounter send,
            BlobWire.DownloadSession session, byte[] expectedRoot, RecoveryBudget recovery, BlobNegotiation negotiation,
            byte[]? streamRoot = null, BlobDownloadOptions? options = null)
        {
            _conn = conn;
            _sink = sink;
            _onVerified = onVerified;
            _send = send;
            _recovery = recovery;
            _negotiation = negotiation;
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
            // A slow verifier must backpressure its sole pump instead of retaining
            // an unbounded number of authenticated 1 KiB chunks.
            var frames = Channel.CreateBounded<ReceivedFrame>(new BoundedChannelOptions(256)
            {
                SingleReader = true,
                SingleWriter = true,
                FullMode = BoundedChannelFullMode.Wait,
            });
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

        private async Task PumpAsync(ChannelWriter<ReceivedFrame> writer, CancellationToken ct)
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

                long arrivedAtMs = Environment.TickCount64;
                if (!_session.TryOpen(mem.Span, _stream, out BlobWire.Frame f))
                {
                    continue; // garbage, tampered ciphertext, or another stream's frame
                }

                // The first frame an encrypted session can ever open is its Welcome, and
                // the Welcome travels unsealed — read its version off the wire to learn
                // whether this connection runs the verified-run path. A provider that
                // answers a v4 Hello with a v3 Welcome keeps the v3 downloader.
                if (_negotiation.Encrypted && _negotiation.SessionVersion == 0
                    && BlobWire.Frame.TryParse(mem.Span, out BlobWire.Frame bootstrap)
                    && bootstrap.Type == BlobWire.TypeWelcome && bootstrap.Stream == _stream
                    && bootstrap.SessionId is { } welcomed
                    && welcomed.AsSpan().SequenceEqual(_session.SessionId))
                {
                    _negotiation.AdoptWelcomeVersion(bootstrap.Version);
                }

                await writer.WriteAsync(new ReceivedFrame(f, arrivedAtMs), ct).ConfigureAwait(false);
                if (f.Type == BlobWire.TypeBye)
                {
                    return;
                }
            }
        }

        private async Task<long> RunLoopAsync(ChannelReader<ReceivedFrame> frames, CancellationToken ct)
        {
            _lastVerifiedTicks = Environment.TickCount64;
            _traceStartTicks = _lastVerifiedTicks;
            long lastLoopTicks = _lastVerifiedTicks;
            try
            {
                while (true)
                {
                    ct.ThrowIfCancellationRequested();
                    if (_conn.State == PinholeConnectionState.Closed)
                    {
                        // Pathlessness is a wait; Closed is a route verdict — the caller's
                        // recovery loop re-dials and resumes from the checkpoints.
                        throw TransportLost("the connection closed before the transfer finished");
                    }

                    // Receive work precedes loss decisions. A delayed verifier may
                    // have the genuine answers queued past their PTO; retrying first
                    // would manufacture duplicates and shrink a healthy window.
                    // Limit the batch so cancellation, path watching and checkpoints
                    // continue even when an authenticated peer fills the queue.
                    for (int drained = 0; drained < 64 && frames.TryRead(out ReceivedFrame buffered); drained++)
                    {
                        ReceiveFrame(buffered);
                    }

                    long now = Environment.TickCount64;
                    // The gap since the previous iteration's clock read measures how
                    // long this loop was NOT running (the drain above may stall on
                    // this very thread): idle waits wake at the ControlTick cadence,
                    // so anything past that is a local stall, not wire time, and is
                    // credited back before any sweep or stall decision below.
                    CreditLocalStall(now, now - lastLoopTicks);
                    lastLoopTicks = now;
                    bool pathPresent = WatchPath(now);
                    TraceState(now, pathPresent);
                    ObserveLedger();
                    _recovery.Check();
                    if (!pathPresent)
                    {
                        // The peer has not failed — the route is gone, and the engine is
                        // recovering it. Neither the stall clock nor the first-contact
                        // clock may run down while there is no path to verify progress
                        // on; the shared recovery allowance bounds the ride.
                        _lastVerifiedTicks = now;
                        _helloSince = now;
                    }

                    if (_totalChunks < 0)
                    {
                        if (_helloSince < 0)
                        {
                            _helloSince = now;
                        }

                        if (pathPresent && now - _helloSince > _recovery.StallLimit((long)FirstHeadTimeout.TotalMilliseconds))
                        {
                            _recovery.Begin(_helloSince);
                            // A v3-only provider does not hang up the engine connection:
                            // its blob layer refuses the version-4 Hello and then stays
                            // silent while the path looks healthy. The first-head
                            // timeout is therefore also a v4 refusal signal — surface
                            // it as one so the outer loop re-dials at v3 instead of
                            // spending the whole budget on version-4 retries.
                            throw !_negotiation.HeadSeen && _negotiation.HelloVersion == BlobWire.CurrentVersion
                                ? new BlobV4RefusedException("the provider did not answer the version-4 hello")
                                : new TimeoutException("the provider did not answer the ticket");
                        }

                        // Retries reuse the same downloader nonce. Welcome carries the
                        // provider nonce and a Head authenticated with the resulting key.
                        if (pathPresent && now - _helloLastTicks >= (long)HelloPace.TotalMilliseconds)
                        {
                            _helloLastTicks = now;
                            TrySend(BlobWire.Hello(_stream, _session.SessionId, _negotiation.HelloVersion));
                        }
                    }
                    else
                    {
                        if (_sink.Applied >= _totalChunks)
                        {
                            break;
                        }

                        if (pathPresent && !frames.TryPeek(out _))
                        {
                            // Healing before fresh demand: re-requests get first claim
                            // on the pacer's credit each tick, the way loss recovery
                            // precedes new data in a transport sender.
                            SweepStale(now);
                            TopUpRequests(now);
                        }

                        // The checkpoint is dirty-checked (no write while Applied has
                        // not moved) and the exit path below writes one final checkpoint
                        // so a cancelled attempt always leaves its prefix — resuming
                        // never depends on timer luck.
                        if (now - _lastCheckpointTicks >= (long)CheckpointPace.TotalMilliseconds)
                        {
                            _lastCheckpointTicks = now;
                            _sink.Checkpoint();
                        }
                    }

                    // Availability wait, not a consuming read: an abandoned WaitToReadAsync can
                    // steal a signal but never an item — TryRead below is the only consumer.
                    if (!frames.TryRead(out ReceivedFrame f))
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
                            throw TransportLost("the connection went quiet before the transfer finished");
                        }
                    }

                    ReceiveFrame(f);
                    CheckStall(Environment.TickCount64);
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
                // process-wide pie. Holds released at a PTO expiry are already back.
                foreach ((long idx, (long _, int _, bool _, bool holdReleased)) in _outstanding)
                {
                    if (!holdReleased)
                    {
                        _controller.ReleaseReservation(ChunkLength(idx));
                    }
                }

                _outstanding.Clear();
            }

            byte[] root = _sink.Complete();
            if (!root.AsSpan().SequenceEqual(_expectedRoot))
            {
                _sink.Reject();
                throw new InvalidDataException("downloaded content failed the root check — the transfer is incomplete or was tampered with");
            }
            _sink.Commit(); // publishing a file is allowed only after its complete root verifies

            return _totalBytes;
        }

        private void ReceiveFrame(ReceivedFrame received)
        {
            BlobWire.Frame frame = received.Frame;
            switch (frame.Type)
            {
                case BlobWire.TypeHead:
                    if (_totalChunks < 0)
                    {
                        _negotiation.MarkHeadSeen();
                        if (_negotiation.SessionVersion == BlobWire.CurrentVersion)
                        {
                            // Hostile-Head bound: refuse a declared size that could pin
                            // unbounded memory before the first byte is even requested.
                            if (frame.TotalBytes > MaxDeclaredTotalBytes)
                            {
                                throw new InvalidDataException(
                                    $"the provider declared {frame.TotalBytes:N0} bytes, above the {MaxDeclaredTotalBytes:N0} transfer bound");
                            }

                            _v4 = true;
                            _sink.UseVerifiedRuns();
                        }

                        _totalBytes = frame.TotalBytes;
                        _totalChunks = frame.TotalChunks;
                        _sink.Init(_totalBytes, _totalChunks);
                        if (_v4)
                        {
                            StartRunPath();
                        }
                        else
                        {
                            // Resume on the wire from the checkpoint's first gap.
                            _maxRequested = _sink.Applied - 1;
                            if (_sink.Applied > 0)
                            {
                                _verified = Math.Min(_sink.Applied * Blake3.ChunkSize, _totalBytes);
                                _onVerified(_verified);
                            }
                        }
                    }
                    break;
                case BlobWire.TypeChunk:
                    ReceiveChunk(frame, received.ArrivedAtMs, Environment.TickCount64);
                    break;
                case BlobWire.TypeProof:
                    if (_v4)
                    {
                        ReceiveProof(frame, Environment.TickCount64);
                    }
                    break;
                case BlobWire.TypeBye:
                    throw new InvalidDataException("the provider cancelled this stream");
            }
        }

        private void StartRunPath()
        {
            _runCount = RunVerify.RunCount(_totalChunks);
            while (_lowestIncomplete < _runCount && _sink.RunCommitted(_lowestIncomplete))
            {
                _lowestIncomplete++;
            }

            // The march restarts at the lowest incomplete run: TopUp jumps over any
            // committed run it meets (sparse resumes leave holes), so only missing
            // runs are ever requested.
            _maxRequested = _lowestIncomplete * RunVerify.RunChunks - 1;

            _verified = _sink.CommittedBytes;
            if (_verified > 0)
            {
                _lastVerifiedTicks = Environment.TickCount64;
                _onVerified(_verified);
            }
        }

        private Exception TransportLost(string message) =>
            !_negotiation.HeadSeen && _negotiation.HelloVersion == BlobWire.CurrentVersion
                ? new BlobV4RefusedException(message)
                : new BlobTransportLostException(message);

        private bool WatchPath(long now)
        {
            bool present = _conn.State is PinholeConnectionState.Open or PinholeConnectionState.Degraded;
            if (!present)
            {
                _recovery.Begin(_lastVerifiedTicks);
                _pathlessSinceMs = _pathlessSinceMs < 0 ? now : _pathlessSinceMs;
                return false;
            }

            long pathlessFor = _pathlessSinceMs >= 0 ? now - _pathlessSinceMs : 0;
            if (_pathlessSinceMs >= 0) _recovery.End();
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
                    // Backoff measured the old route. Carrying it into a freshly
                    // proved route can delay the first request by 8× the new PTO
                    // and exhaust recovery while that route is already healthy.
                    // A hold already released at a PTO expiry stays released: the
                    // flag says the flight is healing traffic, route or no route.
                    _outstanding[idx] = (now, 0, false, _outstanding[idx].HoldReleased);
                }

                foreach (RunStage stage in _staging.Values)
                {
                    // Same reasoning for the proof timers the run path keeps.
                    if (stage.ProofSentAt >= 0)
                    {
                        stage.ProofSentAt = now;
                        stage.ProofRetransmits = 0;
                    }

                    if (stage.FullyStagedAt >= 0)
                    {
                        stage.FullyStagedAt = now;
                    }
                }
            }

            return true;
        }

        // A local stall is not path loss (see LocalStallCreditMs): the flight's
        // answer is queued or in flight, only our own loop stopped looking, so the
        // stall's duration comes off every wire-time clock before SweepStale or
        // CheckStall can act on ages the loop never observed passing. Clocks
        // stamped after the stall began (a chunk verified during this very
        // iteration's drain) are already at `now` and clamp to it; ProofSentAt /
        // FullyStagedAt are -1 until they start and are left that way.
        private void CreditLocalStall(long now, long gapMs)
        {
            long credit = LocalStallCreditMs(gapMs, (long)ControlTick.TotalMilliseconds);
            if (credit <= 0)
            {
                return;
            }

            long[] flights = [.. _outstanding.Keys];
            foreach (long idx in flights)
            {
                (long sentAt, int retransmits, bool sampleRtt, bool holdReleased) = _outstanding[idx];
                _outstanding[idx] = (Math.Min(sentAt + credit, now), retransmits, sampleRtt, holdReleased);
            }

            foreach (RunStage stage in _staging.Values)
            {
                if (stage.ProofSentAt >= 0)
                {
                    stage.ProofSentAt = Math.Min(stage.ProofSentAt + credit, now);
                }

                if (stage.FullyStagedAt >= 0)
                {
                    stage.FullyStagedAt = Math.Min(stage.FullyStagedAt + credit, now);
                }
            }

            _lastVerifiedTicks = Math.Min(_lastVerifiedTicks + credit, now);
        }

        private void ReceiveChunk(BlobWire.Frame f, long arrivedAtMs, long now)
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

            bool hadReservation = _outstanding.Remove(f.Index, out (long SentAtMs, int Retransmits, bool SampleRtt, bool HoldReleased) entry);
            if (hadReservation && entry.SampleRtt)
            {
                // Karn's rule: only a first-attempt arrival measures the path's RTT — a
                // retransmitted request's arrival time no longer bounds the original send.
                _controller.ObserveRtt(TimeSpan.FromMilliseconds(Math.Max(arrivedAtMs - entry.SentAtMs, 1)));
            }

            // A hold released at the chunk's first PTO expiry must not release again
            // here: the arrival's bytes stopped counting against window and budget
            // the moment their lost flight was reclassified as healing traffic.
            bool liveHold = hadReservation && !entry.HoldReleased;
            bool retransmitted = hadReservation && entry.Retransmits > 0;
            if (!_v4)
            {
                bool fresh = _sink.Apply(f.Index, f.ChunkData);
                _controller.OnChunkArrived(len, liveHold, fresh, retransmitted, now);
                if (fresh)
                {
                    _verified += len;
                    _lastVerifiedTicks = now;
                    _onVerified(_verified);
                }

                return;
            }

            if (_totalChunks == 1)
            {
                // A one-chunk file has no folds: the ticket root IS the root-flagged
                // chunk hash, so the per-chunk check above is not enough — verify the
                // bytes against the root directly and commit immediately.
                if (!RunVerify.VerifySingleChunk(f.ChunkData, _expectedRoot))
                {
                    throw new InvalidDataException("chunk 0 failed root verification");
                }

                _controller.OnChunkArrived(len, liveHold, true, retransmitted, now);
                _sink.ApplyRun(0, 1, [f.ChunkData], Blake3.ChunkCv(f.ChunkData, 0, root: true));
                _verified += len;
                _lastVerifiedTicks = now;
                _onVerified(_verified);
                return;
            }

            ReceiveRunChunk(f, len, liveHold, retransmitted, now);
        }

        private void ReceiveRunChunk(BlobWire.Frame f, int len, bool hadReservation, bool retransmitted, long now)
        {
            long run = f.Index / RunVerify.RunChunks;
            if (run < _lowestIncomplete || run * RunVerify.RunChunks > _maxRequested)
            {
                // Committed or never-requested territory: unsolicited, dropped silently.
                _controller.OnChunkArrived(len, hadReservation, fresh: false, retransmitted, now);
                return;
            }

            if (!_staging.TryGetValue(run, out RunStage? stage))
            {
                if (_staging.Count >= MaxStagedRuns)
                {
                    // Beyond the staging bound: drop; the run is re-requested once the
                    // horizon reaches it again.
                    _controller.OnChunkArrived(len, hadReservation, fresh: false, retransmitted, now);
                    return;
                }

                stage = new RunStage(RunVerify.RunLength(run, _totalChunks));
                _staging[run] = stage;
            }

            int slot = (int)(f.Index - run * RunVerify.RunChunks);
            if (stage.Chunks[slot] is not null)
            {
                _controller.OnChunkArrived(len, hadReservation, fresh: false, retransmitted, now);
                return; // duplicate transmission
            }

            stage.Chunks[slot] = f.ChunkData;
            stage.Cvs[slot] = f.ChunkCv;
            stage.Staged++;
            _controller.OnChunkArrived(len, hadReservation, fresh: true, retransmitted, now);
            _verified += len;
            _lastVerifiedTicks = now;
            _onVerified(_verified);
            TryCommitRun(run, stage, now);
        }

        private void ReceiveProof(BlobWire.Frame f, long now)
        {
            long run = f.Index;
            if (run < _lowestIncomplete || run >= _runCount || run * RunVerify.RunChunks > _maxRequested)
            {
                return; // proof for a committed or unrequested run: unsolicited
            }

            if (!_staging.TryGetValue(run, out RunStage? stage))
            {
                if (_staging.Count >= MaxStagedRuns || f.SiblingCvs!.Length > RunVerify.MaxSiblings * RunVerify.CvSize)
                {
                    return;
                }

                stage = new RunStage(RunVerify.RunLength(run, _totalChunks));
                _staging[run] = stage;
            }

            if (stage.Proof is not null)
            {
                return; // first proof wins; honest retries carry identical bytes
            }

            stage.Proof = f.SiblingCvs!;
            _lastVerifiedTicks = now;
            TryCommitRun(run, stage, now);
        }

        // A run commits when all its chunks are staged AND its proof is present: the
        // proof must fold the staged CVs and the sibling chain to the ticket root.
        // Only then do the run's bytes touch the sink — never before.
        private void TryCommitRun(long run, RunStage stage, long now)
        {
            int length = RunVerify.RunLength(run, _totalChunks);
            if (stage.Staged != length)
            {
                return;
            }

            if (stage.Proof is null)
            {
                // The proof rides the request that delivers the run's last chunk
                // (covering or piecewise-completing); a proof one frame behind in the
                // queue is the common case, so never chase it eagerly — a full-run
                // fetch here re-requested every piecewise run wholesale. Only a proof
                // lost on the wire is healed, by the PTO sweep below.
                stage.FullyStagedAt = stage.FullyStagedAt < 0 ? now : stage.FullyStagedAt;
                return;
            }

            var leaves = new byte[length * RunVerify.CvSize];
            for (int i = 0; i < length; i++)
            {
                stage.Cvs[i]!.CopyTo(leaves.AsSpan(i * RunVerify.CvSize));
            }

            if (!RunVerify.VerifyRun(leaves, stage.Proof, run, _totalChunks, _expectedRoot))
            {
                throw new InvalidDataException($"run {run} failed root verification");
            }

            // The verified run's node CV (the root-flagged fold for a single-run file,
            // where it IS the file root; a plain CV otherwise) feeds the final fold.
            var runCv = new byte[RunVerify.CvSize];
            if (!RunVerify.FoldRun(leaves, length, rootOnFinal: _runCount == 1, runCv))
            {
                throw new InvalidOperationException("the run fold rejected its verified leaves");
            }

            var chunks = new byte[length][];
            for (int i = 0; i < length; i++)
            {
                chunks[i] = stage.Chunks[i]!;
            }

            _staging.Remove(run);
            _sink.ApplyRun(run, length, chunks, runCv);
            if (run == _lowestIncomplete)
            {
                while (_lowestIncomplete < _runCount && _sink.RunCommitted(_lowestIncomplete))
                {
                    _lowestIncomplete++;
                }
            }

            _lastVerifiedTicks = now;
        }

        private void RequestRunProof(long run, RunStage stage, long now)
        {
            stage.CoveringRequested = true;
            stage.ProofSentAt = now;
            stage.ProofRetransmits = 0;
            // The provider attaches the run's proof to any request that serves the
            // run's last chunk, so a one-chunk request fetches it in two frames. A
            // full-run burst here would put the proof — the frame we are missing —
            // at the tail of the largest burst the path has just proven it drops.
            Send(BlobWire.Request(_stream, run * RunVerify.RunChunks + RunVerify.RunLength(run, _totalChunks) - 1, 1));
        }

        private long ChunkLength(long index) =>
            (long)Math.Min(Blake3.ChunkSize, _totalBytes - index * Blake3.ChunkSize);

        private void TopUpRequests(long now)
        {
            // Requests stay inside the sink's reorder horizon: a chunk asked for beyond
            // Applied + ReorderSpan would be dropped on the floor on arrival, consuming
            // its reservation while the hole it leaves is never re-requested — measured
            // wire waste AND a guaranteed stall once a leading chunk is lost with a
            // window wider than the buffer. The horizon slides with the applied prefix.
            // On the verified-run path the horizon is run-granular instead (the lowest
            // incomplete run plus the staging bound) and no request may cross a run
            // boundary: a request that spans a whole run from its start boundary is the
            // one the provider answers with a proof.
            long horizon = _v4
                ? Math.Min(_totalChunks, (_lowestIncomplete + MaxStagedRuns) * RunVerify.RunChunks)
                : Math.Min(_totalChunks, _sink.Applied + Math.Min(_sink.ReorderSpan, _totalChunks));
            while (_maxRequested + 1 < horizon)
            {
                long start = _maxRequested + 1;
                long run = start / RunVerify.RunChunks;
                long limit = horizon;
                if (_v4)
                {
                    if (_sink.RunCommitted(run))
                    {
                        // A resumed sparse commit: everything in this run is already
                        // verified on disk — jump the march past it.
                        _maxRequested = Math.Min(horizon, (run + 1) * RunVerify.RunChunks) - 1;
                        continue;
                    }

                    limit = Math.Min(horizon, (run + 1) * RunVerify.RunChunks); // never cross the run end
                }

                int desired = (int)Math.Min(_controller.MaxRunChunks, limit - start);
                int count = Math.Min(desired, _controller.AffordableChunks(desired, now));
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
                    _outstanding[idx] = (now, 0, true, false);
                }

                Send(BlobWire.Request(_stream, start, count));
                _maxRequested = start + count - 1;
                if (_v4 && start == run * RunVerify.RunChunks
                    && start + count == Math.Min((run + 1) * RunVerify.RunChunks, _totalChunks))
                {
                    // One request covered the whole run: this is the one that earns
                    // the proof. Anything less and the proof is fetched on full staging.
                    if (!_staging.TryGetValue(run, out RunStage? stage))
                    {
                        stage = new RunStage(RunVerify.RunLength(run, _totalChunks));
                        _staging[run] = stage;
                    }

                    stage.CoveringRequested = true;
                    stage.ProofSentAt = now;
                }
            }
        }

        // The sweep's patience is bounded by the stall clock, not the PTO
        // alone — BlobClient.SweepArmMs above documents the failure this
        // prevents.
        private long SweepArmMs(long ptoMs, long sentAtMs) =>
            BlobClient.SweepArmMs(ptoMs, sentAtMs, _lastVerifiedTicks,
                _recovery.StallLimit((long)StallTimeout.TotalMilliseconds),
                (long)(_controller.SmoothedRtt ?? TimeSpan.FromMilliseconds(SweepAnswerFloorMs)).TotalMilliseconds);

        private void SweepStale(long now)
        {
            foreach ((long idx, (long sentAt, int retransmits, _, bool holdReleased)) in _outstanding)
            {
                if (now - sentAt < SweepArmMs((long)_controller.PtoFor(retransmits).TotalMilliseconds, sentAt))
                {
                    continue;
                }

                if (!holdReleased)
                {
                    // The hold's flight is dead — this expiry is the proof. A hold
                    // that outlives its flight pins inFlight above the window the
                    // same expiries just collapsed, and the march can never admit
                    // work again: a withheld 64-chunk run froze a CI transfer with
                    // 64 KiB of zombie reservations against the 4 KiB floor while
                    // the runs behind the hole were never even requested. Re-requests
                    // are unbudgeted healing traffic (below), so the stale hold
                    // converts to that status instead of stacking on the window.
                    _controller.ReleaseReservation(ChunkLength(idx));
                }

                // Re-requesting a chunk needs no fresh budget reservation — the
                // re-request is healing traffic and draws neither budget nor pacer
                // credit. Charging again per retry stacked N+1 reservations on a
                // single chunk: sustained loss could fill the aggregate pie with
                // retry debt and deny the very re-requests that would repay it.
                // Pacer credit is NOT drawn here either — the bucket models
                // admission of NEW work; healing traffic must not be throttled by a
                // collapsed window or recovery livelocks at the floor rate. The
                // honest bounds on re-request rate are the per-chunk PTO and the
                // reorder horizon.
                _outstanding[idx] = (now, retransmits + 1, false, true);
                if (Send(BlobWire.Request(_stream, idx, 1))) _controller.OnRetransmit(now);
            }

            if (_v4)
            {
                SweepStaleProofs(now);
            }
        }

        // A fully staged run whose proof never landed gets its whole run re-requested:
        // the provider resends the chunks (duplicates, dropped on arrival) and the
        // proof. Like the single-chunk sweep this is healing traffic — no reservation.
        private void SweepStaleProofs(long now)
        {
            foreach ((long run, RunStage stage) in _staging)
            {
                if (stage.Proof is not null || stage.Staged != RunVerify.RunLength(run, _totalChunks))
                {
                    continue;
                }

                // The patience clock starts at whichever came last: the covering
                // request leaving, or the run's final chunk staging without a proof.
                long since = Math.Max(stage.ProofSentAt, stage.FullyStagedAt);
                if (since < 0)
                {
                    continue;
                }

                if (now - since < SweepArmMs((long)_controller.PtoFor(stage.ProofRetransmits).TotalMilliseconds, since))
                {
                    continue;
                }

                stage.ProofSentAt = now;
                stage.ProofRetransmits++;
                if (Send(BlobWire.Request(_stream, run * RunVerify.RunChunks + RunVerify.RunLength(run, _totalChunks) - 1, 1)))
                {
                    _controller.OnRetransmit(now);
                }
            }
        }

        private void CheckStall(long now)
        {
            long limitMs = _recovery.StallLimit((long)StallTimeout.TotalMilliseconds);
            if (_pathlessSinceMs < 0 && now - _lastVerifiedTicks > limitMs)
            {
                _recovery.Begin(_lastVerifiedTicks);
                throw new TimeoutException(
                    $"the download stalled: no chunk verified for {TimeSpan.FromMilliseconds(limitMs).TotalSeconds:0.##}s");
            }
        }

        // One compact state line per ~250 ms, only when a test asked for it via
        // BlobTestHooks.Trace: enough timeline to see which clock froze on a CI
        // runner without flooding the log. Null in production, and AsyncLocal so
        // parallel transfers never interleave into one timeline.
        // R3/P3 conservation probe (BlobTestHooks.Ledger): one snapshot per control
        // tick of the three reservation faces. Every mutation of the ledger happens
        // synchronously on this thread between ticks, so a snapshot is never torn.
        // The final drain (the finally block below) is observed by the caller as the
        // budget resting at zero once the stream has unwound.
        private void ObserveLedger()
        {
            Action<long, long, long>? ledger = BlobTestHooks.Ledger;
            if (ledger is null)
            {
                return;
            }

            long holds = 0;
            foreach ((long idx, (long _, int _, bool _, bool holdReleased)) in _outstanding)
            {
                if (!holdReleased)
                {
                    holds += ChunkLength(idx);
                }
            }

            ledger(_controller.BudgetReservedBytes, _controller.PacerInFlightBytes, holds);
        }

        private void TraceState(long now, bool pathPresent)
        {
            Action<string>? trace = BlobTestHooks.Trace;
            if (trace is null || now - _lastTraceTicks < 250)
            {
                return;
            }

            _lastTraceTicks = now;
            int maxRtx = 0;
            foreach ((_, (long _, int retransmits, _, _)) in _outstanding)
            {
                maxRtx = Math.Max(maxRtx, retransmits);
            }

            var staging = new StringBuilder();
            foreach ((long run, RunStage stage) in _staging)
            {
                staging.Append(run).Append(':').Append(stage.Staged).Append('/').Append(stage.Chunks.Length)
                    .Append(stage.Proof is null ? " " : "+p ");
            }

            trace($"t={((now - _traceStartTicks) / 1000.0):0.0}s state={_conn.State} path={pathPresent} v4={_v4} " +
                  $"ver={_verified}/{_totalBytes} app={_sink.Applied}/{_totalChunks} lowInc={_lowestIncomplete}/{_runCount} " +
                  $"maxReq={_maxRequested} out={_outstanding.Count} rtxMax={maxRtx} staging=[{staging}]");
        }

        private bool Send(byte[] plain)
        {
            if (!TrySend(_session.Seal(_send.Next(), plain))) return false;
            _controller.OnRequestSent();
            return true;
        }

        private bool TrySend(byte[] wire)
        {
            try { _conn.Send(wire); return true; }
            catch (InvalidOperationException) when (_conn.State is PinholeConnectionState.Punching or PinholeConnectionState.Dead)
            {
                // The path can disappear between WatchPath and Send. Leave this frame
                // to the next Hello/request retry so the control loop continues checking
                // cancellation and the shared deadline instead of blocking in a ride-out.
                return false;
            }
        }
    }

    // ---------------------------------------------------------------- sinks

    internal abstract class Sink
    {
        public long Applied { get; protected set; }

        public virtual long ReorderSpan => long.MaxValue;

        public abstract void Init(long totalBytes, long totalChunks);
        public abstract bool Apply(long index, byte[] data);
        public abstract byte[] Complete();
        public virtual void Commit() { }
        public virtual void Reject() => Abandon();
        public virtual void Checkpoint() { }
        public virtual void Abandon() { }

        // ---------------------------------------------------------------- verified runs (v4)
        // Activated by the downloader after a version-4 Welcome delivered the Head and
        // before Init. On this path the sink never sees an unverified byte: whole runs
        // arrive already chained to the ticket root.
        public virtual void UseVerifiedRuns() { }

        public virtual void ApplyRun(long runIndex, int runLength, byte[][] chunks, byte[] runCv) { }

        public virtual bool RunCommitted(long runIndex) => false;

        public virtual long CommittedBytes => 0;
    }

    internal sealed class FileSink(string target, byte[] root) : Sink
    {
        private const string Magic = "PBPART01";
        private static readonly byte[] MagicBytes = System.Text.Encoding.ASCII.GetBytes(Magic);
        private const string RunMagic = "PBPART02"; // v4: committed runs + fold state, no prefix re-hash
        private static readonly byte[] RunMagicBytes = System.Text.Encoding.ASCII.GetBytes(RunMagic);
        private const long ReorderWindow = 512;
        private const int MaxResumableSparseRuns = 64; // staging keeps ~16; parsed leniently, still bounded

        public override long ReorderSpan => ReorderWindow;

        private readonly string _partDir = target + ".pinhole-part";
        private readonly Dictionary<long, byte[]> _reorder = new();
        private FileStream _data = null!;
        private readonly Blake3.Tree _tree = new(retainOutboard: false);
        private long _totalBytes;
        private long _totalChunks;

        // v4 verified-run state. Disk only ever holds verified bytes: writes happen at
        // run commit, and the checkpoint describes exactly those runs plus the fold
        // state needed to finish the root without re-reading anything.
        private bool _runMode;
        private long _runCount;
        private bool[] _committedRuns = [];
        private readonly Dictionary<long, byte[]> _runSparse = new(); // committed runs beyond the fold prefix
        private uint[] _runStack = [];                                // contiguous-prefix fold stack over run CVs
        private long[] _runStackRuns = [];
        private int _runStackDepth;
        private long _runPrefix;          // contiguous committed prefix, in runs
        private long _committedBytes;
        private int _runStateVersion;
        private int _runCheckpointedVersion;

        public bool Resumed { get; private set; }

        internal long CheckpointWrites { get; private set; }

        // v3 resume re-hashes the whole prefix from disk; the v4 resume is O(1). This
        // counter makes the difference observable: only the v3 path ever moves it.
        internal long RehashedPrefixChunks { get; private set; }

        private long _checkpointedApplied = -1;

        public override void UseVerifiedRuns() => _runMode = true;

        public override void Init(long totalBytes, long totalChunks)
        {
            _totalBytes = totalBytes;
            _totalChunks = totalChunks;
            Directory.CreateDirectory(_partDir);
            if (_runMode)
            {
                InitRunMode();
                return;
            }

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
                RehashedPrefixChunks++;
            }

            Applied = prefix;
            // The on-disk state (or its absence at prefix 0) already claims exactly this
            // prefix; the dirty check in Checkpoint relies on that bookkeeping.
            _checkpointedApplied = prefix;
        }

        private void InitRunMode()
        {
            _runCount = RunVerify.RunCount(_totalChunks);
            _committedRuns = new bool[_runCount];
            _runStack = new uint[8 * RunVerify.MaxSiblings];
            _runStackRuns = new long[RunVerify.MaxSiblings];
            LoadRunState();
            _data = new FileStream(Path.Combine(_partDir, "data"), FileMode.OpenOrCreate, FileAccess.ReadWrite,
                FileShare.None, Blake3.ChunkSize, FileOptions.Asynchronous);
            // No prefix re-hash: every committed run was verified against the ticket
            // root before it was written, so resuming is O(1) in the state file.
            _runCheckpointedVersion = _runStateVersion;
        }

        public override bool Apply(long index, byte[] data)
        {
            if (index < Applied || _reorder.ContainsKey(index) || index >= Applied + ReorderWindow)
            {
                return false; // duplicates and out-of-window chunks never reach disk
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
            else
            {
                _reorder[index] = data; // ahead of the cursor but inside the window
            }
            return true;
        }

        public override void ApplyRun(long runIndex, int runLength, byte[][] chunks, byte[] runCv)
        {
            long first = runIndex * RunVerify.RunChunks;
            for (int i = 0; i < runLength; i++)
            {
                byte[] chunk = chunks[i];
                _data.Seek((first + i) * Blake3.ChunkSize, SeekOrigin.Begin);
                _data.Write(chunk, 0, chunk.Length);
                _committedBytes += chunk.Length;
            }

            _committedRuns[runIndex] = true;
            Applied += runLength;
            if (runIndex == _runPrefix && runIndex < _runCount - 1)
            {
                // Extends the contiguous prefix: fold it into the stack and pull in any
                // runs that committed early and were waiting in the sparse set.
                PushRunCv(runCv);
                _runPrefix++;
                while (_runPrefix < _runCount - 1 && _runSparse.Remove(_runPrefix, out byte[]? next))
                {
                    PushRunCv(next);
                    _runPrefix++;
                }
            }
            else
            {
                // Committed out of order, or the final run: the final run stays out of
                // the stack so the last fold can carry the ROOT flag (a plain push of a
                // power-of-two run count would merge the top pair without it).
                _runSparse[runIndex] = runCv;
            }

            _runStateVersion++;
        }

        public override bool RunCommitted(long runIndex) => _committedRuns[runIndex];

        public override long CommittedBytes => _committedBytes;

        private void PushRunCv(byte[] cv)
        {
            Span<uint> words = stackalloc uint[8];
            RunVerify.LoadCv(cv, words);
            Crypto.Blake3.PushCv(words, 1, _runStack, _runStackRuns, ref _runStackDepth, Crypto.Blake3.IvWords, 0);
        }

        private void Feed(byte[] data)
        {
            _tree.Update(data);
            Applied++;
        }

        public override byte[] Complete()
        {
            if (!_runMode)
            {
                return _totalBytes == 0 ? Blake3.Hash([]) : _tree.RootHash();
            }

            if (_totalBytes == 0)
            {
                return Blake3.Hash([]);
            }

            if (_runCount == 1)
            {
                // Single-run files verified the root directly at commit (the run's own
                // ROOT-flagged fold equals the ticket root); no final fold exists.
                return _runSparse[0];
            }

            // All runs committed: the stack holds runs 0..n-2 folded, the sparse set
            // holds exactly the final run. Fold the final run's CV up the spine with
            // ROOT on the last fold — FoldRunsToRoot's finish, kept incrementally.
            Span<uint> acc = stackalloc uint[8];
            RunVerify.LoadCv(_runSparse[_runCount - 1], acc);
            Span<uint> parent = stackalloc uint[8];
            for (int i = _runStackDepth - 1; i >= 0; i--)
            {
                Crypto.Blake3.ParentWords(_runStack.AsSpan(8 * i, 8), acc, Crypto.Blake3.IvWords, 0, root: i == 0, parent);
                parent.CopyTo(acc);
            }

            var digest = new byte[RunVerify.CvSize];
            RunVerify.WordsToBytes(acc, digest);
            return digest;
        }

        public override void Commit()
        {
            _data.SetLength(_totalBytes);
            _data.Flush(flushToDisk: true);
            _data.Dispose();
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(target))!);
            File.Move(Path.Combine(_partDir, "data"), target, overwrite: true);
            Directory.Delete(_partDir, recursive: true);
        }

        public override void Reject()
        {
            _data.Dispose();
            Directory.Delete(_partDir, recursive: true);
        }

        public override void Abandon()
        {
            // Cancelled mid-transfer: release the handle but keep the part directory —
            // the checkpointed prefix is exactly what the next attempt resumes from.
            _data?.Dispose();
        }

        public override void Checkpoint()
        {
            if (_runMode)
            {
                CheckpointRuns();
                return;
            }

            // Dirty check (A-10): the control loop ticks this every 50 ms even while
            // stalled, and each write is two fsyncs and a rename. The state is a pure
            // function of Applied, so an unmoved cursor means the file is already right.
            if (Applied == 0 || Applied >= _totalChunks || Applied == _checkpointedApplied)
            {
                return;
            }

            var state = new byte[8 + 32 + 16];
            System.Text.Encoding.ASCII.GetBytes(Magic).CopyTo(state, 0);
            root.CopyTo(state, 8);
            BinaryPrimitives.WriteInt64LittleEndian(state.AsSpan(8 + 32), _totalBytes);
            BinaryPrimitives.WriteInt64LittleEndian(state.AsSpan(8 + 32 + 8), Applied);
            // A checkpoint may claim only durable data. Replacing a flushed
            // temporary state file keeps a torn write from destroying the last
            // usable checkpoint while the downloader is cancelled or crashes.
            _data.Flush(flushToDisk: true);
            string temporary = Path.Combine(_partDir, "state.tmp");
            using (var snapshot = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                snapshot.Write(state);
                snapshot.Flush(flushToDisk: true);
            }
            File.Move(temporary, Path.Combine(_partDir, "state"), overwrite: true);
            _checkpointedApplied = Applied;
            CheckpointWrites++;
        }

        // Same dirty-check discipline as the v3 checkpoint: the state is a pure
        // function of the committed-run set, so an unchanged version writes nothing.
        private void CheckpointRuns()
        {
            if (Applied == 0 || Applied >= _totalChunks || _runCheckpointedVersion == _runStateVersion)
            {
                return;
            }

            int bitmapBytes = (int)((_runCount + 7) / 8);
            var state = new byte[60 + bitmapBytes + 4 + _runStackDepth * 40 + 4 + _runSparse.Count * 40];
            RunMagicBytes.CopyTo(state);
            root.CopyTo(state, 8);
            BinaryPrimitives.WriteInt64LittleEndian(state.AsSpan(40), _totalBytes);
            BinaryPrimitives.WriteInt64LittleEndian(state.AsSpan(48), _runCount);
            BinaryPrimitives.WriteInt32LittleEndian(state.AsSpan(56), bitmapBytes);
            for (long r = 0; r < _runCount; r++)
            {
                if (_committedRuns[r])
                {
                    state[60 + r / 8] |= (byte)(1 << (int)(r % 8));
                }
            }

            int pos = 60 + bitmapBytes;
            BinaryPrimitives.WriteInt32LittleEndian(state.AsSpan(pos), _runStackDepth);
            pos += 4;
            for (int i = 0; i < _runStackDepth; i++)
            {
                BinaryPrimitives.WriteInt64LittleEndian(state.AsSpan(pos), _runStackRuns[i]);
                RunVerify.WordsToBytes(_runStack.AsSpan(8 * i, 8), state.AsSpan(pos + 8));
                pos += 40;
            }

            BinaryPrimitives.WriteInt32LittleEndian(state.AsSpan(pos), _runSparse.Count);
            pos += 4;
            foreach ((long runIndex, byte[] cv) in _runSparse)
            {
                BinaryPrimitives.WriteInt64LittleEndian(state.AsSpan(pos), runIndex);
                cv.CopyTo(state, pos + 8);
                pos += 40;
            }

            _data.Flush(flushToDisk: true);
            string temporary = Path.Combine(_partDir, "state.tmp");
            using (var snapshot = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                snapshot.Write(state);
                snapshot.Flush(flushToDisk: true);
            }
            File.Move(temporary, Path.Combine(_partDir, "state"), overwrite: true);
            _runCheckpointedVersion = _runStateVersion;
            CheckpointWrites++;
        }

        private void LoadRunState()
        {
            string statePath = Path.Combine(_partDir, "state");
            if (!File.Exists(statePath) || !File.Exists(Path.Combine(_partDir, "data")))
            {
                return;
            }

            try
            {
                byte[] state = File.ReadAllBytes(statePath);
                if (state.Length < 64 || !state.AsSpan(0, 8).SequenceEqual(RunMagicBytes)
                    || !state.AsSpan(8, 32).SequenceEqual(root.AsSpan()))
                {
                    return; // absent, v3-format (PBPART01), or foreign: restart clean
                }

                long totalBytes = BinaryPrimitives.ReadInt64LittleEndian(state.AsSpan(40));
                long runCount = BinaryPrimitives.ReadInt64LittleEndian(state.AsSpan(48));
                if (totalBytes != _totalBytes || runCount != _runCount || runCount < 0)
                {
                    return;
                }

                int bitmapBytes = BinaryPrimitives.ReadInt32LittleEndian(state.AsSpan(56));
                if (bitmapBytes != (_runCount + 7) / 8 || 60 + bitmapBytes + 4 > state.Length)
                {
                    return;
                }

                int pos = 60 + bitmapBytes;
                int stackCount = BinaryPrimitives.ReadInt32LittleEndian(state.AsSpan(pos));
                pos += 4;
                if (stackCount is < 0 or > RunVerify.MaxSiblings || pos + stackCount * 40 + 4 > state.Length)
                {
                    return;
                }

                long prefix = 0;
                for (int i = 0; i < stackCount; i++)
                {
                    long runs = BinaryPrimitives.ReadInt64LittleEndian(state.AsSpan(pos));
                    byte[] cv = state.AsSpan(pos + 8, RunVerify.CvSize).ToArray();
                    if (runs < 1 || prefix + runs >= runCount)
                    {
                        ResetRunState(); // the fold stack covers strictly less than the whole file
                        return;
                    }

                    RunVerify.LoadCv(cv, _runStack.AsSpan(8 * i, 8));
                    _runStackRuns[i] = runs;
                    prefix += runs;
                    pos += 40;
                }

                _runStackDepth = stackCount;
                int sparseCount = BinaryPrimitives.ReadInt32LittleEndian(state.AsSpan(pos));
                pos += 4;
                if (sparseCount is < 0 or > MaxResumableSparseRuns || pos + sparseCount * 40 != state.Length)
                {
                    ResetRunState();
                    return;
                }

                long highest = prefix - 1;
                for (int i = 0; i < sparseCount; i++)
                {
                    long runIndex = BinaryPrimitives.ReadInt64LittleEndian(state.AsSpan(pos));
                    if (runIndex <= prefix || runIndex >= runCount || _runSparse.ContainsKey(runIndex))
                    {
                        ResetRunState();
                        return;
                    }

                    _runSparse[runIndex] = state.AsSpan(pos + 8, RunVerify.CvSize).ToArray();
                    highest = Math.Max(highest, runIndex);
                    pos += 40;
                }

                // Cross-check the bitmap against the fold state before trusting it.
                for (long r = 0; r < runCount; r++)
                {
                    bool bit = (state[60 + r / 8] & (1 << (int)(r % 8))) != 0;
                    bool derived = r < prefix || _runSparse.ContainsKey(r);
                    if (bit != derived)
                    {
                        ResetRunState();
                        return;
                    }
                }

                // The data file must cover the highest committed run's extent; a
                // truncated data file voids the state (mirror of the v3 rule that a
                // short prefix restarts from zero).
                long extent = Math.Min(_totalBytes, (highest + 1) * RunVerify.RunChunks * Blake3.ChunkSize);
                if (highest < 0 || new FileInfo(Path.Combine(_partDir, "data")).Length < extent)
                {
                    ResetRunState();
                    return;
                }

                for (long r = 0; r < prefix; r++)
                {
                    _committedRuns[r] = true;
                }

                foreach (long r in _runSparse.Keys)
                {
                    _committedRuns[r] = true;
                }

                _runPrefix = prefix;

                long committedChunks = 0;
                for (long r = 0; r < _runCount; r++)
                {
                    if (_committedRuns[r])
                    {
                        long first = r * RunVerify.RunChunks;
                        int len = RunVerify.RunLength(r, _totalChunks);
                        committedChunks += len;
                        _committedBytes += Math.Min(_totalBytes, (first + len) * Blake3.ChunkSize) - first * Blake3.ChunkSize;
                    }
                }

                Applied = committedChunks;
                Resumed = committedChunks > 0;
                _runStateVersion = 1;
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException or UnauthorizedAccessException)
            {
                ResetRunState();
            }
        }

        private void ResetRunState()
        {
            _runSparse.Clear();
            Array.Clear(_committedRuns);
            Array.Clear(_runStack);
            Array.Clear(_runStackRuns);
            _runStackDepth = 0;
            _runPrefix = 0;
            _committedBytes = 0;
            Applied = 0;
            Resumed = false;
            _runStateVersion = 0;
        }

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

                // prefix is strictly below totalChunks, so every claimed chunk
                // is full-sized. Anything shorter restarts from zero.
                long onDisk = new FileInfo(Path.Combine(_partDir, "data")).Length;
                return onDisk >= prefix * Blake3.ChunkSize ? prefix : 0;
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                return 0;
            }
        }
    }

    internal sealed class MemorySink : Sink
    {
        // Directory manifests are the only memory sink; a lying Head can never size
        // the process's heap past this bound (terminal failure, not OOM).
        internal const long MaxManifestBytes = 64 * 1024 * 1024;

        private readonly Dictionary<long, byte[]> _received = new();
        private readonly Dictionary<long, byte[]> _applied = new();
        private bool[] _committedRuns = [];
        private bool _runMode;
        private long _totalBytes = -1;
        public byte[] Data { get; private set; } = Array.Empty<byte>();

        public override void UseVerifiedRuns() => _runMode = true;

        public override void Init(long totalBytes, long totalChunks)
        {
            _totalBytes = totalBytes;
            if (_runMode)
            {
                if (totalBytes > MaxManifestBytes)
                {
                    throw new InvalidDataException(
                        $"the manifest declares {totalBytes:N0} bytes, above the {MaxManifestBytes:N0} in-memory bound");
                }

                _committedRuns = new bool[RunVerify.RunCount(totalChunks)];
            }
        }

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

        public override void ApplyRun(long runIndex, int runLength, byte[][] chunks, byte[] runCv)
        {
            long first = runIndex * RunVerify.RunChunks;
            for (int i = 0; i < runLength; i++)
            {
                _applied[first + i] = chunks[i];
            }

            _committedRuns[runIndex] = true;
            Applied += runLength;
        }

        public override bool RunCommitted(long runIndex) => _committedRuns[runIndex];

        public override byte[] Complete()
        {
            var tree = new Blake3.Tree(retainOutboard: false);
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
