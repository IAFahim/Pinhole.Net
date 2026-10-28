using Pinhole.Core;

namespace Pinhole.Blobs;

public sealed class BlobTransferStats
{
    public long VerifiedBytes { get; internal set; }

    public long DuplicateBytes { get; internal set; }

    public long ReceivedBytes => VerifiedBytes + DuplicateBytes;

    public long RequestsSent { get; internal set; }

    public long Retransmits { get; internal set; }

    public long LossEvents { get; internal set; }

    public long RestoredWindows { get; internal set; }

    public long ConservativeResumes { get; internal set; }

    public TimeSpan? SmoothedRtt { get; internal set; }

    public long WindowBytes { get; internal set; }
}

public sealed class BlobFlowBudget
{
    public static BlobFlowBudget Shared { get; } = new(8 * 1024 * 1024);

    private long _used;

    public long CapacityBytes { get; }

    public BlobFlowBudget(long capacityBytes)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacityBytes, 64 * 1024);
        CapacityBytes = capacityBytes;
    }

    internal bool TryReserve(long bytes)
    {
        long used = Interlocked.Read(ref _used);
        while (bytes <= CapacityBytes - used)
        {
            long observed = Interlocked.CompareExchange(ref _used, used + bytes, used);
            if (observed == used) return true;
            used = observed;
        }
        // Failed reservations never become visible in the ledger, even briefly.
        return false;
    }

    internal void Release(long bytes) => Interlocked.Add(ref _used, -bytes);

    internal long UsedBytes => Interlocked.Read(ref _used);
}

// The I/O half of the congestion controller: it owns the stats sink, the trace
// lines, and the shared BlobFlowBudget reservation, and delegates every window,
// RTT, PTO, and pacing DECISION to the sans-IO PacerMachine (Pinhole.Core).
internal sealed class BlobController
{
    private readonly BlobFlowBudget _budget;
    private readonly BlobTransferStats? _stats;
    private PacerState _pacer;

    public BlobController(long maxWindowBytes, BlobFlowBudget budget, BlobTransferStats? stats, bool fixedWindow)
    {
        _budget = budget;
        _stats = stats;
        _pacer = PacerState.Create(BlobWire.MaxChunkData, BlobWire.MaxRequestCount, maxWindowBytes, fixedWindow);
    }

    public long WindowBytes => _pacer.Window;

    public void OnRequestSent()
    {
        if (_stats is not null) _stats.RequestsSent++;
    }

    public int MaxRunChunks => PacerMachine.MaxRunChunks(in _pacer);

    public int AffordableChunks(int desired, long nowMs) =>
        PacerMachine.AffordableChunks(ref _pacer, desired, nowMs);

    public bool TryStartRun(long bytes, long nowMs)
    {
        if (!PacerMachine.CanStartRun(ref _pacer, bytes, nowMs))
        {
            return false;
        }

        // A refused reservation must not burn pacer credit (A-11): the commit that
        // deducts it only runs after the budget said yes.
        if (!_budget.TryReserve(bytes))
        {
            return false;
        }

        PacerMachine.CommitStartRun(ref _pacer, bytes);
        return true;
    }

    public TimeSpan PtoFor(int retransmits) =>
        TimeSpan.FromMilliseconds(PacerMachine.PtoMs(in _pacer, retransmits));

    // The stats copy of this exists only when the app attached a sink; the
    // downloader's stall math must not depend on that option.
    public TimeSpan? SmoothedRtt => !_pacer.HaveRtt ? null : TimeSpan.FromMilliseconds(_pacer.SrttMs);

    public void OnChunkArrived(int chunkBytes, bool hadReservation, bool fresh, bool retransmitted, long nowMs)
    {
        if (hadReservation)
        {
            PacerMachine.ReleaseReservation(ref _pacer, chunkBytes);
            _budget.Release(chunkBytes);
        }

        PacerEvent verdict = PacerMachine.OnChunkArrived(ref _pacer, chunkBytes, fresh, retransmitted, nowMs);
        if (_stats is not null)
        {
            if (fresh)
            {
                _stats.VerifiedBytes += chunkBytes;
            }
            else
            {
                _stats.DuplicateBytes += chunkBytes;
            }

            if (verdict.Kind == PacerEventKind.Restored)
            {
                _stats.RestoredWindows++;
                _stats.WindowBytes = _pacer.Window;
            }
            else if (fresh && !_pacer.FixedWindow)
            {
                _stats.WindowBytes = _pacer.Window;
            }
        }

        if (verdict.Kind == PacerEventKind.Restored)
        {
            BlobTestHooks.Trace?.Invoke(
                $"ctrl restore window={_pacer.Window} expiries={_pacer.CollapseExpiries} verdicts={verdict.Verdicts} " +
                $"ptoInflate={_pacer.PtoInflation:0.0}");
        }
    }

    public void ObserveRtt(TimeSpan rtt)
    {
        PacerMachine.ObserveRtt(ref _pacer, rtt);
        if (_stats is not null && _pacer.HaveRtt)
        {
            _stats.SmoothedRtt = TimeSpan.FromMilliseconds(_pacer.SrttMs);
        }
    }

    public void OnRetransmit(long nowMs)
    {
        if (_stats is not null)
        {
            _stats.Retransmits++;
        }

        if (PacerMachine.OnRetransmit(ref _pacer, nowMs).Kind != PacerEventKind.Collapsed)
        {
            return;
        }

        if (_stats is not null)
        {
            _stats.LossEvents++;
            _stats.WindowBytes = _pacer.Window;
        }

        BlobTestHooks.Trace?.Invoke(
            $"ctrl collapse window={_pacer.Window} from={_pacer.PreCollapseWindow} expiries={_pacer.CollapseExpiries} " +
            $"standing={PacerMachine.StandingQueue(in _pacer)} srtt={_pacer.SrttMs} minRtt={_pacer.MinRttMs} " +
            $"ptoInflate={_pacer.PtoInflation:0.0}");
    }

    public void OnPathChanged()
    {
        if (!PacerMachine.OnPathChanged(ref _pacer))
        {
            return;
        }

        if (_stats is not null)
        {
            _stats.ConservativeResumes++;
            _stats.SmoothedRtt = null;
            _stats.WindowBytes = _pacer.Window;
        }
    }

    public void ReleaseReservation(long chunkBytes)
    {
        PacerMachine.ReleaseReservation(ref _pacer, chunkBytes);
        _budget.Release(chunkBytes);
    }
}

internal static class BlobTestHooks
{
    private static readonly bool DefaultFixedWindow =
        Environment.GetEnvironmentVariable("PINHOLE_BLOB_FIXED_WINDOW") is "1";
    private static readonly AsyncLocal<bool?> Override = new();

    // An A/B run must not change unrelated transfers executing in parallel tests.
    public static bool ForceFixedWindow
    {
        get => Override.Value ?? DefaultFixedWindow;
        set => Override.Value = value;
    }

    // CI forensics for hangs local runs cannot reproduce: when set, the downloader's
    // control loop drops a one-line state snapshot here a few times per second.
    // AsyncLocal for the same reason as ForceFixedWindow — parallel blob tests must
    // never cross-write each other's timeline.
    private static readonly AsyncLocal<Action<string>?> TraceSink = new();

    public static Action<string>? Trace
    {
        get => TraceSink.Value;
        set => TraceSink.Value = value;
    }
}
