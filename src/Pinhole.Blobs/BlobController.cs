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

        return false;
    }

    internal void Release(long bytes) => Interlocked.Add(ref _used, -bytes);

    internal long UsedBytes => Interlocked.Read(ref _used);
}

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

    internal long BudgetReservedBytes => _budget.UsedBytes;

    internal long PacerInFlightBytes => _pacer.InFlight;

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

        if (!_budget.TryReserve(bytes))
        {
            return false;
        }

        PacerMachine.CommitStartRun(ref _pacer, bytes);
        return true;
    }

    public TimeSpan PtoFor(int retransmits) =>
        TimeSpan.FromMilliseconds(PacerMachine.PtoMs(in _pacer, retransmits));

    public TimeSpan? SmoothedRtt => !_pacer.HaveRtt ? null : TimeSpan.FromMilliseconds(_pacer.SrttMs);

    public void OnChunkArrived(int chunkBytes, bool hadReservation, bool fresh, bool retransmitted, long nowMs, long index)
    {
        if (hadReservation)
        {
            PacerMachine.ReleaseReservation(ref _pacer, chunkBytes);
            _budget.Release(chunkBytes);
        }

        PacerEvent verdict = PacerMachine.OnChunkArrived(ref _pacer, chunkBytes, fresh, retransmitted, nowMs, index);
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

    public static bool ForceFixedWindow
    {
        get => Override.Value ?? DefaultFixedWindow;
        set => Override.Value = value;
    }

    private static readonly AsyncLocal<Action<string>?> TraceSink = new();

    public static Action<string>? Trace
    {
        get => TraceSink.Value;
        set => TraceSink.Value = value;
    }

    private static readonly AsyncLocal<Action<long, long, long>?> LedgerSink = new();

    public static Action<long, long, long>? Ledger
    {
        get => LedgerSink.Value;
        set => LedgerSink.Value = value;
    }
}
