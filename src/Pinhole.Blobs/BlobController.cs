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

internal sealed class BlobController
{
    private const int ChunkBytes = BlobWire.MaxChunkData;
    private const long InitialWindow = 32 * ChunkBytes;  // 32 KiB probe start
    private const long MinimumWindow = 4 * ChunkBytes;
    private const long InitialPtoMs = 900;               // matches the recorded fixed-window baseline
    private const long PtoFloorMs = 150;
    private const long PtoCeilingMs = 3_000;
    private const long GranularityMs = 50;
    private const long MinRttMs = 20;                    // pacing never assumes better than 20 ms
    private const long NoSamplePacingRttMs = 100;
    private const long LossWindowFloorMs = 250;

    private readonly long _maxWindow;
    private readonly BlobFlowBudget _budget;
    private readonly BlobTransferStats? _stats;
    private readonly bool _fixedWindow; // the recorded #27 baseline behavior, for A/B runs

    private long _window;
    private long _ssthresh = long.MaxValue; // slow start until the first loss
    private long _inFlight;
    private long _fractionalGrowth;         // CA accumulator: ~1 chunk added per RTT

    private long _srttMs;
    private long _rttvarMs;
    private long _minRttMs = long.MaxValue; // the path's base delay; queueing only ever adds
    private bool _haveRtt;
    private double _ptoInflation = 1.0;     // duplicate pressure pushes the timer out
    private long _pacerCreditBytes;         // token bucket: burst credit, capped at one run
    private long _lastPacerMs = long.MinValue;
    private long _lossWindowStartMs;  // TickCount64 is positive; 0 is "the clock started now"
    private long _lastLossMs = -long.MaxValue / 2; // far past: the first reduction is never rate-limited
    private long _expiriesThisLossWindow;
    private bool _collapsePending;             // a loss collapse is awaiting its duplicate verdict
    private long _collapseExpiries;            // expiries the pending collapse consumed
    private long _preCollapseWindow;
    private long _preCollapseSsthresh;
    private long _spuriousVerdicts;            // +1 per dup-after-retransmit, -1 per fresh-after-retransmit
    private long _dupWindowStartMs;
    private long _lastDupMs;
    private long _dupWindowBytes;

    public BlobController(long maxWindowBytes, BlobFlowBudget budget, BlobTransferStats? stats, bool fixedWindow)
    {
        _maxWindow = Math.Max(maxWindowBytes, MinimumWindow);
        _budget = budget;
        _stats = stats;
        _fixedWindow = fixedWindow;
        _window = fixedWindow ? 4 * BlobWire.MaxRequestCount * ChunkBytes : Math.Min(InitialWindow, _maxWindow);
    }

    public long WindowBytes => _window;

    public void OnRequestSent()
    {
        if (_stats is not null) _stats.RequestsSent++;
    }

    public int MaxRunChunks => _fixedWindow
        ? BlobWire.MaxRequestCount
        : (int)Math.Clamp(_window / (8 * ChunkBytes), 2, BlobWire.MaxRequestCount);

    // The pacer runs on the caller's clock (D-02): both credit accrual points must
    // see the same timebase the control loop chose, not an ambient read that can
    // jump ahead of it.
    public int AffordableChunks(int desired, long nowMs)
    {
        if (_fixedWindow)
        {
            return desired;
        }

        AccruePacerCredit(nowMs);
        return (int)Math.Min(desired, _pacerCreditBytes / ChunkBytes);
    }

    public bool TryStartRun(long bytes, long nowMs)
    {
        if (_inFlight + bytes > _window)
        {
            return false;
        }

        if (!_fixedWindow)
        {
            AccruePacerCredit(nowMs);
            if (_pacerCreditBytes < bytes)
            {
                return false;
            }
        }

        if (!_budget.TryReserve(bytes))
        {
            return false;
        }

        if (!_fixedWindow)
        {
            _pacerCreditBytes -= bytes;
        }

        _inFlight += bytes;
        return true;
    }

    private void AccruePacerCredit(long nowMs)
    {
        // Slow start paces against the path's BASE delay (min RTT) so the window's
        // climb is not throttled by the very queue it is building. Congestion
        // avoidance paces at the smoothed RTT too — but queueing delay is
        // self-inflicted: letting a built queue stretch the pacing RTT without
        // bound collapses the issue rate quadratically (window halves AND the
        // divisor inflates — the observed 4 MiB starvation). Delay beyond 4× the
        // base is congestion EVIDENCE — it already halves the window — not a
        // pacing target, so SRTT's say is capped there.
        long pacingRtt = !_haveRtt ? NoSamplePacingRttMs
            : _window < _ssthresh ? Math.Max(Math.Min(_srttMs, _minRttMs), MinRttMs)
            : Math.Max(Math.Min(_srttMs, _minRttMs * 4), MinRttMs);
        long rateBytesPerMs = Math.Max(_window / pacingRtt, 1);
        long elapsed = _lastPacerMs == long.MinValue ? 0 : Math.Max(nowMs - _lastPacerMs, 0);
        _lastPacerMs = nowMs;
        long maxRunBytes = (long)MaxRunChunks * ChunkBytes;
        _pacerCreditBytes = Math.Min(_pacerCreditBytes + rateBytesPerMs * elapsed, maxRunBytes);
    }

    private long PtoBaseMs() => !_haveRtt
        ? InitialPtoMs
        : Math.Clamp(_srttMs + Math.Max(4 * _rttvarMs, GranularityMs), PtoFloorMs, PtoCeilingMs);

    public TimeSpan PtoFor(int retransmits)
    {
        if (_fixedWindow)
        {
            return TimeSpan.FromMilliseconds(InitialPtoMs);
        }

        long pto = (long)(PtoBaseMs() * Math.Min(1L << Math.Min(retransmits, 3), 8) * _ptoInflation);
        return TimeSpan.FromMilliseconds(Math.Min(pto, PtoCeilingMs * 8));
    }

    // The stats copy of this exists only when the app attached a sink; the
    // downloader's stall math must not depend on that option.
    public TimeSpan? SmoothedRtt => !_haveRtt ? null : TimeSpan.FromMilliseconds(_srttMs);

    public void OnChunkArrived(int chunkBytes, bool hadReservation, bool fresh, bool retransmitted, long nowMs)
    {
        if (hadReservation)
        {
            _inFlight -= chunkBytes;
            _budget.Release(chunkBytes);
        }

        if (!fresh)
        {
            if (_stats is not null)
            {
                _stats.DuplicateBytes += chunkBytes;
            }

            // A duplicate of a chunk we re-requested is a verdict on the expiry that
            // re-requested it: the original was in flight the whole time — the timer
            // fired on queueing delay (or a runner stall), not loss. Count it toward
            // undoing the collapse those expiries caused; the retransmission served
            // below is the wire cost already paid.
            if (retransmitted && _collapsePending)
            {
                _spuriousVerdicts++;
                TryRestoreSpuriousCollapse();
            }

            if (_dupWindowStartMs == 0)
            {
                _dupWindowStartMs = nowMs;
                _dupWindowBytes = 0;
            }

            _dupWindowBytes += chunkBytes;
            _lastDupMs = nowMs;

            // Duplicates beyond a quarter of the window inside one RTT mean the timer
            // fired early — the path was moving the data, slowly. Inflate the PTO rather
            // than shrinking the window: the loss signal proper is OnRetransmit's.
            if (_dupWindowBytes > _window / 4)
            {
                _ptoInflation = Math.Min(_ptoInflation * 1.5, 4.0);
                _dupWindowStartMs = nowMs;
                _dupWindowBytes = 0;
            }

            return;
        }

        // The retransmission delivered what the original never did: a real-loss vote
        // against restoring the collapse those expiries caused.
        if (retransmitted && _collapsePending)
        {
            _spuriousVerdicts--;
        }

        if (_stats is not null)
        {
            _stats.VerifiedBytes += chunkBytes;
        }

        if (_fixedWindow)
        {
            return;
        }

        Grow(chunkBytes);
        if (_ptoInflation > 1.0 && _lastDupMs > 0 && nowMs - _lastDupMs > 3 * Math.Max(_srttMs, LossWindowFloorMs))
        {
            // A full loss window with zero duplicates is a clean bill: the timer
            // relaxation is immediate, not a slow crawl — an early bad orbit must not
            // latch high PTOs for the rest of the transfer.
            _ptoInflation = 1.0;
        }
    }

    public void ObserveRtt(TimeSpan rtt)
    {
        if (_fixedWindow)
        {
            return;
        }

        long sample = Math.Max((long)rtt.TotalMilliseconds, 1);
        _minRttMs = Math.Min(_minRttMs, sample);
        if (!_haveRtt)
        {
            _srttMs = sample;
            _rttvarMs = sample / 2;
            _haveRtt = true;
        }
        else
        {
            long err = Math.Abs(sample - _srttMs);
            _rttvarMs = (3 * _rttvarMs + err) / 4;
            _srttMs = (7 * _srttMs + sample) / 8;
        }

        if (_stats is not null)
        {
            _stats.SmoothedRtt = TimeSpan.FromMilliseconds(_srttMs);
        }
    }

    private void Grow(int chunkBytes)
    {
        if (_window < _ssthresh)
        {
            _window = Math.Min(_window + chunkBytes, _maxWindow); // slow start: doubles per RTT
        }
        else
        {
            _fractionalGrowth += (long)Math.Max((double)chunkBytes * chunkBytes / _window, 1);
            if (_fractionalGrowth >= ChunkBytes)
            {
                _window = Math.Min(_window + _fractionalGrowth / ChunkBytes * ChunkBytes, _maxWindow);
                _fractionalGrowth %= ChunkBytes;
            }
        }

        if (_stats is not null)
        {
            _stats.WindowBytes = _window;
        }
    }

    public void OnRetransmit(long nowMs)
    {
        if (_stats is not null)
        {
            _stats.Retransmits++;
        }

        if (_fixedWindow)
        {
            return;
        }

        long lossWindow = Math.Max(_srttMs, LossWindowFloorMs);
        if (nowMs - _lossWindowStartMs >= lossWindow)
        {
            _lossWindowStartMs = nowMs;
            _expiriesThisLossWindow = 0;
        }

        _expiriesThisLossWindow++;
        bool delayStanding = _haveRtt && _srttMs * 5 >= _minRttMs * 8; // ≥ 1.6× base delay
        // A standing queue is exactly what a deep buffer builds, so under delayStanding
        // a PTO expiry is weaker loss evidence than on a clean path: it may be queueing
        // delay (or a slow runner's scheduling stall) rather than a dropped frame. Two
        // expiries still collapse — real overflow drops clusters, not single frames.
        long collapseQuorum = delayStanding ? 2 : 3;
        if (_expiriesThisLossWindow < collapseQuorum)
        {
            return; // scattered loss: heal it, the window stands
        }

        if (nowMs - _lastLossMs < lossWindow)
        {
            return; // already reduced inside this loss window
        }

        _lastLossMs = nowMs;
        _preCollapseWindow = _window;
        _preCollapseSsthresh = _ssthresh;
        _collapseExpiries = _expiriesThisLossWindow;
        _spuriousVerdicts = 0;
        _collapsePending = true;
        _expiriesThisLossWindow = 0;
        if (_stats is not null)
        {
            _stats.LossEvents++;
        }

        _ssthresh = Math.Max(_window / 2, 2 * MinimumWindow);
        // Halve INTO the reduction (window below the new threshold) so slow start
        // rebounds exponentially to the threshold instead of crawling linearly from
        // it — a lossy path collapses shallower and recovers faster.
        _window = Math.Max(_ssthresh / 2, MinimumWindow);
        if (_stats is not null)
        {
            _stats.WindowBytes = _window;
        }

        BlobTestHooks.Trace?.Invoke(
            $"ctrl collapse window={_window} from={_preCollapseWindow} expiries={_collapseExpiries} " +
            $"standing={delayStanding} srtt={_srttMs} minRtt={_minRttMs} ptoInflate={_ptoInflation:0.0}");
    }

    // Half the expiries behind a collapse arriving as duplicates overturns it: the
    // flight those expiries buried was moving, and the window's dip (a quarter of
    // what it was) plus the linear congestion-avoidance climb back is pure
    // self-inflicted under-utilization on a path that never lost anything.
    private void TryRestoreSpuriousCollapse()
    {
        if (_spuriousVerdicts < Math.Max(_collapseExpiries / 2, 1))
        {
            return;
        }

        _window = Math.Min(_preCollapseWindow, _maxWindow);
        _ssthresh = _preCollapseSsthresh;
        _collapsePending = false;
        long verdicts = _spuriousVerdicts;
        _spuriousVerdicts = 0;
        if (_stats is not null)
        {
            _stats.RestoredWindows++;
            _stats.WindowBytes = _window;
        }

        BlobTestHooks.Trace?.Invoke(
            $"ctrl restore window={_window} expiries={_collapseExpiries} verdicts={verdicts} " +
            $"ptoInflate={_ptoInflation:0.0}");
    }

    public void OnPathChanged()
    {
        if (_fixedWindow)
        {
            return;
        }

        _haveRtt = false;
        _srttMs = 0;
        _rttvarMs = 0;
        _minRttMs = long.MaxValue;
        _fractionalGrowth = 0;
        _window = Math.Min(InitialWindow, _maxWindow);
        _ssthresh = long.MaxValue;
        _ptoInflation = 1.0;
        _dupWindowBytes = 0;
        _dupWindowStartMs = 0;
        _lastDupMs = 0;
        _pacerCreditBytes = 0;
        _lastPacerMs = long.MinValue;
        _lossWindowStartMs = 0;
        _expiriesThisLossWindow = 0;
        _collapsePending = false;
        _collapseExpiries = 0;
        _spuriousVerdicts = 0;
        _lastLossMs = -long.MaxValue / 2;
        if (_stats is not null)
        {
            _stats.ConservativeResumes++;
            _stats.SmoothedRtt = null;
            _stats.WindowBytes = _window;
        }
    }

    public void ReleaseReservation(long chunkBytes)
    {
        _inFlight -= chunkBytes;
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
