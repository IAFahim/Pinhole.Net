namespace Pinhole.Blobs;

/// <summary>Per-download transfer accounting, filled in live by the downloader when
/// supplied via <see cref="BlobDownloadOptions.Stats"/>. These are the numbers the
/// congestion controller is judged by: wire load is measured as bytes that actually
/// arrived (verified plus duplicate), never as request credits issued.</summary>
public sealed class BlobTransferStats
{
    /// <summary>Chunk bytes verified and applied (fresh arrivals only).</summary>
    public long VerifiedBytes { get; internal set; }

    /// <summary>Chunk bytes that arrived for an index already held — retransmission
    /// waste on the wire, counted even though it verified nothing.</summary>
    public long DuplicateBytes { get; internal set; }

    /// <summary>Total chunk bytes received (verified + duplicate): the real
    /// provider-response load this download put on the path.</summary>
    public long ReceivedBytes => VerifiedBytes + DuplicateBytes;

    /// <summary>Req frames sent (new runs and re-requests alike).</summary>
    public long RequestsSent { get; internal set; }

    /// <summary>Individual re-request frames sent for chunks that passed their
    /// retransmission timer without arriving.</summary>
    public long Retransmits { get; internal set; }

    /// <summary>Distinct loss windows in which the congestion window was reduced.</summary>
    public long LossEvents { get; internal set; }

    /// <summary>Conservative resume events: path migrations and recoveries from
    /// sustained pathlessness, each of which resets the window to its floor.</summary>
    public long ConservativeResumes { get; internal set; }

    /// <summary>Smoothed round-trip time at the latest sample; null before the first
    /// clean sample.</summary>
    public TimeSpan? SmoothedRtt { get; internal set; }

    /// <summary>The window (bytes) at the latest adjustment.</summary>
    public long WindowBytes { get; internal set; }
}

/// <summary>Process-wide cap on total in-flight blob bytes shared by every download in
/// this process. Per-download windows bound each flow; this budget bounds the aggregate,
/// so opening more simultaneous downloads divides a fixed pie instead of multiplying one.
/// Downloads join <see cref="Shared"/> unless given their own.</summary>
public sealed class BlobFlowBudget
{
    /// <summary>The default budget every download joins: 8 MiB of outstanding chunk
    /// bytes process-wide (eight saturated fat-path downloads' worth, and a modest
    /// footprint next to the engine's per-node receive buffering).</summary>
    public static BlobFlowBudget Shared { get; } = new(8 * 1024 * 1024);

    private long _used;

    /// <summary>Total outstanding bytes this budget admits across all joining downloads.</summary>
    public long CapacityBytes { get; }

    /// <param name="capacityBytes">Total bytes that may be outstanding across all joining
    /// downloads. At least 64 KiB — a budget smaller than one minimum window cannot admit
    /// a single run and only deadlocks.</param>
    public BlobFlowBudget(long capacityBytes)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacityBytes, 64 * 1024);
        CapacityBytes = capacityBytes;
    }

    internal bool TryReserve(long bytes)
    {
        if (Interlocked.Add(ref _used, bytes) <= CapacityBytes)
        {
            return true;
        }

        Interlocked.Add(ref _used, -bytes);
        return false;
    }

    internal void Release(long bytes) => Interlocked.Add(ref _used, -bytes);

    internal long UsedBytes => Interlocked.Read(ref _used);
}

/// <summary>The receiver-side congestion controller for one blob stream: a byte-based
/// window under slow-start/AIMD, a retransmission timer derived from measured RTT
/// (SRTT/RTTVAR, RFC 6298/9002-shaped; Karn's rule keeps retransmitted chunks from
/// polluting the estimate), a leaky-bucket pacer so runs leave at window rate rather
/// than back-to-back, duplicate-response accounting as a too-early-timer signal, and a
/// conservative reset on path migration or sustained pathlessness. Receiver-driven by
/// construction: the requests this paces are the only thing that pulls data onto the
/// wire. The wire itself is unchanged — no new frames, no version bump; a
/// controller-mode downloader talks to any v3 provider, and vice versa.</summary>
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
    private long _dupWindowStartMs;
    private long _lastDupMs;
    private long _dupWindowBytes;

    public BlobController(long maxWindowBytes, BlobFlowBudget budget, BlobTransferStats? stats, bool fixedWindow)
    {
        _maxWindow = Math.Max(maxWindowBytes, MinimumWindow);
        _budget = budget;
        _stats = stats;
        _fixedWindow = fixedWindow;
        _window = fixedWindow ? 4 * BlobWire.MaxRequestCount * ChunkBytes : InitialWindow;
    }

    public long WindowBytes => _window;

    /// <summary>How many chunks a single Req run may carry: grows with the window so a
    /// fat path batches and a thin one stays deferential — every run is a back-to-back
    /// provider burst, so its size is a burst bound. The granularity stays at most a
    /// sixteenth of the window, so admission never strands a large fraction of a small
    /// window waiting for a whole oversized run.</summary>
    public int MaxRunChunks => _fixedWindow
        ? BlobWire.MaxRequestCount
        : (int)Math.Clamp(_window / (8 * ChunkBytes), 2, BlobWire.MaxRequestCount);

    /// <summary>How many chunks the pacer's current credit can pay for right now, capped
    /// at <paramref name="desired"/>: the caller sizes each run to the credit actually
    /// available instead of blocking until a full run's worth accumulates, so issuance
    /// tracks the pacing rate smoothly rather than in whole-run jumps.</summary>
    public int AffordableChunks(int desired)
    {
        if (_fixedWindow)
        {
            return desired;
        }

        AccruePacerCredit(Environment.TickCount64);
        return (int)Math.Min(desired, _pacerCreditBytes / ChunkBytes);
    }

    /// <summary>Admission for one request (a new run or a single re-request) of exactly
    /// <paramref name="bytes"/> of chunk data: needs window room, pacer credit, then
    /// aggregate-budget room. On success the bytes are reserved per-stream and
    /// process-wide. The pacer is a token bucket filled at window rate (window bytes per
    /// RTT, so the whole window could leave once per RTT) with burst credit capped at
    /// one run — requests may leave back-to-back while credit lasts, then wait.</summary>
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

            _pacerCreditBytes -= bytes;
        }

        if (!_budget.TryReserve(bytes))
        {
            return false;
        }

        _inFlight += bytes;
        return true;
    }

    private void AccruePacerCredit(long nowMs)
    {
        // Slow start paces against the path's BASE delay (min RTT) so the window's
        // climb is not throttled by the very queue it is building; congestion
        // avoidance paces against the smoothed RTT, queueing included.
        long pacingRtt = !_haveRtt ? NoSamplePacingRttMs
            : _window < _ssthresh ? Math.Max(Math.Min(_srttMs, _minRttMs), MinRttMs)
            : Math.Max(_srttMs, MinRttMs);
        long rateBytesPerMs = Math.Max(_window / pacingRtt, 1);
        long elapsed = _lastPacerMs == long.MinValue ? 0 : Math.Max(nowMs - _lastPacerMs, 0);
        _lastPacerMs = nowMs;
        long maxRunBytes = (long)MaxRunChunks * ChunkBytes;
        _pacerCreditBytes = Math.Min(_pacerCreditBytes + rateBytesPerMs * elapsed, maxRunBytes);
    }

    private long PtoBaseMs() => !_haveRtt
        ? InitialPtoMs
        : Math.Clamp(_srttMs + Math.Max(4 * _rttvarMs, GranularityMs), PtoFloorMs, PtoCeilingMs);

    /// <summary>The retransmission timer for a chunk already re-sent
    /// <paramref name="retransmits"/> times without arriving: base PTO with doubling
    /// backoff and the duplicate-pressure inflation, so one stuck chunk cannot spin at
    /// the floor rate forever.</summary>
    public TimeSpan PtoFor(int retransmits)
    {
        if (_fixedWindow)
        {
            return TimeSpan.FromMilliseconds(InitialPtoMs);
        }

        long pto = (long)(PtoBaseMs() * Math.Min(1L << Math.Min(retransmits, 3), 8) * _ptoInflation);
        return TimeSpan.FromMilliseconds(Math.Min(pto, PtoCeilingMs * 8));
    }

    /// <summary>A chunk arrived. <paramref name="hadReservation"/>: this arrival matched
    /// an outstanding request, so its bytes come back (per-stream window and process
    /// budget). <paramref name="fresh"/>: the sink did not already hold it; when false
    /// the bytes are duplicates on the wire and feed the too-early-timer signal.</summary>
    public void OnChunkArrived(int chunkBytes, bool hadReservation, bool fresh, long nowMs)
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

    /// <summary>RTT observation from the downloader (request send time to arrival, clean
    /// samples only, enforced by the caller per Karn's rule).</summary>
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

    /// <summary>A re-request is going out for a chunk whose timer expired. A single
    /// expiry is evidence of scattered random loss, not congestion — re-request and move
    /// on. The window halves (at most once per loss window, RFC 6675-style) only when the
    /// expiries show congestion's signature: several inside one window (a burst died
    /// together — queue overflow) or standing delay well above the path's base RTT (a
    /// queue has been building). Without this gate, steady 5% random loss would ratchet
    /// the window to its floor and never climb back.</summary>
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
        if (_expiriesThisLossWindow < 3 && !delayStanding)
        {
            return; // scattered loss: heal it, the window stands
        }

        if (nowMs - _lastLossMs < lossWindow)
        {
            return; // already reduced inside this loss window
        }

        _lastLossMs = nowMs;
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
    }

    /// <summary>The path changed under the transfer (migration, or return from
    /// sustained pathlessness): the old path's RTT samples and confirmed window
    /// described a world that no longer exists. Resume conservatively — initial window,
    /// clean timers — and re-earn the rate; a stale estimate flooding a fresh path is
    /// exactly what RFC 9002's migration rules exist to prevent.</summary>
    public void OnPathChanged()
    {
        if (_fixedWindow)
        {
            return;
        }

        _haveRtt = false;
        _minRttMs = long.MaxValue;
        _window = InitialWindow;
        _ptoInflation = 1.0;
        _dupWindowBytes = 0;
        _dupWindowStartMs = 0;
        _pacerCreditBytes = 0;
        _lossWindowStartMs = 0;
        _lastLossMs = -long.MaxValue / 2;
        if (_stats is not null)
        {
            _stats.ConservativeResumes++;
            _stats.WindowBytes = _window;
        }
    }

    /// <summary>Admission for one retransmission. Recovery is timer-paced, not
    /// window-paced: a lost chunk's original reservation legitimately holds window room
    /// until it arrives, so gating its re-request on the same window would deadlock —
    /// the lost bytes can never be re-asked for. The aggregate budget still bounds total
    /// outstanding bytes, and the PTO's doubling backoff bounds each chunk's retry rate,
    /// so recovery traffic is bounded without competing with fresh requests for
    /// admission.</summary>
    public bool TryStartRecovery(long bytes) => _budget.TryReserve(bytes);

    /// <summary>A recovery reservation came home (or the stream is ending): release its
    /// share of the process-wide budget.</summary>
    public void OnRecoverySettled(long bytes) => _budget.Release(bytes);

    /// <summary>Gives back one reservation without an arrival — the stream is ending
    /// (done, stalled, or cancelled) and must release its share of the window and of the
    /// process-wide budget.</summary>
    public void ReleaseReservation(long chunkBytes)
    {
        _inFlight -= chunkBytes;
        _budget.Release(chunkBytes);
    }
}

/// <summary>Test/diagnostic seam: forces the recorded #27 fixed-window behavior (a
/// constant 4×64-chunk window, the flat 900 ms re-request timer, no pacing, no backoff)
/// so same-machine A/B comparisons against the baseline can be re-run. Set the
/// PINHOLE_BLOB_FIXED_WINDOW=1 environment variable before the process starts.</summary>
internal static class BlobTestHooks
{
    public static bool ForceFixedWindow { get; set; } =
        Environment.GetEnvironmentVariable("PINHOLE_BLOB_FIXED_WINDOW") is "1";
}
