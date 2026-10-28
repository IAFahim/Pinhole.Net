namespace Pinhole.Core;

public enum PacerEventKind : byte
{
    None = 0,
    Collapsed = 1, // a loss window collapsed the window; the pre-collapse figures stay in state
    Restored = 2,  // duplicates overturned a pending collapse
}

public struct PacerEvent
{
    public PacerEventKind Kind;
    public long Verdicts; // Restored: the spurious-verdict count that met the quorum (state resets it)
}

// The blob downloader's congestion controller, decision half: congestion window with
// slow start and congestion avoidance, RTT EWMA, PTO computation and duplicate
// inflation, loss-window collapse with spurious-restore verdicts, and the pacer token
// bucket. The BlobController shell owns the stats sink, the trace lines, and the
// shared BlobFlowBudget reservation around these decisions.
public struct PacerState
{
    // Shell-supplied configuration.
    public int ChunkBytes;      // one chunk's payload; every byte figure is counted in these
    public int MaxRequestCount; // the wire's per-request run cap; also the pacer's burst cap
    public long MaxWindow;      // hard ceiling for Window (already clamped to the minimum)
    public bool FixedWindow;    // the recorded #27 baseline behavior: adapt nothing, measure only

    // Congestion window.
    public long Window;
    public long Ssthresh;           // slow start until the first loss
    public long InFlight;
    public long FractionalGrowth;   // CA accumulator: ~1 chunk added per RTT

    // RTT EWMA.
    public long SrttMs;
    public long RttvarMs;
    public long MinRttMs;           // the path's base delay; queueing only ever adds
    public bool HaveRtt;

    // PTO.
    public double PtoInflation;     // duplicate pressure pushes the timer out

    // Pacer token bucket: burst credit, capped at one run.
    public long PacerCreditBytes;
    public long LastPacerMs;

    // Loss window.
    public long LossWindowStartMs;  // TickCount64 is positive; 0 is "the clock started now"
    public long LastLossMs;         // far past: the first reduction is never rate-limited
    public long ExpiriesThisLossWindow;

    // Collapse verdicts.
    public bool CollapsePending;    // a loss collapse is awaiting its duplicate verdict
    public long CollapseExpiries;   // expiries the pending collapse consumed
    public long PreCollapseWindow;
    public long PreCollapseSsthresh;
    public long SpuriousVerdicts;   // +1 per dup-after-retransmit, -1 per fresh-after-retransmit
    public long DupWindowStartMs;
    public long LastDupMs;
    public long DupWindowBytes;

    public static PacerState Create(int chunkBytes, int maxRequestCount, long maxWindowBytes, bool fixedWindow)
    {
        PacerState s = default;
        s.ChunkBytes = chunkBytes;
        s.MaxRequestCount = maxRequestCount;
        s.FixedWindow = fixedWindow;
        s.MaxWindow = Math.Max(maxWindowBytes, 4L * chunkBytes);
        s.Ssthresh = long.MaxValue;
        s.MinRttMs = long.MaxValue;
        s.PtoInflation = 1.0;
        s.LastPacerMs = long.MinValue;
        s.LastLossMs = -long.MaxValue / 2;
        s.Window = fixedWindow ? 4L * maxRequestCount * chunkBytes : Math.Min(32L * chunkBytes, s.MaxWindow);
        return s;
    }
}

public static class PacerMachine
{
    public const long InitialPtoMs = 900;  // matches the recorded fixed-window baseline
    public const long PtoFloorMs = 150;
    public const long PtoCeilingMs = 3_000;
    public const long GranularityMs = 50;
    public const long MinRttMs = 20;       // pacing never assumes better than 20 ms
    public const long NoSamplePacingRttMs = 100;
    public const long LossWindowFloorMs = 250;

    public static int MaxRunChunks(in PacerState s) => s.FixedWindow
        ? s.MaxRequestCount
        : (int)Math.Clamp(s.Window / (8L * s.ChunkBytes), 2, s.MaxRequestCount);

    // The pacer runs on the caller's clock (D-02): both credit accrual points must
    // see the same timebase the control loop chose, not an ambient read that can
    // jump ahead of it.
    public static int AffordableChunks(ref PacerState s, int desired, long nowMs)
    {
        if (s.FixedWindow)
        {
            return desired;
        }

        AccruePacerCredit(ref s, nowMs);
        return (int)Math.Min(desired, s.PacerCreditBytes / s.ChunkBytes);
    }

    // The window/pacer half of TryStartRun: false when the congestion window or the
    // pacer credit refuses the run (an accrual that happened on the way persists,
    // exactly as it did before the budget was asked). CommitStartRun consumes the
    // credit only after the shell's budget reservation succeeded.
    public static bool CanStartRun(ref PacerState s, long bytes, long nowMs)
    {
        if (s.InFlight + bytes > s.Window)
        {
            return false;
        }

        if (!s.FixedWindow)
        {
            AccruePacerCredit(ref s, nowMs);
            if (s.PacerCreditBytes < bytes)
            {
                return false;
            }
        }

        return true;
    }

    public static void CommitStartRun(ref PacerState s, long bytes)
    {
        if (!s.FixedWindow)
        {
            s.PacerCreditBytes -= bytes;
        }

        s.InFlight += bytes;
    }

    public static void ReleaseReservation(ref PacerState s, long chunkBytes)
    {
        s.InFlight -= chunkBytes;
    }

    private static void AccruePacerCredit(ref PacerState s, long nowMs)
    {
        // Slow start paces against the path's BASE delay (min RTT) so the window's
        // climb is not throttled by the very queue it is building. Congestion
        // avoidance paces at the smoothed RTT too — but queueing delay is
        // self-inflicted: letting a built queue stretch the pacing RTT without
        // bound collapses the issue rate quadratically (window halves AND the
        // divisor inflates — the observed 4 MiB starvation). Delay beyond 4× the
        // base is congestion EVIDENCE — it already halves the window — not a
        // pacing target, so SRTT's say is capped there.
        long pacingRtt = !s.HaveRtt ? NoSamplePacingRttMs
            : s.Window < s.Ssthresh ? Math.Max(Math.Min(s.SrttMs, s.MinRttMs), MinRttMs)
            : Math.Max(Math.Min(s.SrttMs, s.MinRttMs * 4), MinRttMs);
        long rateBytesPerMs = Math.Max(s.Window / pacingRtt, 1);
        long elapsed = s.LastPacerMs == long.MinValue ? 0 : Math.Max(nowMs - s.LastPacerMs, 0);
        s.LastPacerMs = nowMs;
        long maxRunBytes = (long)MaxRunChunks(in s) * s.ChunkBytes;
        s.PacerCreditBytes = Math.Min(s.PacerCreditBytes + rateBytesPerMs * elapsed, maxRunBytes);
    }

    private static long PtoBaseMs(in PacerState s) => !s.HaveRtt
        ? InitialPtoMs
        : Math.Clamp(s.SrttMs + Math.Max(4 * s.RttvarMs, GranularityMs), PtoFloorMs, PtoCeilingMs);

    public static long PtoMs(in PacerState s, int retransmits)
    {
        if (s.FixedWindow)
        {
            return InitialPtoMs;
        }

        long pto = (long)(PtoBaseMs(in s) * Math.Min(1L << Math.Min(retransmits, 3), 8) * s.PtoInflation);
        return Math.Min(pto, PtoCeilingMs * 8);
    }

    public static PacerEvent OnChunkArrived(ref PacerState s, int chunkBytes, bool fresh, bool retransmitted, long nowMs)
    {
        if (!fresh)
        {
            PacerEvent verdict = default;

            // A duplicate of a chunk we re-requested is a verdict on the expiry that
            // re-requested it: the original was in flight the whole time — the timer
            // fired on queueing delay (or a runner stall), not loss. Count it toward
            // undoing the collapse those expiries caused; the retransmission served
            // below is the wire cost already paid.
            if (retransmitted && s.CollapsePending)
            {
                s.SpuriousVerdicts++;
                verdict = TryRestoreSpuriousCollapse(ref s);
            }

            if (s.DupWindowStartMs == 0)
            {
                s.DupWindowStartMs = nowMs;
                s.DupWindowBytes = 0;
            }

            s.DupWindowBytes += chunkBytes;
            s.LastDupMs = nowMs;

            // Duplicates beyond a quarter of the window inside one RTT mean the timer
            // fired early — the path was moving the data, slowly. Inflate the PTO rather
            // than shrinking the window: the loss signal proper is OnRetransmit's.
            if (s.DupWindowBytes > s.Window / 4)
            {
                s.PtoInflation = Math.Min(s.PtoInflation * 1.5, 4.0);
                s.DupWindowStartMs = nowMs;
                s.DupWindowBytes = 0;
            }

            return verdict;
        }

        // The retransmission delivered what the original never did: a real-loss vote
        // against restoring the collapse those expiries caused.
        if (retransmitted && s.CollapsePending)
        {
            s.SpuriousVerdicts--;
        }

        if (s.FixedWindow)
        {
            return default;
        }

        Grow(ref s, chunkBytes);
        if (s.PtoInflation > 1.0 && s.LastDupMs > 0 && nowMs - s.LastDupMs > 3 * Math.Max(s.SrttMs, LossWindowFloorMs))
        {
            // A full loss window with zero duplicates is a clean bill: the timer
            // relaxation is immediate, not a slow crawl — an early bad orbit must not
            // latch high PTOs for the rest of the transfer.
            s.PtoInflation = 1.0;
        }

        return default;
    }

    public static void ObserveRtt(ref PacerState s, TimeSpan rtt)
    {
        if (s.FixedWindow)
        {
            return;
        }

        long sample = Math.Max((long)rtt.TotalMilliseconds, 1);
        s.MinRttMs = Math.Min(s.MinRttMs, sample);
        if (!s.HaveRtt)
        {
            s.SrttMs = sample;
            s.RttvarMs = sample / 2;
            s.HaveRtt = true;
        }
        else
        {
            long err = Math.Abs(sample - s.SrttMs);
            s.RttvarMs = (3 * s.RttvarMs + err) / 4;
            s.SrttMs = (7 * s.SrttMs + sample) / 8;
        }
    }

    private static void Grow(ref PacerState s, int chunkBytes)
    {
        if (s.Window < s.Ssthresh)
        {
            s.Window = Math.Min(s.Window + chunkBytes, s.MaxWindow); // slow start: doubles per RTT
        }
        else
        {
            s.FractionalGrowth += (long)Math.Max((double)chunkBytes * chunkBytes / s.Window, 1);
            if (s.FractionalGrowth >= s.ChunkBytes)
            {
                s.Window = Math.Min(s.Window + s.FractionalGrowth / s.ChunkBytes * s.ChunkBytes, s.MaxWindow);
                s.FractionalGrowth %= s.ChunkBytes;
            }
        }
    }

    // ≥ 1.6× base delay. Public so the shell's collapse trace reports the same
    // standing-queue verdict the collapse decision used.
    public static bool StandingQueue(in PacerState s) => s.HaveRtt && s.SrttMs * 5 >= s.MinRttMs * 8;

    public static PacerEvent OnRetransmit(ref PacerState s, long nowMs)
    {
        if (s.FixedWindow)
        {
            return default;
        }

        long lossWindow = Math.Max(s.SrttMs, LossWindowFloorMs);
        if (nowMs - s.LossWindowStartMs >= lossWindow)
        {
            s.LossWindowStartMs = nowMs;
            s.ExpiriesThisLossWindow = 0;
        }

        s.ExpiriesThisLossWindow++;
        bool delayStanding = StandingQueue(in s);
        // A standing queue is exactly what a deep buffer builds, so under delayStanding
        // a PTO expiry is weaker loss evidence than on a clean path: it may be queueing
        // delay (or a slow runner's scheduling stall) rather than a dropped frame. Two
        // expiries still collapse — real overflow drops clusters, not single frames.
        long collapseQuorum = delayStanding ? 2 : 3;
        if (s.ExpiriesThisLossWindow < collapseQuorum)
        {
            return default; // scattered loss: heal it, the window stands
        }

        if (nowMs - s.LastLossMs < lossWindow)
        {
            return default; // already reduced inside this loss window
        }

        s.LastLossMs = nowMs;
        s.PreCollapseWindow = s.Window;
        s.PreCollapseSsthresh = s.Ssthresh;
        s.CollapseExpiries = s.ExpiriesThisLossWindow;
        s.SpuriousVerdicts = 0;
        s.CollapsePending = true;
        s.ExpiriesThisLossWindow = 0;

        s.Ssthresh = Math.Max(s.Window / 2, 2 * MinimumWindow(in s));
        // Halve INTO the reduction (window below the new threshold) so slow start
        // rebounds exponentially to the threshold instead of crawling linearly from
        // it — a lossy path collapses shallower and recovers faster.
        s.Window = Math.Max(s.Ssthresh / 2, MinimumWindow(in s));
        return new PacerEvent { Kind = PacerEventKind.Collapsed };
    }

    // Half the expiries behind a collapse arriving as duplicates overturns it: the
    // flight those expiries buried was moving, and the window's dip (a quarter of
    // what it was) plus the linear congestion-avoidance climb back is pure
    // self-inflicted under-utilization on a path that never lost anything.
    private static PacerEvent TryRestoreSpuriousCollapse(ref PacerState s)
    {
        if (s.SpuriousVerdicts < Math.Max(s.CollapseExpiries / 2, 1))
        {
            return default;
        }

        s.Window = Math.Min(s.PreCollapseWindow, s.MaxWindow);
        s.Ssthresh = s.PreCollapseSsthresh;
        s.CollapsePending = false;
        long verdicts = s.SpuriousVerdicts;
        s.SpuriousVerdicts = 0;
        return new PacerEvent { Kind = PacerEventKind.Restored, Verdicts = verdicts };
    }

    // True when the reset happened (the fixed-window baseline stays put).
    public static bool OnPathChanged(ref PacerState s)
    {
        if (s.FixedWindow)
        {
            return false;
        }

        s.HaveRtt = false;
        s.SrttMs = 0;
        s.RttvarMs = 0;
        s.MinRttMs = long.MaxValue;
        s.FractionalGrowth = 0;
        s.Window = Math.Min(32L * s.ChunkBytes, s.MaxWindow);
        s.Ssthresh = long.MaxValue;
        s.PtoInflation = 1.0;
        s.DupWindowBytes = 0;
        s.DupWindowStartMs = 0;
        s.LastDupMs = 0;
        s.PacerCreditBytes = 0;
        s.LastPacerMs = long.MinValue;
        s.LossWindowStartMs = 0;
        s.ExpiriesThisLossWindow = 0;
        s.CollapsePending = false;
        s.CollapseExpiries = 0;
        s.SpuriousVerdicts = 0;
        s.LastLossMs = -long.MaxValue / 2;
        return true;
    }

    private static long MinimumWindow(in PacerState s) => 4L * s.ChunkBytes;
}
