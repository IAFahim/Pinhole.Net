namespace Pinhole.Core;

public enum PacerEventKind : byte
{
    None = 0,
    Collapsed = 1,
    Restored = 2,
}

public struct PacerEvent
{
    public PacerEventKind Kind;
    public long Verdicts;
}

public struct PacerState
{

    public int ChunkBytes;
    public int MaxRequestCount;
    public long MaxWindow;
    public bool FixedWindow;

    public long Window;
    public long Ssthresh;
    public long InFlight;
    public long FractionalGrowth;

    public long SrttMs;
    public long RttvarMs;
    public long MinRttMs;
    public bool HaveRtt;

    public double PtoInflation;

    public long PacerCreditBytes;
    public long LastPacerMs;

    public long LossWindowStartMs;
    public long LastLossMs;
    public long ExpiriesThisLossWindow;

    public bool CollapsePending;
    public long CollapseExpiries;
    public long PreCollapseWindow;
    public long PreCollapseSsthresh;
    public long SpuriousVerdicts;

    public long[]? FreshVoteIndices;
    public int FreshVoteCount;
    public const int VoteRingCapacity = 32;
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
        s.FreshVoteIndices = new long[VoteRingCapacity];
        return s;
    }
}

public static class PacerMachine
{
    public const long InitialPtoMs = 900;
    public const long PtoFloorMs = 150;
    public const long PtoCeilingMs = 3_000;
    public const long GranularityMs = 50;
    public const long MinRttMs = 20;
    public const long NoSamplePacingRttMs = 100;
    public const long LossWindowFloorMs = 250;

    public static int MaxRunChunks(in PacerState s) => s.FixedWindow
        ? s.MaxRequestCount
        : (int)Math.Clamp(s.Window / (8L * s.ChunkBytes), 2, s.MaxRequestCount);

    public static int AffordableChunks(ref PacerState s, int desired, long nowMs)
    {
        if (s.FixedWindow)
        {
            return desired;
        }

        AccruePacerCredit(ref s, nowMs);
        return (int)Math.Min(desired, s.PacerCreditBytes / s.ChunkBytes);
    }

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

        long pacingRtt = !s.HaveRtt ? NoSamplePacingRttMs
            : s.Window < s.Ssthresh ? Math.Max(Math.Min(s.SrttMs, s.MinRttMs), MinRttMs)
            : Math.Max(Math.Min(s.SrttMs, s.MinRttMs * 4), MinRttMs);
        long rateBytesPerMs = Math.Max(s.Window / pacingRtt, 1);
        long elapsed = s.LastPacerMs == long.MinValue ? 0 : Math.Max(nowMs - s.LastPacerMs, 0);
        s.LastPacerMs = nowMs;
        long maxRunBytes = (long)MaxRunChunks(in s) * s.ChunkBytes;
        s.PacerCreditBytes = Math.Min(s.PacerCreditBytes + rateBytesPerMs * elapsed, maxRunBytes);
    }

    private static long PtoBaseMs(in PacerState s)
    {
        if (!s.HaveRtt)
        {
            return InitialPtoMs;
        }

        long varMultiplier = StandingQueue(in s) ? 8 : 4;
        return Math.Clamp(s.SrttMs + Math.Max(varMultiplier * s.RttvarMs, GranularityMs), PtoFloorMs, PtoCeilingMs);
    }

    public static long PtoMs(in PacerState s, int retransmits)
    {
        if (s.FixedWindow)
        {
            return InitialPtoMs;
        }

        long pto = (long)(PtoBaseMs(in s) * Math.Min(1L << Math.Min(retransmits, 3), 8) * s.PtoInflation);
        return Math.Min(pto, PtoCeilingMs * 8);
    }

    public static PacerEvent OnChunkArrived(ref PacerState s, int chunkBytes, bool fresh, bool retransmitted, long nowMs, long index)
    {
        if (!fresh)
        {
            PacerEvent verdict = default;

            bool overturns = s.CollapsePending && TakeFreshVote(ref s, index);
            if (overturns || (retransmitted && s.CollapsePending))
            {
                s.SpuriousVerdicts += overturns ? 2 : 1;
                verdict = TryRestoreSpuriousCollapse(ref s);
            }

            if (s.DupWindowStartMs == 0)
            {
                s.DupWindowStartMs = nowMs;
                s.DupWindowBytes = 0;
            }

            s.DupWindowBytes += chunkBytes;
            s.LastDupMs = nowMs;

            if (s.DupWindowBytes > s.Window / 4)
            {
                s.PtoInflation = Math.Min(s.PtoInflation * 1.5, 4.0);
                s.DupWindowStartMs = nowMs;
                s.DupWindowBytes = 0;
            }

            return verdict;
        }

        if (retransmitted && s.CollapsePending)
        {
            s.SpuriousVerdicts--;
            RememberFreshVote(ref s, index);
        }

        if (s.FixedWindow)
        {
            return default;
        }

        Grow(ref s, chunkBytes);
        if (s.PtoInflation > 1.0 && s.LastDupMs > 0 && nowMs - s.LastDupMs > 3 * Math.Max(s.SrttMs, LossWindowFloorMs))
        {

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
            s.Window = Math.Min(s.Window + chunkBytes, s.MaxWindow);
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

        long collapseQuorum = delayStanding ? 2 : 3;
        if (s.ExpiriesThisLossWindow < collapseQuorum)
        {
            return default;
        }

        if (nowMs - s.LastLossMs < lossWindow)
        {
            return default;
        }

        s.LastLossMs = nowMs;
        s.PreCollapseWindow = s.Window;
        s.PreCollapseSsthresh = s.Ssthresh;
        s.CollapseExpiries = s.ExpiriesThisLossWindow;
        s.SpuriousVerdicts = 0;
        s.CollapsePending = true;
        s.FreshVoteCount = 0;
        s.ExpiriesThisLossWindow = 0;

        s.Ssthresh = Math.Max(s.Window / 2, 2 * MinimumWindow(in s));
        if (delayStanding)
        {

            s.Window = s.Ssthresh;
        }
        else
        {

            s.Window = Math.Max(s.Ssthresh / 2, MinimumWindow(in s));
        }

        return new PacerEvent { Kind = PacerEventKind.Collapsed };
    }

    private static void RememberFreshVote(ref PacerState s, long index)
    {
        if (s.FreshVoteIndices is not { Length: > 0 } ring)
        {
            return;
        }

        if (s.FreshVoteCount < ring.Length)
        {
            ring[s.FreshVoteCount++] = index;
            return;
        }

        Array.Copy(ring, 1, ring, 0, ring.Length - 1);
        ring[^1] = index;
    }

    private static bool TakeFreshVote(ref PacerState s, long index)
    {
        if (s.FreshVoteIndices is not { Length: > 0 } ring)
        {
            return false;
        }

        for (int i = 0; i < s.FreshVoteCount; i++)
        {
            if (ring[i] == index)
            {
                ring[i] = ring[s.FreshVoteCount - 1];
                s.FreshVoteCount--;
                return true;
            }
        }

        return false;
    }

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
        s.FreshVoteCount = 0;
        return new PacerEvent { Kind = PacerEventKind.Restored, Verdicts = verdicts };
    }

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
        s.FreshVoteCount = 0;
        s.LastLossMs = -long.MaxValue / 2;
        return true;
    }

    private static long MinimumWindow(in PacerState s) => 4L * s.ChunkBytes;
}
