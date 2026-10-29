using Pinhole.Core;
using Xunit;

namespace Pinhole.Tests.Core;

// Deterministic PacerMachine tests: every clock is a literal millisecond handed to
// the machine; nothing here sleeps or races. The engines wire the machine with the
// blob wire's own figures — 1024-byte chunks, 64-chunk runs — and these tests use
// the same numbers so a machine regression is an engine regression. They complement
// the behavioral Congestion/Bottleneck/LossLadder suites, which drive the same
// decisions through BlobController over a virtual network.
public sealed class PacerMachineTests
{
    private const int Chunk = 1024;
    private const int MaxRun = 64;

    private static PacerState Pacer(bool fixedWindow = false, long maxWindowBytes = 1024 * 1024) =>
        PacerState.Create(Chunk, MaxRun, maxWindowBytes, fixedWindow);

    // Seeds the deep-queue RTT shape the behavioral suites exercise: 40 ms base
    // delay with a standing queue holding srtt at 77 ms (>= 1.6x the base).
    private static void DeepQueueShape(ref PacerState s)
    {
        PacerMachine.ObserveRtt(ref s, TimeSpan.FromMilliseconds(40));
        PacerMachine.ObserveRtt(ref s, TimeSpan.FromMilliseconds(200));
        PacerMachine.ObserveRtt(ref s, TimeSpan.FromMilliseconds(200));
    }

    // ------------------------------------------------------------------ PTO ladder

    [Fact]
    public void Pacer_PtoDoublesPerRetransmit_ToTheEighthMultiple_AndCapsAtEightCeilings()
    {
        PacerState s = Pacer();

        // No RTT sample: the recorded fixed-window baseline constant is the base.
        Assert.Equal(900, PacerMachine.PtoMs(in s, 0));
        Assert.Equal(1800, PacerMachine.PtoMs(in s, 1));
        Assert.Equal(3600, PacerMachine.PtoMs(in s, 2));
        Assert.Equal(7200, PacerMachine.PtoMs(in s, 3));
        Assert.Equal(7200, PacerMachine.PtoMs(in s, 9)); // the shift stops doubling after three

        // Samples pull the base to the EWMA shape: srtt 100, rttvar 50 -> 300 ms.
        PacerMachine.ObserveRtt(ref s, TimeSpan.FromMilliseconds(100));
        Assert.Equal(300, PacerMachine.PtoMs(in s, 0));
        Assert.Equal(600, PacerMachine.PtoMs(in s, 1));
        Assert.Equal(2400, PacerMachine.PtoMs(in s, 3));

        // The granularity floor dominates tiny samples: 10 + max(20, 50) -> clamped to 150.
        PacerState tiny = Pacer();
        PacerMachine.ObserveRtt(ref tiny, TimeSpan.FromMilliseconds(10));
        Assert.Equal(150, PacerMachine.PtoMs(in tiny, 0));

        // The hard ceiling: base clamped to 3000, three doublings, 4x inflation —
        // the 96 s product is cut to 8 x 3000.
        PacerState huge = Pacer();
        PacerMachine.ObserveRtt(ref huge, TimeSpan.FromMilliseconds(9_000));
        huge.PtoInflation = 4.0;
        Assert.Equal(PacerMachine.PtoCeilingMs * 8, PacerMachine.PtoMs(in huge, 3));
        Assert.Equal(PacerMachine.PtoCeilingMs * 8, PacerMachine.PtoMs(in huge, 9));

        // The fixed-window baseline never adapts: one flat number for every input.
        PacerState fixedWindow = Pacer(fixedWindow: true);
        PacerMachine.ObserveRtt(ref fixedWindow, TimeSpan.FromMilliseconds(9_000));
        Assert.Equal(900, PacerMachine.PtoMs(in fixedWindow, 0));
        Assert.Equal(900, PacerMachine.PtoMs(in fixedWindow, 5));
    }

    // ------------------------------------------------------------------ PTO under standing delay (deep-queue H4)

    [Fact]
    public void Pacer_StandingQueueDoublesThePtoVarianceTerm_CleanPathsKeepJacobsonKarels()
    {
        // Deep-queue shape: samples 40/200/200 leave srtt 77, rttvar 76, min 40 —
        // standing (77*5 >= 40*8). The variance term doubles to 8x there: a
        // queue-delay spike is weak loss evidence, and waiting it out is cheaper
        // than re-serving the originals as duplicates.
        PacerState standing = Pacer();
        DeepQueueShape(ref standing);
        Assert.True(PacerMachine.StandingQueue(in standing));
        Assert.Equal(77 + 8 * 76, PacerMachine.PtoMs(in standing, 0));

        // A clean path keeps the classic 4x term: single 77 ms sample, min == srtt.
        PacerState clean = Pacer();
        PacerMachine.ObserveRtt(ref clean, TimeSpan.FromMilliseconds(77));
        Assert.False(PacerMachine.StandingQueue(in clean));
        Assert.Equal(77 + 4 * 38, PacerMachine.PtoMs(in clean, 0));

        // The widening rides the whole ladder: backoff and the hard ceiling apply
        // on top of it exactly as before.
        Assert.Equal(2 * (77 + 8 * 76), PacerMachine.PtoMs(in standing, 1));
    }

    [Fact]
    public void Pacer_DuplicatePressureInflatesThePto_UntilACleanLossWindowRelaxesIt()
    {
        PacerState s = Pacer(); // window 32 KiB: the dup burst threshold is 8 KiB

        // Eight duplicate KiB do not cross a quarter of the window; the ninth does.
        for (int i = 0; i < 8; i++)
        {
            PacerMachine.OnChunkArrived(ref s, Chunk, fresh: false, retransmitted: false, 1000 + i, i);
        }

        Assert.Equal(1.0, s.PtoInflation, 10);
        PacerMachine.OnChunkArrived(ref s, Chunk, fresh: false, retransmitted: false, 1008, 0);
        Assert.Equal(1.5, s.PtoInflation, 10);
        Assert.Equal((long)(900 * 1.5), PacerMachine.PtoMs(in s, 0));

        // Each further burst multiplies by 1.5, capped at 4x.
        for (int burst = 0; burst < 4; burst++)
        {
            for (int i = 0; i < 9; i++)
            {
                PacerMachine.OnChunkArrived(ref s, Chunk, fresh: false, retransmitted: false, 2000 + burst * 10_000 + i, i);
            }
        }

        Assert.Equal(4.0, s.PtoInflation, 10);

        // A full loss window with zero duplicates is a clean bill: immediate relax.
        long lastDup = s.LastDupMs;
        PacerMachine.OnChunkArrived(ref s, Chunk, fresh: true, retransmitted: false, lastDup + 751, 0);
        Assert.Equal(1.0, s.PtoInflation, 10);

        // One millisecond short of the window the relaxation does not fire
        // (3 * max(srtt, floor) = 750 with no samples).
        PacerState tight = Pacer();
        for (int i = 0; i < 9; i++)
        {
            PacerMachine.OnChunkArrived(ref tight, Chunk, fresh: false, retransmitted: false, 5000 + i, i);
        }

        PacerMachine.OnChunkArrived(ref tight, Chunk, fresh: true, retransmitted: false, 5008 + 750, 0);
        Assert.Equal(1.5, tight.PtoInflation, 10);
    }

    // ------------------------------------------------------------------ loss collapse

    [Fact]
    public void Pacer_OnACleanPathThreeExpiriesCollapse_ScatteredOnesNeverDo()
    {
        PacerState s = Pacer();
        long window = s.Window;

        // No RTT sample: delayStanding is false, the quorum is three.
        Assert.Equal(PacerEventKind.None, PacerMachine.OnRetransmit(ref s, 1000).Kind);
        Assert.Equal(PacerEventKind.None, PacerMachine.OnRetransmit(ref s, 1001).Kind);
        Assert.Equal(window, s.Window); // two expiries inside one loss window stand

        PacerEvent collapse = PacerMachine.OnRetransmit(ref s, 1002);
        Assert.Equal(PacerEventKind.Collapsed, collapse.Kind);
        Assert.Equal(window / 2, s.Ssthresh); // halve the threshold...
        Assert.Equal(window / 4, s.Window);   // ...and halve INTO it (slow-start rebound)
        Assert.Equal(window, s.PreCollapseWindow);
        Assert.Equal(3, s.CollapseExpiries);
        Assert.True(s.CollapsePending);

        // The same four expiries spread across loss windows never reach the quorum:
        // the counter resets at each loss-window boundary.
        PacerState scattered = Pacer();
        Assert.Equal(PacerEventKind.None, PacerMachine.OnRetransmit(ref scattered, 1000).Kind);
        Assert.Equal(PacerEventKind.None, PacerMachine.OnRetransmit(ref scattered, 1001).Kind);
        Assert.Equal(PacerEventKind.None, PacerMachine.OnRetransmit(ref scattered, 1402).Kind);
        Assert.Equal(PacerEventKind.None, PacerMachine.OnRetransmit(ref scattered, 1403).Kind);
        Assert.Equal(32 * Chunk, scattered.Window);
    }

    [Fact]
    public void Pacer_StandingDelayLowersTheQuorumToTwo_AndReductionsAreRateLimited()
    {
        PacerState s = Pacer();
        DeepQueueShape(ref s);
        Assert.Equal(77, s.SrttMs);
        Assert.True(PacerMachine.StandingQueue(in s)); // 77*5 >= 40*8: >= 1.6x base delay

        long window = s.Window;
        Assert.Equal(PacerEventKind.None, PacerMachine.OnRetransmit(ref s, 10_000).Kind); // one expiry is not loss
        Assert.Equal(PacerEventKind.Collapsed, PacerMachine.OnRetransmit(ref s, 10_001).Kind); // a cluster is
        Assert.Equal(2, s.CollapseExpiries);
        long collapsed = s.Window;
        Assert.Equal(Math.Max(window / 2, 4 * Chunk), collapsed); // standing: land AT the threshold

        // More expiries inside the same loss window are rate-limited: one reduction each.
        Assert.Equal(PacerEventKind.None, PacerMachine.OnRetransmit(ref s, 10_002).Kind);
        Assert.Equal(PacerEventKind.None, PacerMachine.OnRetransmit(ref s, 10_003).Kind);
        Assert.Equal(collapsed, s.Window);

        // A full loss window later the counter and the rate limit both open again.
        Assert.Equal(PacerEventKind.None, PacerMachine.OnRetransmit(ref s, 10_260).Kind); // fresh window, one expiry
        Assert.Equal(PacerEventKind.Collapsed, PacerMachine.OnRetransmit(ref s, 10_261).Kind);
        Assert.Equal(collapsed / 2, s.Window); // each standing collapse halves to its threshold
    }

    // The depth split #27 H2 pins: identical windows, different evidence. Standing
    // delay lands AT the threshold (halve once — the queue keeps the link fed while
    // the excess bleeds off); a clean-path drop cluster lands INTO it (halve twice —
    // slow start rebounds exponentially to the threshold).
    [Fact]
    public void Pacer_StandingCollapseHalvesToTheThreshold_CleanPathStillHalvesIntoIt()
    {
        PacerState standing = Pacer();
        DeepQueueShape(ref standing); // srtt 77 on a 40 ms base: standing
        Assert.Equal(32 * Chunk, standing.Window);
        PacerMachine.OnRetransmit(ref standing, 10_000);
        Assert.Equal(PacerEventKind.Collapsed, PacerMachine.OnRetransmit(ref standing, 10_001).Kind);
        Assert.Equal(16 * Chunk, standing.Ssthresh); // max(32768/2, 8192)
        Assert.Equal(16 * Chunk, standing.Window);   // AT the threshold, not ssthresh/2

        PacerState clean = Pacer();
        Assert.Equal(32 * Chunk, clean.Window);
        PacerMachine.OnRetransmit(ref clean, 1000);
        PacerMachine.OnRetransmit(ref clean, 1001);
        Assert.Equal(PacerEventKind.Collapsed, PacerMachine.OnRetransmit(ref clean, 1002).Kind);
        Assert.Equal(16 * Chunk, clean.Ssthresh);
        Assert.Equal(8 * Chunk, clean.Window);       // INTO the threshold: ssthresh/2

        // At the ssthresh floor (window 8 KiB halves to 4, floored to 2x the 4 KiB
        // minimum) the standing response holds the window where it stands — the
        // floor exists so a collapse cannot refuse all work, and standing evidence
        // is too weak to take the last headroom away. The clean path still drops
        // to the minimum window.
        PacerState small = Pacer(maxWindowBytes: 8 * Chunk);
        small.Window = 8 * Chunk;
        PacerMachine.ObserveRtt(ref small, TimeSpan.FromMilliseconds(40));
        PacerMachine.ObserveRtt(ref small, TimeSpan.FromMilliseconds(200));
        PacerMachine.ObserveRtt(ref small, TimeSpan.FromMilliseconds(200));
        PacerMachine.OnRetransmit(ref small, 10_000);
        Assert.Equal(PacerEventKind.Collapsed, PacerMachine.OnRetransmit(ref small, 10_001).Kind);
        Assert.Equal(8 * Chunk, small.Ssthresh); // max(4096, 2*4096)
        Assert.Equal(8 * Chunk, small.Window);

        PacerState smallClean = Pacer(maxWindowBytes: 8 * Chunk);
        smallClean.Window = 8 * Chunk;
        PacerMachine.OnRetransmit(ref smallClean, 1000);
        PacerMachine.OnRetransmit(ref smallClean, 1001);
        Assert.Equal(PacerEventKind.Collapsed, PacerMachine.OnRetransmit(ref smallClean, 1002).Kind);
        Assert.Equal(8 * Chunk, smallClean.Ssthresh);
        Assert.Equal(4 * Chunk, smallClean.Window); // max(ssthresh/2, minimum) = the floor
    }

    // ------------------------------------------------------------------ spurious-restore verdicts

    [Fact]
    public void Pacer_RestoreNeedsNetSpuriousVerdicts_AndOnlyDuplicatesOfRetransmitsVote()
    {
        PacerState s = Pacer();
        DeepQueueShape(ref s);
        PacerMachine.OnRetransmit(ref s, 10_000);
        PacerMachine.OnRetransmit(ref s, 10_001); // standing quorum: collapse, 2 expiries
        Assert.True(s.CollapsePending);

        // A fresh delivery of a retransmitted chunk is a REAL-loss vote: the verdict
        // ledger goes negative, so a single dup no longer clears the bar.
        PacerMachine.OnChunkArrived(ref s, Chunk, fresh: true, retransmitted: true, 10_050, 7);
        Assert.Equal(-1, s.SpuriousVerdicts);
        Assert.True(s.CollapsePending);

        // Plain duplicates (of never-retransmitted chunks) are wire load, not verdicts.
        PacerMachine.OnChunkArrived(ref s, Chunk, fresh: false, retransmitted: false, 10_051, 8);
        Assert.Equal(-1, s.SpuriousVerdicts);

        // Duplicate verdicts climb back from the deficit one by one: at zero the
        // quorum max(2/2, 1) = 1 is still short.
        Assert.Equal(PacerEventKind.None, PacerMachine.OnChunkArrived(ref s, Chunk, fresh: false, retransmitted: true, 10_052, 9).Kind);
        Assert.Equal(0, s.SpuriousVerdicts);
        Assert.True(s.CollapsePending);

        PacerEvent restore = PacerMachine.OnChunkArrived(ref s, Chunk, fresh: false, retransmitted: true, 10_053, 10);
        Assert.Equal(PacerEventKind.Restored, restore.Kind);
        Assert.Equal(1, restore.Verdicts);
        Assert.Equal(s.PreCollapseWindow, s.Window); // the dip and the climb back were self-inflicted
        Assert.Equal(long.MaxValue, s.Ssthresh);
        Assert.False(s.CollapsePending);
        Assert.Equal(0, s.SpuriousVerdicts);

        // The latch: with no pending collapse, further duplicate verdicts change nothing.
        Assert.Equal(PacerEventKind.None, PacerMachine.OnChunkArrived(ref s, Chunk, fresh: false, retransmitted: true, 10_054, 11).Kind);
        Assert.Equal(s.PreCollapseWindow, s.Window);
    }

    [Fact]
    public void Pacer_StragglerOriginal_OverturnsItsChunksFreshVote_RegardlessOfArrivalOrder()
    {
        // The hunter's macOS capture: nothing drops (tailDropped=0), the re-served
        // copies land FIRST and vote real-loss, and the slow originals straggle in
        // after — with no entry left to vouch for them. Both copies were in flight
        // the whole time, so the straggler must cancel its chunk's vote and add the
        // spurious one, netting the same +1 the dup-first ordering earns.
        PacerState s = Pacer();
        DeepQueueShape(ref s);
        PacerMachine.OnRetransmit(ref s, 10_000);
        PacerMachine.OnRetransmit(ref s, 10_001); // standing quorum: collapse, 2 expiries
        Assert.True(s.CollapsePending);

        // The re-served copy of chunk 7 is fresh and votes real-loss (-1, recorded).
        PacerMachine.OnChunkArrived(ref s, Chunk, fresh: true, retransmitted: true, 10_050, 7);
        Assert.Equal(-1, s.SpuriousVerdicts);
        Assert.True(s.CollapsePending);

        // The original of chunk 7 straggles in: entry long gone, retransmitted false.
        // It swings the ledger by two — cancel plus spurious — and the collapse
        // overturns at quorum max(2/2, 1) = 1.
        PacerEvent restore = PacerMachine.OnChunkArrived(ref s, Chunk, fresh: false, retransmitted: false, 10_400, 7);
        Assert.Equal(PacerEventKind.Restored, restore.Kind);
        Assert.Equal(s.PreCollapseWindow, s.Window);
        Assert.Equal(0, s.SpuriousVerdicts);
        Assert.Equal(0, s.FreshVoteCount);

        // A straggler nobody recorded votes nowhere: it is plain wire load.
        PacerState lone = Pacer();
        DeepQueueShape(ref lone);
        PacerMachine.OnRetransmit(ref lone, 10_000);
        PacerMachine.OnRetransmit(ref lone, 10_001);
        Assert.Equal(PacerEventKind.None, PacerMachine.OnChunkArrived(ref lone, Chunk, fresh: false, retransmitted: false, 10_400, 99).Kind);
        Assert.True(lone.CollapsePending);
        Assert.Equal(0, lone.SpuriousVerdicts);
    }

    [Fact]
    public void Pacer_ASecondCollapseClearsTheOldVerdictLedger()
    {
        PacerState s = Pacer();
        DeepQueueShape(ref s);

        // Collapse one: a fresh-retransmit vote puts the ledger at -1.
        PacerMachine.OnRetransmit(ref s, 10_000);
        PacerMachine.OnRetransmit(ref s, 10_001);
        PacerMachine.OnChunkArrived(ref s, Chunk, fresh: true, retransmitted: true, 10_050, 7);
        Assert.Equal(-1, s.SpuriousVerdicts);

        // Collapse two a loss window later starts a fresh ledger at zero, so a single
        // dup verdict restores it — the old deficit must not outlive its collapse.
        PacerMachine.OnRetransmit(ref s, 10_600);
        PacerMachine.OnRetransmit(ref s, 10_601);
        Assert.Equal(0, s.SpuriousVerdicts);
        long secondFrom = s.PreCollapseWindow;

        PacerEvent restore = PacerMachine.OnChunkArrived(ref s, Chunk, fresh: false, retransmitted: true, 10_700, 10);
        Assert.Equal(PacerEventKind.Restored, restore.Kind);
        Assert.Equal(secondFrom, s.Window);
    }

    // ------------------------------------------------------------------ pacer token bucket

    [Fact]
    public void Pacer_FirstAccrualStampsTheClockWithoutCredit_AndEveryAccrualCapsAtOneRun()
    {
        PacerState s = Pacer(); // 32 KiB slow-start window, no RTT sample: pace at 100 ms

        // The first call only seeds the clock: elapsed is zero by definition.
        Assert.Equal(0, PacerMachine.AffordableChunks(ref s, 64, 5000));
        Assert.Equal(5000, s.LastPacerMs);

        // 200 ms at 32768/100 = 327 B/ms accrues 65400, capped at MaxRunChunks*Chunk
        // (the 32 KiB window allows a 4-chunk run) — and no elapsed span beats the cap.
        Assert.Equal(4, PacerMachine.AffordableChunks(ref s, 64, 5200));
        Assert.Equal(4 * Chunk, s.PacerCreditBytes);
        Assert.Equal(4, PacerMachine.AffordableChunks(ref s, 64, 5200 + 1_000_000));
        Assert.Equal(4 * Chunk, s.PacerCreditBytes);

        // A clock that runs backwards accrues nothing but still restamps.
        PacerState back = Pacer();
        PacerMachine.AffordableChunks(ref back, 64, 1000);
        Assert.Equal(0, PacerMachine.AffordableChunks(ref back, 64, 900));
        Assert.Equal(900, back.LastPacerMs);
    }

    [Fact]
    public void Pacer_CommittedRunsConsumeCreditOnce_WindowRefusalNeverTouchesTheClock()
    {
        PacerState s = Pacer();

        // A run bigger than the whole window is refused before the pacer clock starts.
        Assert.False(PacerMachine.CanStartRun(ref s, s.Window + 1, 5000));
        Assert.Equal(long.MinValue, s.LastPacerMs);

        // The seeding call refuses on empty credit but starts the clock (D-02: the
        // accrual from a refused run persists — nothing was sent, but time passed).
        Assert.False(PacerMachine.CanStartRun(ref s, 2048, 5000));
        Assert.Equal(5000, s.LastPacerMs);

        // 100 ms later a full run's credit exists; the check consumes nothing and the
        // commit consumes it exactly once, only when the shell chooses to run it.
        Assert.True(PacerMachine.CanStartRun(ref s, 2048, 5100));
        Assert.Equal(4 * Chunk, s.PacerCreditBytes);
        PacerMachine.CommitStartRun(ref s, 2048);
        Assert.Equal(2 * Chunk, s.PacerCreditBytes);
        Assert.Equal(2048, s.InFlight);

        // In-flight bytes count against the window first: an oversized run is refused
        // without an accrual, so the credit balance survives it untouched.
        Assert.False(PacerMachine.CanStartRun(ref s, s.Window, 5200));
        Assert.Equal(2 * Chunk, s.PacerCreditBytes);

        // Released reservations give the window its headroom back.
        PacerMachine.ReleaseReservation(ref s, 2048);
        Assert.Equal(0, s.InFlight);

        // The fixed-window baseline never spends credit: the window is the only brake.
        PacerState fixedWindow = Pacer(fixedWindow: true);
        Assert.True(PacerMachine.CanStartRun(ref fixedWindow, 4 * MaxRun * Chunk, 0));
        PacerMachine.CommitStartRun(ref fixedWindow, 4 * MaxRun * Chunk);
        Assert.Equal(0, fixedWindow.PacerCreditBytes);
        Assert.Equal(long.MinValue, fixedWindow.LastPacerMs);
        Assert.False(PacerMachine.CanStartRun(ref fixedWindow, 1, 0)); // the window is full
    }

    // ------------------------------------------------------------------ pacing RTT shape

    [Fact]
    public void Pacer_SlowStartPacesAtMinRtt_CaCapsAtFourTimesTheBase()
    {
        // Slow start paces against the base delay: 40 ms sample, 5 ms elapsed,
        // rate = 32768/40 = 819 B/ms -> 4095 bytes = 3 chunks (floor division).
        PacerState slow = Pacer();
        PacerMachine.ObserveRtt(ref slow, TimeSpan.FromMilliseconds(40));
        PacerMachine.AffordableChunks(ref slow, 64, 1000); // seed
        Assert.Equal(3, PacerMachine.AffordableChunks(ref slow, 64, 1005));
        Assert.Equal(4095, slow.PacerCreditBytes);

        // CA never paces slower than 4x the base: srtt 265 on a 40 ms base paces at
        // 160 — delay beyond that is congestion evidence, not a pacing target. An
        // 8 KiB window keeps the one-run cap (2048) out of the discriminator's way:
        // 60 ms at 8192/160 = 51 B/ms = 3060 -> capped 2048 = 2 chunks, where pacing
        // at srtt would give 30*60 = 1800 = 1 chunk.
        PacerState deep = Pacer(maxWindowBytes: 8 * Chunk);
        PacerMachine.ObserveRtt(ref deep, TimeSpan.FromMilliseconds(40));
        PacerMachine.ObserveRtt(ref deep, TimeSpan.FromMilliseconds(1000));
        PacerMachine.ObserveRtt(ref deep, TimeSpan.FromMilliseconds(1000));
        Assert.Equal(265, deep.SrttMs);
        deep.Ssthresh = deep.Window; // leave slow start
        PacerMachine.AffordableChunks(ref deep, 64, 1000); // seed
        Assert.Equal(2, PacerMachine.AffordableChunks(ref deep, 64, 1060));
        Assert.Equal(2 * Chunk, deep.PacerCreditBytes);

        // With no sample at all the pacer assumes 100 ms: 10 ms of a 32 KiB window
        // is 3270 bytes = 3 chunks (a 40 ms pace would hit the 4-chunk run cap).
        PacerState blind = Pacer();
        PacerMachine.AffordableChunks(ref blind, 64, 1000); // seed
        Assert.Equal(3, PacerMachine.AffordableChunks(ref blind, 64, 1010));

        // The fixed-window baseline bypasses the bucket entirely.
        PacerState fixedWindow = Pacer(fixedWindow: true);
        Assert.Equal(9, PacerMachine.AffordableChunks(ref fixedWindow, 9, 1234));
        Assert.Equal(0, fixedWindow.PacerCreditBytes);
        Assert.Equal(long.MinValue, fixedWindow.LastPacerMs);
    }

    [Fact]
    public void Pacer_PacingNeverAssumesBetterThanTwentyMilliseconds()
    {
        // A 5 ms base is floored to 20: 2 ms at 32768/20 = 1638 B/ms = 3276 = 3
        // chunks; pacing at the raw 5 ms would hit the 4-chunk run cap instead.
        PacerState s = Pacer();
        PacerMachine.ObserveRtt(ref s, TimeSpan.FromMilliseconds(5));
        PacerMachine.AffordableChunks(ref s, 64, 1000); // seed
        Assert.Equal(3, PacerMachine.AffordableChunks(ref s, 64, 1002));
        Assert.Equal(3276, s.PacerCreditBytes);
    }

    // ------------------------------------------------------------------ window growth

    [Fact]
    public void Pacer_SlowStartAddsAChunkPerDelivery_UntilTheCap_CAAddsOnePerRTT()
    {
        PacerState s = Pacer(maxWindowBytes: 64 * Chunk);
        Assert.Equal(32 * Chunk, s.Window);

        // Slow start: every fresh delivery adds its own chunk, bounded by the cap.
        for (int i = 0; i < 40; i++)
        {
            PacerMachine.OnChunkArrived(ref s, Chunk, fresh: true, retransmitted: false, i, i);
        }

        Assert.Equal(64 * Chunk, s.Window); // 32768 + 40*1024 clamped at the cap

        // Duplicates never grow the window.
        PacerMachine.OnChunkArrived(ref s, Chunk, fresh: false, retransmitted: false, 100, 0);
        Assert.Equal(64 * Chunk, s.Window);

        // Congestion avoidance: each 1024 adds 1024*1024/65536 = 16 to the
        // accumulator; only the 64th delivery carries a full chunk over.
        s.Ssthresh = s.Window;
        for (int i = 0; i < 63; i++)
        {
            PacerMachine.OnChunkArrived(ref s, Chunk, fresh: true, retransmitted: false, 200 + i, i);
        }

        Assert.Equal(64 * Chunk, s.Window); // at the cap the growth lands as headroom
        Assert.Equal(1008, s.FractionalGrowth);

        // Below the cap the accumulator carries over one chunk per window's worth of
        // deliveries: at 32 KiB each chunk adds 1024*1024/32768 = 32, so the 32nd
        // delivery crosses the 1024 bar and moves the window by exactly one chunk.
        PacerState open = Pacer();
        open.Ssthresh = 32 * Chunk; // CA from the start, 32 KiB window, 1 MiB of headroom
        for (int i = 0; i < 31; i++)
        {
            PacerMachine.OnChunkArrived(ref open, Chunk, fresh: true, retransmitted: false, i, i);
        }

        Assert.Equal(32 * Chunk, open.Window);
        Assert.Equal(992, open.FractionalGrowth);
        PacerMachine.OnChunkArrived(ref open, Chunk, fresh: true, retransmitted: false, 31, 31);
        Assert.Equal(33 * Chunk, open.Window);
        Assert.Equal(0, open.FractionalGrowth);

        // The fixed-window baseline measures but never adapts.
        PacerState fixedWindow = Pacer(fixedWindow: true);
        for (int i = 0; i < 100; i++)
        {
            PacerMachine.OnChunkArrived(ref fixedWindow, Chunk, fresh: true, retransmitted: false, i, i);
        }

        Assert.Equal(4 * MaxRun * Chunk, fixedWindow.Window);
    }

    // ------------------------------------------------------------------ RTT EWMA and reset

    [Fact]
    public void Pacer_RttEwmaMatchesTheEngineFormula_AndMinRttOnlyFalls()
    {
        PacerState s = Pacer();
        Assert.False(s.HaveRtt);

        PacerMachine.ObserveRtt(ref s, TimeSpan.FromMilliseconds(40));
        Assert.True(s.HaveRtt);
        Assert.Equal(40, s.SrttMs);
        Assert.Equal(20, s.RttvarMs);
        Assert.Equal(40, s.MinRttMs);

        PacerMachine.ObserveRtt(ref s, TimeSpan.FromMilliseconds(200)); // err 160: var (3*20+160)/4 = 55
        Assert.Equal(55, s.RttvarMs);
        Assert.Equal(60, s.SrttMs); // (7*40+200)/8
        Assert.Equal(40, s.MinRttMs);

        PacerMachine.ObserveRtt(ref s, TimeSpan.FromMilliseconds(200)); // err 140: var (3*55+140)/4 = 76
        Assert.Equal(76, s.RttvarMs);
        Assert.Equal(77, s.SrttMs); // (7*60+200)/8

        // A sub-millisecond sample clamps to 1: the EWMA never sees a zero RTT.
        PacerMachine.ObserveRtt(ref s, TimeSpan.FromMicroseconds(400));
        Assert.Equal(1, s.MinRttMs);

        // Path change forgets everything and restores the 32 KiB probe start.
        Assert.True(PacerMachine.OnPathChanged(ref s));
        Assert.False(s.HaveRtt);
        Assert.Equal(0, s.SrttMs);
        Assert.Equal(long.MaxValue, s.MinRttMs);
        Assert.Equal(32 * Chunk, s.Window);
        Assert.Equal(long.MaxValue, s.Ssthresh);
        Assert.Equal(1.0, s.PtoInflation, 10);
        Assert.Equal(0, s.PacerCreditBytes);
        Assert.Equal(long.MinValue, s.LastPacerMs);
        Assert.False(s.CollapsePending);
        Assert.Equal(900, PacerMachine.PtoMs(in s, 0)); // no sample: back to the baseline

        // The fixed-window baseline ignores samples and path changes alike.
        PacerState fixedWindow = Pacer(fixedWindow: true);
        PacerMachine.ObserveRtt(ref fixedWindow, TimeSpan.FromMilliseconds(40));
        Assert.False(fixedWindow.HaveRtt);
        Assert.False(PacerMachine.OnPathChanged(ref fixedWindow));
        Assert.Equal(4 * MaxRun * Chunk, fixedWindow.Window);
    }

    // ------------------------------------------------------------------ run shape

    [Fact]
    public void Pacer_MaxRunChunksScalesWithTheWindow_BetweenTwoAndTheWireCap()
    {
        PacerState baseline = Pacer(fixedWindow: true);
        Assert.Equal(MaxRun, PacerMachine.MaxRunChunks(in baseline));

        PacerState s = Pacer();
        Assert.Equal(4, PacerMachine.MaxRunChunks(in s)); // 32768 / (8*1024)

        s.Window = 2 * 1024 * 1024;
        Assert.Equal(MaxRun, PacerMachine.MaxRunChunks(in s)); // clamped at the wire cap

        s.Window = 8 * Chunk;
        Assert.Equal(2, PacerMachine.MaxRunChunks(in s)); // 1 clamps up to 2

        s.Window = 4 * Chunk; // the minimum window after a deep collapse
        Assert.Equal(2, PacerMachine.MaxRunChunks(in s));
    }
}
