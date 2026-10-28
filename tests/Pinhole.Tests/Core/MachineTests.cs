using Pinhole.Core;
using Pinhole.Crypto;
using Xunit;

namespace Pinhole.Tests.Core;

// Tick-driven, deterministic machine tests: every "clock" is a literal millisecond
// handed to the machine as a Tick; nothing here sleeps or races. The engines wire
// the machines with base=1200, step=128, attempts=3, ceilings 1472/1452 — these
// tests use the same numbers so a machine regression is an engine regression.
public sealed class MachineTests
{
    private const int BaseWire = 1200;
    private const int StepBytes = 128;
    private const int Attempts = 3;
    private const int CeilingV4 = 1472;
    private const int CeilingV6 = 1452;
    private const long ReprobeMs = 60_000;
    private const long ProbeTimeoutMs = 500;

    private static PmtuState Pmtu() => PmtuState.Create(
        BaseWire, StepBytes, Attempts, CeilingV4, CeilingV6, ReprobeMs, ProbeTimeoutMs);

    private static int PmtuStep(ref PmtuState s, in PmtuInput input, long nowMs, Span<Effect> effects) =>
        PmtuMachine.Step(ref s, in input, new Tick(nowMs), effects);

    private static PmtuInput PmtuTick(bool eligible = true, bool ipv4 = true)
    {
        PmtuInput input = default;
        input.Kind = PmtuInputKind.Tick;
        input.PathEligible = eligible;
        input.IPv4 = ipv4;
        return input;
    }

    private static PmtuInput PmtuAck(long nonce)
    {
        PmtuInput input = default;
        input.Kind = PmtuInputKind.PongAcked;
        input.Nonce = nonce;
        return input;
    }

    private static (int Size, long Nonce, long Deadline)? Probe(Span<Effect> effects, int count)
    {
        long? nonce = null;
        long? deadline = null;
        int size = 0;
        for (int i = 0; i < count; i++)
        {
            if (effects[i].Kind == EffectKind.Transmit)
            {
                size = effects[i].Length;
                nonce = effects[i].Value;
            }
            else if (effects[i].Kind == EffectKind.Arm)
            {
                deadline = effects[i].Value;
            }
        }

        return nonce is { } n && deadline is { } d ? (size, n, d) : null;
    }

    private static KeepaliveState Keepalive(long intervalMs = 1000, long timeoutMs = 300, int maxUnanswered = 3) =>
        KeepaliveState.Create(intervalMs, timeoutMs, maxUnanswered);

    private static int KeepaliveStep(ref KeepaliveState s, in KeepaliveInput input, long nowMs, Span<Effect> effects) =>
        KeepaliveMachine.Step(ref s, in input, new Tick(nowMs), effects);

    // ------------------------------------------------------------------ PMTU: climb

    [Fact]
    public void Pmtu_ClimbsStepwise_VerifyingEachSize_TillTheCeilingParks()
    {
        PmtuState s = Pmtu();
        Span<Effect> effects = stackalloc Effect[2];

        // Every size is probed twice in the engine: once to confirm (Wire rises),
        // once to re-verify (VerifiedSize rises). Only then does the next climb go.
        long t = 1000;
        int[] expected = [1328, 1328, 1456, 1456, 1472, 1472];
        foreach (int size in expected)
        {
            int n = PmtuStep(ref s, PmtuTick(), t, effects);
            (int Size, long Nonce, long Deadline)? sent = Probe(effects, n);
            Assert.True(sent is not null, $"expected a probe at t={t}");
            (int Size, long Nonce, long Deadline) probe = sent ?? (0, 0, 0);
            Assert.Equal(size, probe.Size);
            Assert.Equal(t + ProbeTimeoutMs, probe.Deadline);
            Assert.True(probe.Nonce > 0, "PMTUD nonces are positive (bit 62 marker)");
            Assert.Equal(t, probe.Nonce & ~PmtuMachine.ProbeMarker); // nonce = t | marker

            Assert.Equal(0, PmtuStep(ref s, PmtuAck(probe.Nonce), t + 10, effects));
            Assert.False(s.Outstanding);
            t += 1000;
        }

        Assert.Equal(CeilingV4, s.Wire);
        Assert.True(s.VerifiedSize);

        // At the ceiling there is nothing left to climb: an Arm-only cooldown.
        int parked = PmtuStep(ref s, PmtuTick(), t, effects);
        Assert.Equal(1, parked);
        Assert.Equal(EffectKind.Arm, effects[0].Kind);
        Assert.Equal(t + ReprobeMs, effects[0].Value);
        Assert.Equal(0, PmtuStep(ref s, PmtuTick(), t + ReprobeMs - 1, effects));
    }

    [Fact]
    public void Pmtu_ClimbHonorsTheIpv6Ceiling()
    {
        PmtuState s = Pmtu();
        Span<Effect> effects = stackalloc Effect[2];
        int n = PmtuStep(ref s, PmtuTick(ipv4: false), 0, effects);
        Assert.Equal(1328, Probe(effects, n)!.Value.Size);
        Assert.Equal(0, PmtuStep(ref s, PmtuAck(Probe(effects, n)!.Value.Nonce), 1, effects));

        // v6 ceiling clamps the second climb: min(1452, 1328 + 128) = 1452, not 1456.
        n = PmtuStep(ref s, PmtuTick(ipv4: false), 2, effects);
        Assert.Equal(1328, Probe(effects, n)!.Value.Size);
        Assert.Equal(0, PmtuStep(ref s, PmtuAck(Probe(effects, n)!.Value.Nonce), 3, effects));
        n = PmtuStep(ref s, PmtuTick(ipv4: false), 4, effects);
        Assert.Equal(1452, Probe(effects, n)!.Value.Size);
    }

    // ------------------------------------------------------------------ PMTU: loss and shrink

    [Fact]
    public void Pmtu_LostProbeRetriesAtTheExactDeadline_ThenCooldownsAfterMaxAttempts()
    {
        PmtuState s = Pmtu();
        Span<Effect> effects = stackalloc Effect[2];

        int n = PmtuStep(ref s, PmtuTick(), 1000, effects);
        long deadline = Probe(effects, n)!.Value.Deadline;
        Assert.Equal(1500, deadline);

        Assert.Equal(0, PmtuStep(ref s, PmtuTick(), 1499, effects)); // still hoping
        Assert.True(s.Outstanding);

        // Exactly at the deadline the absence of a pong IS the measurement: retransmit.
        n = PmtuStep(ref s, PmtuTick(), 1500, effects);
        Assert.Equal(1328, Probe(effects, n)!.Value.Size);
        Assert.Equal(2000, Probe(effects, n)!.Value.Deadline);
        n = PmtuStep(ref s, PmtuTick(), 2000, effects);
        Assert.Equal(1328, Probe(effects, n)!.Value.Size);

        // Third strike: no transmit, an Arm-only cooldown at now + reprobe interval.
        int cooled = PmtuStep(ref s, PmtuTick(), 2500, effects);
        Assert.Equal(1, cooled);
        Assert.Equal(EffectKind.Arm, effects[0].Kind);
        Assert.Equal(2500 + ReprobeMs, effects[0].Value);
        Assert.False(s.Outstanding);
        Assert.Equal(0, s.Wire); // nothing was ever confirmed

        // During the cooldown nothing moves; at its end the climb restarts from the floor.
        Assert.Equal(0, PmtuStep(ref s, PmtuTick(), 2500 + ReprobeMs - 1, effects));
        int restart = PmtuStep(ref s, PmtuTick(), 2500 + ReprobeMs, effects);
        Assert.Equal(1328, Probe(effects, restart)!.Value.Size);
    }

    [Fact]
    public void Pmtu_ConfirmedSizeThatStopsTraversingFallsBackToTheFloor()
    {
        PmtuState s = Pmtu();
        Span<Effect> effects = stackalloc Effect[2];

        int n = PmtuStep(ref s, PmtuTick(), 1000, effects);
        Assert.Equal(0, PmtuStep(ref s, PmtuAck(Probe(effects, n)!.Value.Nonce), 1010, effects));
        Assert.Equal(1328, s.Wire);

        // The re-verification probe of the confirmed size loses all three attempts.
        n = PmtuStep(ref s, PmtuTick(), 2000, effects); // re-verify 1328
        Assert.Equal(1328, Probe(effects, n)!.Value.Size);
        PmtuStep(ref s, PmtuTick(), 2500, effects);
        PmtuStep(ref s, PmtuTick(), 3000, effects);
        int after = PmtuStep(ref s, PmtuTick(), 3500, effects);

        Assert.Equal(0, after); // no cooldown: fall back and re-climb immediately
        Assert.Equal(BaseWire, s.Wire);
        Assert.False(s.VerifiedSize);
        Assert.False(s.Outstanding);

        int reclimb = PmtuStep(ref s, PmtuTick(), 3501, effects);
        Assert.Equal(1328, Probe(effects, reclimb)!.Value.Size);
    }

    [Fact]
    public void Pmtu_FailedClimbClearsVerificationSoTheNextCycleRechecksTheConfirmedSize()
    {
        PmtuState s = Pmtu();
        Span<Effect> effects = stackalloc Effect[2];

        int n = PmtuStep(ref s, PmtuTick(), 1000, effects);
        Assert.Equal(0, PmtuStep(ref s, PmtuAck(Probe(effects, n)!.Value.Nonce), 1010, effects));
        n = PmtuStep(ref s, PmtuTick(), 2000, effects);
        Assert.Equal(0, PmtuStep(ref s, PmtuAck(Probe(effects, n)!.Value.Nonce), 2010, effects));
        Assert.True(s.VerifiedSize);

        // A failed climb (1328 -> 1456 never answers) starts the cooldown and schedules
        // a re-verification of 1328 for the cycle after it.
        n = PmtuStep(ref s, PmtuTick(), 3000, effects);
        Assert.Equal(1456, Probe(effects, n)!.Value.Size);
        PmtuStep(ref s, PmtuTick(), 3500, effects);
        PmtuStep(ref s, PmtuTick(), 4000, effects);
        PmtuStep(ref s, PmtuTick(), 4500, effects);
        Assert.False(s.VerifiedSize);
        Assert.Equal(1328, s.Wire);

        int reverify = PmtuStep(ref s, PmtuTick(), 4500 + ReprobeMs, effects);
        Assert.Equal(1328, Probe(effects, reverify)!.Value.Size); // the confirmed size, not 1456
    }

    // ------------------------------------------------------------------ PMTU: evidence, migration, acks

    [Fact]
    public void Pmtu_InboundEvidenceRaisesTheWireButNeverLowersOrBreachesTheFloor()
    {
        PmtuState s = Pmtu();
        Span<Effect> effects = stackalloc Effect[2];

        PmtuInput evidence(long wire, bool ipv4 = true)
        {
            PmtuInput input = default;
            input.Kind = PmtuInputKind.InboundEvidence;
            input.IPv4 = ipv4;
            input.WireLength = (int)wire;
            return input;
        }

        Assert.Equal(0, PmtuStep(ref s, evidence(1100), 0, effects));
        Assert.Equal(0, s.Wire); // below the guaranteed floor: not evidence of anything
        Assert.Equal(0, PmtuStep(ref s, evidence(2000), 0, effects));
        Assert.Equal(0, s.Wire); // above the probe ceiling: loopback-sized, ignored
        Assert.Equal(0, PmtuStep(ref s, evidence(1400), 0, effects));
        Assert.Equal(1400, s.Wire);
        Assert.Equal(0, PmtuStep(ref s, evidence(1300), 0, effects));
        Assert.Equal(1400, s.Wire); // a small datagram never demotes a bigger confirmation
        Assert.Equal(0, PmtuStep(ref s, evidence(1460, ipv4: false), 0, effects));
        Assert.Equal(1400, s.Wire); // v6 ceiling applies to v6-sized evidence
    }

    [Fact]
    public void Pmtu_MigrationAndIneligibilityVoidTheMeasurement()
    {
        PmtuState s = Pmtu();
        Span<Effect> effects = stackalloc Effect[2];
        int n = PmtuStep(ref s, PmtuTick(), 1000, effects);
        Assert.Equal(0, PmtuStep(ref s, PmtuAck(Probe(effects, n)!.Value.Nonce), 1010, effects));
        Assert.Equal(1328, s.Wire);

        // Relay/TCP detour: the measurement is void but quietly — no effects, no throw.
        Assert.Equal(0, PmtuStep(ref s, PmtuTick(eligible: false), 2000, effects));
        Assert.Equal(0, s.Wire);
        Assert.False(s.Outstanding);

        int again = PmtuStep(ref s, PmtuTick(), 3000, effects);
        Assert.Equal(0, PmtuStep(ref s, PmtuAck(Probe(effects, again)!.Value.Nonce), 3010, effects));
        Assert.Equal(1328, s.Wire);

        PmtuInput migrated = default;
        migrated.Kind = PmtuInputKind.PathMigrated;
        Assert.Equal(0, PmtuStep(ref s, migrated, 4000, effects));
        Assert.Equal(0, s.Wire); // the confirmation belonged to the old endpoint
        Assert.False(s.VerifiedSize);
    }

    [Fact]
    public void Pmtu_PongWithAWrongNonceConfirmsNothing()
    {
        PmtuState s = Pmtu();
        Span<Effect> effects = stackalloc Effect[2];
        int n = PmtuStep(ref s, PmtuTick(), 1000, effects);
        long nonce = Probe(effects, n)!.Value.Nonce;

        Assert.Equal(0, PmtuStep(ref s, PmtuAck(nonce + 1), 1010, effects));
        Assert.True(s.Outstanding);
        Assert.Equal(0, s.Wire);

        Assert.Equal(0, PmtuStep(ref s, PmtuAck(nonce), 1020, effects));
        Assert.False(s.Outstanding);
        Assert.Equal(1328, s.Wire);
    }

    // ------------------------------------------------------------------ keepalive: cadence

    [Fact]
    public void Keepalive_FiresOnTheFirstEligibleTick_ThenExactlyAtEachIntervalBoundary()
    {
        KeepaliveState s = Keepalive(intervalMs: 1000);
        Span<Effect> effects = stackalloc Effect[2];

        KeepaliveInput tick(bool eligible = true)
        {
            KeepaliveInput input = default;
            input.Kind = KeepaliveInputKind.MaintainTick;
            input.PathEligible = eligible;
            return input;
        }

        int n = KeepaliveStep(ref s, tick(), 5, effects);
        Assert.Equal(2, n);
        Assert.Equal(EffectKind.Transmit, effects[0].Kind);
        Assert.Equal(EffectPath.Direct, effects[0].Path);
        Assert.Equal(0, effects[0].Value); // the shell stamps its own send time
        Assert.Equal(EffectKind.Arm, effects[1].Kind);
        Assert.Equal(1005, effects[1].Value);

        Assert.Equal(0, KeepaliveStep(ref s, tick(), 1004, effects)); // one ms early: silence
        Assert.Equal(0, KeepaliveStep(ref s, tick(eligible: false), 1004, effects)); // closed: silence

        n = KeepaliveStep(ref s, tick(), 1005, effects); // exactly on the boundary
        Assert.Equal(2, n);
        Assert.Equal(2005, effects[1].Value);

        // An ineligible stretch (Closed) never advances the cadence.
        Assert.Equal(0, KeepaliveStep(ref s, tick(eligible: false), 2000, effects));
        n = KeepaliveStep(ref s, tick(), 2005, effects);
        Assert.Equal(2, n);
        Assert.Equal(3005, effects[1].Value);
    }

    [Fact]
    public void Keepalive_ZeroIntervalIsOff()
    {
        KeepaliveState s = Keepalive(intervalMs: 0);
        Span<Effect> effects = stackalloc Effect[2];
        KeepaliveInput input = default;
        input.Kind = KeepaliveInputKind.MaintainTick;
        input.PathEligible = true;
        Assert.Equal(0, KeepaliveStep(ref s, input, 0, effects));
        Assert.Equal(0, KeepaliveStep(ref s, input, long.MaxValue / 2, effects));
    }

    // ------------------------------------------------------------------ keepalive: probe ladder

    [Fact]
    public void Keepalive_UnansweredProbesEscalateOnExactDeadlines_ToNotifyThenReset()
    {
        KeepaliveState s = Keepalive(timeoutMs: 300, maxUnanswered: 3);
        Span<Effect> effects = stackalloc Effect[2];

        KeepaliveInput ProbeTickFor(int path = EffectPath.Direct)
        {
            KeepaliveInput input = default;
            input.Kind = KeepaliveInputKind.ProbeTick;
            input.PathEligible = true;
            input.Path = path;
            return input;
        }

        int n = KeepaliveStep(ref s, ProbeTickFor(), 1000, effects);
        (long nonce, long deadline) = DirectProbe(effects, n);
        Assert.Equal(1000 | KeepaliveMachine.ProbeMarker, nonce);
        Assert.Equal(1300, deadline);
        Assert.True(nonce < 0); // sign-bit marker: never mistaken for a caller ping timestamp

        Assert.Equal(0, KeepaliveStep(ref s, ProbeTickFor(), 1299, effects)); // may still land
        Assert.True(s.ProbeOutstanding);

        Assert.Equal(0, KeepaliveStep(ref s, ProbeTickFor(), 1300, effects)); // strike one, no effect yet
        Assert.False(s.ProbeOutstanding);
        Assert.Equal(1, s.UnansweredProbes);

        n = KeepaliveStep(ref s, ProbeTickFor(), 1301, effects); // next tick sends the next probe
        Assert.Equal(1301 | KeepaliveMachine.ProbeMarker, DirectProbe(effects, n).Nonce);

        KeepaliveStep(ref s, ProbeTickFor(), 1601, effects); // strike two
        KeepaliveStep(ref s, ProbeTickFor(), 1602, effects); // probe three, deadline 1902
        n = KeepaliveStep(ref s, ProbeTickFor(), 1902, effects); // strike three

        // Max unanswered reached: a Notify, the ladder resets, no probe is armed.
        Assert.Equal(1, n);
        Assert.Equal(EffectKind.Notify, effects[0].Kind);
        Assert.Equal(EffectPath.Direct, effects[0].Path);
        Assert.Equal(0, s.UnansweredProbes);
        Assert.False(s.ProbeOutstanding);
    }

    private static (long Nonce, long Deadline) DirectProbe(Span<Effect> effects, int count)
    {
        long nonce = 0;
        long deadline = 0;
        for (int i = 0; i < count; i++)
        {
            if (effects[i].Kind == EffectKind.Transmit)
            {
                nonce = effects[i].Value;
            }
            else if (effects[i].Kind == EffectKind.Arm)
            {
                deadline = effects[i].Value;
            }
        }

        return (nonce, deadline);
    }

    [Fact]
    public void Keepalive_MatchingAckStopsTheLadder_WrongEchoDoesNot()
    {
        KeepaliveState s = Keepalive();
        Span<Effect> effects = stackalloc Effect[2];
        KeepaliveInput probeTick = default;
        probeTick.Kind = KeepaliveInputKind.ProbeTick;
        probeTick.PathEligible = true;
        probeTick.Path = EffectPath.Direct;

        int n = KeepaliveStep(ref s, probeTick, 1000, effects);
        long nonce = DirectProbe(effects, n).Nonce;

        KeepaliveInput ack = default;
        ack.Kind = KeepaliveInputKind.ProbeAcked;
        ack.Echo = nonce + 1;
        Assert.Equal(0, KeepaliveStep(ref s, ack, 1010, effects));
        Assert.True(s.ProbeOutstanding); // an unrelated echo confirms nothing

        ack.Echo = nonce;
        Assert.Equal(0, KeepaliveStep(ref s, ack, 1020, effects));
        Assert.False(s.ProbeOutstanding);
        Assert.Equal(0, s.UnansweredProbes);

        int next = KeepaliveStep(ref s, probeTick, 1030, effects);
        Assert.Equal(2, next); // alive again: fresh probe, fresh nonce
        Assert.NotEqual(nonce, DirectProbe(effects, next).Nonce);
    }

    [Fact]
    public void Keepalive_RecentActivityForgetsAHalfFinishedLadder()
    {
        KeepaliveState s = Keepalive();
        Span<Effect> effects = stackalloc Effect[2];
        KeepaliveInput idleTick = default;
        idleTick.Kind = KeepaliveInputKind.ProbeTick;
        idleTick.PathEligible = true;
        idleTick.Path = EffectPath.Direct;
        KeepaliveInput activeTick = idleTick;
        activeTick.RecentActivity = true;

        KeepaliveStep(ref s, idleTick, 1000, effects); // probe one, deadline 1300
        KeepaliveStep(ref s, idleTick, 1300, effects); // strike one
        KeepaliveStep(ref s, idleTick, 1301, effects); // probe two, deadline 1601
        Assert.True(s.ProbeOutstanding);
        Assert.Equal(1, s.UnansweredProbes);

        Assert.Equal(0, KeepaliveStep(ref s, activeTick, 1500, effects)); // traffic returned
        Assert.False(s.ProbeOutstanding);
        Assert.Equal(0, s.UnansweredProbes);
    }

    [Fact]
    public void Keepalive_RelayProbesRidePlainPings_NoNonceIsRecorded()
    {
        KeepaliveState s = Keepalive();
        Span<Effect> effects = stackalloc Effect[2];
        KeepaliveInput probeTick = default;
        probeTick.Kind = KeepaliveInputKind.ProbeTick;
        probeTick.PathEligible = true;
        probeTick.Path = EffectPath.Relay;

        int n = KeepaliveStep(ref s, probeTick, 1000, effects);
        Assert.Equal(2, n);
        Assert.Equal(EffectPath.Relay, effects[0].Path);
        Assert.Equal(0, effects[0].Value); // the shell's own ping carries no machine nonce
        Assert.True(s.ProbeOutstanding);
        Assert.Equal(0, s.ProbeNonce);
        Assert.Equal(1300, effects[1].Value);
    }

    [Fact]
    public void Keepalive_PathChangedDropsTheLadder()
    {
        KeepaliveState s = Keepalive();
        Span<Effect> effects = stackalloc Effect[2];
        KeepaliveInput probeTick = default;
        probeTick.Kind = KeepaliveInputKind.ProbeTick;
        probeTick.PathEligible = true;
        probeTick.Path = EffectPath.Direct;
        KeepaliveStep(ref s, probeTick, 1000, effects);
        KeepaliveStep(ref s, probeTick, 1300, effects); // strike one

        KeepaliveInput changed = default;
        changed.Kind = KeepaliveInputKind.PathChanged;
        Assert.Equal(0, KeepaliveStep(ref s, changed, 1400, effects));
        Assert.False(s.ProbeOutstanding);
        Assert.Equal(0, s.UnansweredProbes);
    }

    // ------------------------------------------------------------------ keepalive: RTT EWMA

    [Fact]
    public void Keepalive_RttEwmaMatchesTheEngineFormula()
    {
        KeepaliveState s = Keepalive();
        Span<Effect> effects = stackalloc Effect[2];

        KeepaliveInput Sample(long echo)
        {
            KeepaliveInput input = default;
            input.Kind = KeepaliveInputKind.RttSample;
            input.Echo = echo;
            return input;
        }

        KeepaliveStep(ref s, Sample(1000), 1030, effects); // 30 ms
        Assert.Equal(30 * TimeSpan.TicksPerMillisecond, (long)s.RttEwmaTicks);

        KeepaliveStep(ref s, Sample(2000), 2050, effects); // 50 ms sample, 0.25 gain
        Assert.Equal(35 * TimeSpan.TicksPerMillisecond, (long)s.RttEwmaTicks);
    }

    // ------------------------------------------------------------------ path selector

    private static int SelectorStep(ref PathSelectorState s, in PathSelectorInput input, Span<Effect> effects) =>
        PathSelectorMachine.Step(ref s, in input, new Tick(1000), effects);

    private static PathSelectorInput Selector(PathSelectorInputKind kind) => new() { Kind = kind };

    [Fact]
    public void PathSelector_DirectEvidenceOpensEveryLivePhase_AndClosedAbsorbs()
    {
        Span<Effect> effects = stackalloc Effect[1];
        foreach (ConnPhase phase in new[] { ConnPhase.Punching, ConnPhase.Degraded, ConnPhase.Dead })
        {
            PathSelectorState s = PathSelectorState.Create(phase, PathSel.None);
            int n = SelectorStep(ref s, Selector(PathSelectorInputKind.DirectConfirmed), effects);
            Assert.Equal(1, n);
            Assert.Equal(ConnPhase.Open, s.Phase);
            Assert.Equal(PathSel.Direct, s.Path);
            // The verdict packs the new pair: phase << 8 | path.
            Assert.Equal(((long)ConnPhase.Open << (int)PathSelectorMachine.VerdictShift) | (uint)(byte)PathSel.Direct, effects[0].Value);
        }

        // Open + direct is the steady state: a fresh confirmation is not a transition.
        PathSelectorState steady = PathSelectorState.Create(ConnPhase.Open, PathSel.Direct);
        Assert.Equal(0, SelectorStep(ref steady, Selector(PathSelectorInputKind.DirectConfirmed), effects));

        // Closed is absorbing: stray frames never revive a closed connection.
        PathSelectorState closed = PathSelectorState.Create(ConnPhase.Closed, PathSel.None);
        Assert.Equal(0, SelectorStep(ref closed, Selector(PathSelectorInputKind.DirectConfirmed), effects));
        Assert.Equal(ConnPhase.Closed, closed.Phase);
    }

    [Fact]
    public void PathSelector_RelayEvidenceDegradesOnlyPendingPhases_WhenThePeerIsConfirmed()
    {
        Span<Effect> effects = stackalloc Effect[1];
        foreach (ConnPhase phase in new[] { ConnPhase.Punching, ConnPhase.Dead })
        {
            PathSelectorInput input = Selector(PathSelectorInputKind.RelayConfirmed);
            input.PeerConfirmed = true;
            PathSelectorState s = PathSelectorState.Create(phase, PathSel.None);
            Assert.Equal(1, SelectorStep(ref s, in input, effects));
            Assert.Equal(ConnPhase.Degraded, s.Phase);
            Assert.Equal(PathSel.Relay, s.Path);
        }

        PathSelectorInput unconfirmed = Selector(PathSelectorInputKind.RelayConfirmed);
        unconfirmed.PeerConfirmed = false;
        PathSelectorState pending = PathSelectorState.Create(ConnPhase.Punching, PathSel.None);
        Assert.Equal(0, SelectorStep(ref pending, in unconfirmed, effects)); // relay proves reachability, not the peer

        PathSelectorInput signaling = Selector(PathSelectorInputKind.RelayConfirmed);
        signaling.PeerConfirmed = true;
        signaling.RelaySignalingOnly = true;
        PathSelectorState reserved = PathSelectorState.Create(ConnPhase.Punching, PathSel.None);
        Assert.Equal(0, SelectorStep(ref reserved, in signaling, effects)); // signaling relays never carry sessions

        PathSelectorInput live = Selector(PathSelectorInputKind.RelayConfirmed);
        live.PeerConfirmed = true;
        PathSelectorState open = PathSelectorState.Create(ConnPhase.Open, PathSel.Direct);
        Assert.Equal(0, SelectorStep(ref open, in live, effects)); // relay evidence never displaces direct
    }

    [Fact]
    public void PathSelector_LostDirectFallsToRelay_OrBackToPunching()
    {
        Span<Effect> effects = stackalloc Effect[1];
        PathSelectorInput withRelay = Selector(PathSelectorInputKind.DirectLost);
        withRelay.RelayUsable = true;
        PathSelectorState open = PathSelectorState.Create(ConnPhase.Open, PathSel.Direct);
        Assert.Equal(1, SelectorStep(ref open, in withRelay, effects));
        Assert.Equal(ConnPhase.Degraded, open.Phase);
        Assert.Equal(PathSel.Relay, open.Path);

        PathSelectorInput withoutRelay = Selector(PathSelectorInputKind.DirectLost);
        PathSelectorState open2 = PathSelectorState.Create(ConnPhase.Open, PathSel.Direct);
        Assert.Equal(1, SelectorStep(ref open2, in withoutRelay, effects));
        Assert.Equal(ConnPhase.Punching, open2.Phase);
        Assert.Equal(PathSel.None, open2.Path);

        // Degraded with a live relay keeps it; without one there is nothing to send on.
        PathSelectorState degradedLive = PathSelectorState.Create(ConnPhase.Degraded, PathSel.Relay);
        Assert.Equal(0, SelectorStep(ref degradedLive, in withRelay, effects));
        PathSelectorState degradedDead = PathSelectorState.Create(ConnPhase.Degraded, PathSel.Relay);
        Assert.Equal(1, SelectorStep(ref degradedDead, in withoutRelay, effects));
        Assert.Equal(ConnPhase.Punching, degradedDead.Phase);

        // Pending connections have no carrying path to lose.
        PathSelectorState punching = PathSelectorState.Create(ConnPhase.Punching, PathSel.None);
        Assert.Equal(0, SelectorStep(ref punching, in withoutRelay, effects));
    }

    [Fact]
    public void PathSelector_ForcedClosedClearsThePath_DeadKeepsIt()
    {
        Span<Effect> effects = stackalloc Effect[1];
        PathSelectorInput close = Selector(PathSelectorInputKind.Forced);
        close.ForcedPhase = (byte)ConnPhase.Closed;
        PathSelectorState open = PathSelectorState.Create(ConnPhase.Open, PathSel.Direct);
        Assert.Equal(1, SelectorStep(ref open, in close, effects));
        Assert.Equal(ConnPhase.Closed, open.Phase);
        Assert.Equal(PathSel.None, open.Path);

        PathSelectorInput condemn = Selector(PathSelectorInputKind.Forced);
        condemn.ForcedPhase = (byte)ConnPhase.Dead;
        PathSelectorState relayed = PathSelectorState.Create(ConnPhase.Degraded, PathSel.Relay);
        Assert.Equal(1, SelectorStep(ref relayed, in condemn, effects));
        Assert.Equal(ConnPhase.Dead, relayed.Phase);
        Assert.Equal(PathSel.Relay, relayed.Path); // Dead is revivable; the path survives for the revival
    }

    [Fact]
    public void PathSelector_AnEventuallyGoodPathReachesOpenAgainAfterEveryFall()
    {
        // P2 in miniature: whatever the fall, live direct evidence restores Open, and
        // the fall never strands the session in Open on a dead path.
        Span<Effect> effects = stackalloc Effect[1];
        PathSelectorState s = PathSelectorState.Create(ConnPhase.Punching, PathSel.None);

        PathSelectorInput relay = Selector(PathSelectorInputKind.RelayConfirmed);
        relay.PeerConfirmed = true;
        Assert.Equal(1, SelectorStep(ref s, in relay, effects));
        Assert.Equal(ConnPhase.Degraded, s.Phase);

        Assert.Equal(1, SelectorStep(ref s, Selector(PathSelectorInputKind.DirectConfirmed), effects));
        Assert.Equal(ConnPhase.Open, s.Phase);

        Assert.Equal(1, SelectorStep(ref s, Selector(PathSelectorInputKind.DirectLost), effects));
        Assert.Equal(ConnPhase.Punching, s.Phase);

        Assert.Equal(1, SelectorStep(ref s, Selector(PathSelectorInputKind.DirectConfirmed), effects));
        Assert.Equal(ConnPhase.Open, s.Phase);
        Assert.Equal(PathSel.Direct, s.Path);
    }

    // ------------------------------------------------------------------ handshake

    private static HandshakeState Handshake(uint self = 0xA0A0_1010, bool offeredCrypto = false) =>
        HandshakeState.Create(self, offeredCrypto);

    private static (long Kind, long Reply, long Fail) HandshakeStep(ref HandshakeState s, in HandshakeInput input, Span<Effect> effects)
    {
        int n = HandshakeMachine.Step(ref s, in input, new Tick(1000), effects);
        long kind = 0, reply = -1, fail = 0;
        for (int i = 0; i < n; i++)
        {
            if (effects[i].Kind == EffectKind.Notify) kind = effects[i].Value;
            else if (effects[i].Kind == EffectKind.Transmit) reply = effects[i].Value;
            else if (effects[i].Kind == EffectKind.Close) fail = effects[i].Value;
        }

        return (kind, reply, fail);
    }

    [Fact]
    public void Handshake_PlaintextPuncLatchesTheTokenAndEarnsALegacyPack()
    {
        HandshakeState s = Handshake();
        Span<Effect> effects = stackalloc Effect[2];
        HandshakeInput punc = default;
        punc.Kind = HandshakeInputKind.PuncBegin;
        punc.FrameToken = 0x0BADC0DE;
        (long kind, long reply, long fail) = HandshakeStep(ref s, in punc, effects);
        Assert.Equal(0, kind);
        Assert.Equal(HandshakeMachine.ReplyPackLegacy, reply);
        Assert.Equal(0, fail);
        Assert.True(s.RemoteTokenKnown);
        Assert.Equal(0x0BADC0DEu, s.RemoteToken);
    }

    [Fact]
    public void Handshake_CryptoPuncSequencesKeyAgreementBetweenTheVerdicts()
    {
        HandshakeState s = Handshake(offeredCrypto: true);
        Span<Effect> effects = stackalloc Effect[2];

        HandshakeInput punc = default;
        punc.Kind = HandshakeInputKind.PuncBegin;
        punc.CryptoBody = true;
        punc.PinMatches = true;
        punc.FrameToken = 0x0BADC0DE;
        (long kind, long reply, _) = HandshakeStep(ref s, in punc, effects);
        Assert.Equal(HandshakeMachine.NeedKeys, kind);
        Assert.Equal(-1, reply);
        Assert.False(s.RemoteTokenKnown); // a low-order PUNC must not install even a provisional token

        // Rejected keys leave the latch untouched; an honest retry still works.
        HandshakeInput badKeys = default;
        badKeys.Kind = HandshakeInputKind.PuncKeys;
        badKeys.Accepted = false;
        badKeys.FrameToken = 0x0BADC0DE;
        Assert.Equal(HandshakeMachine.RejectPuncKeys, HandshakeStep(ref s, in badKeys, effects).Kind);
        Assert.False(s.RemoteTokenKnown);

        HandshakeInput keys = badKeys;
        keys.Accepted = true;
        (kind, reply, _) = HandshakeStep(ref s, in keys, effects);
        Assert.Equal(0, kind);
        Assert.Equal(HandshakeMachine.ReplyPackCrypto, reply);
        Assert.True(s.RemoteTokenKnown);
        Assert.Equal(0x0BADC0DEu, s.RemoteToken);
    }

    [Fact]
    public void Handshake_PuncRefusals_PinBeforeTokenBeforeMixedMode()
    {
        HandshakeState s = Handshake(offeredCrypto: true);
        s.RemoteToken = 0x1111_2222;
        s.RemoteTokenKnown = true;
        s.RemoteTokenAuthenticated = true;
        Span<Effect> effects = stackalloc Effect[2];

        // All three would apply; the pin verdict wins.
        HandshakeInput pinned = default;
        pinned.Kind = HandshakeInputKind.PuncBegin;
        pinned.CryptoBody = true;
        pinned.PinMatches = false;
        pinned.FrameToken = 0x9999_9999; // not the latched token
        Assert.Equal(HandshakeMachine.RejectPin, HandshakeStep(ref s, in pinned, effects).Kind);

        // Stale frames from an older connection: a known token that stopped matching.
        HandshakeInput stale = default;
        stale.Kind = HandshakeInputKind.PuncBegin;
        stale.CryptoBody = true;
        stale.PinMatches = true;
        stale.FrameToken = 0x9999_9999;
        Assert.Equal(HandshakeMachine.RejectPuncToken, HandshakeStep(ref s, in stale, effects).Kind);

        // Crossed modes: plaintext PUNC on a crypto connection.
        HandshakeInput crossed = default;
        crossed.Kind = HandshakeInputKind.PuncBegin;
        crossed.CryptoBody = false;
        crossed.FrameToken = 0x1111_2222; // token matches, so the mode check is reached
        Assert.Equal(HandshakeMachine.RejectMixedMode, HandshakeStep(ref s, in crossed, effects).Kind);

        // An UNauthenticated latched token may still be replaced by the real one.
        s.RemoteTokenAuthenticated = false;
        HandshakeInput replace = default;
        replace.Kind = HandshakeInputKind.PuncBegin;
        replace.CryptoBody = true;
        replace.PinMatches = true;
        replace.FrameToken = 0x3333_4444;
        Assert.Equal(HandshakeMachine.NeedKeys, HandshakeStep(ref s, in replace, effects).Kind);
    }

    [Fact]
    public void Handshake_PackEchoAndLengthVerdicts()
    {
        HandshakeState s = Handshake();
        Span<Effect> effects = stackalloc Effect[2];

        HandshakeInput pack = default;
        pack.Kind = HandshakeInputKind.PackBegin;
        pack.BodyPlausible = false;
        Assert.Equal(HandshakeMachine.RejectPackLength, HandshakeStep(ref s, in pack, effects).Kind);

        pack.BodyPlausible = true;
        pack.FrameToken = 0xDEAD_BEEF; // not ours
        Assert.Equal(HandshakeMachine.RejectPackEcho, HandshakeStep(ref s, in pack, effects).Kind);

        pack.FrameToken = 0xA0A0_1010; // ours
        pack.LengthClassOk = false;
        Assert.Equal(0, HandshakeStep(ref s, in pack, effects).Kind); // silently ignored
        Assert.False(s.RemoteTokenKnown);

        // Legacy body on a plaintext connection: latch the responder's token.
        pack.LengthClassOk = true;
        pack.CryptoBody = false;
        pack.PeerToken = 0x5555_6666;
        Assert.Equal(0, HandshakeStep(ref s, in pack, effects).Kind);
        Assert.True(s.RemoteTokenKnown);
        Assert.Equal(0x5555_6666u, s.RemoteToken);
    }

    [Fact]
    public void Handshake_Mac1Gate_RefusesSilentlyBeforeEveryOtherVerdict()
    {
        Span<Effect> effects = stackalloc Effect[2];

        // PUNC with a failed mac1: silent refusal, and it wins over every other check —
        // feed it a bad pin AND a stale token AND crossed modes to prove ordering.
        HandshakeState s = Handshake(offeredCrypto: true);
        s.RemoteToken = 0x1111_2222;
        s.RemoteTokenKnown = true;
        s.RemoteTokenAuthenticated = true;
        HandshakeInput badPunc = default;
        badPunc.Kind = HandshakeInputKind.PuncBegin;
        badPunc.CryptoBody = true;
        badPunc.PinMatches = false;
        badPunc.Mac1Present = true;
        badPunc.Mac1Ok = false;
        badPunc.FrameToken = 0x9999_9999; // not the latched token
        (long kind, long reply, long fail) = HandshakeStep(ref s, in badPunc, effects);
        Assert.Equal(HandshakeMachine.RejectMac1, kind);
        Assert.Equal(-1, reply);       // no PACK
        Assert.Equal(0, fail);         // no Close — the frame simply did not exist
        Assert.Equal(0x1111_2222u, s.RemoteToken); // no state moved

        // PACK with a failed mac1: silent before the echo verdict too — a forger must not
        // even learn whether the echoed token was right.
        HandshakeState dialer = Handshake(offeredCrypto: true);
        HandshakeInput badPack = default;
        badPack.Kind = HandshakeInputKind.PackBegin;
        badPack.BodyPlausible = true;
        badPack.LengthClassOk = true;
        badPack.CryptoBody = true;
        badPack.PinMatches = false;
        badPack.Mac1Present = true;
        badPack.Mac1Ok = false;
        badPack.FrameToken = 0xDEAD_BEEF; // wrong echo
        (kind, reply, fail) = HandshakeStep(ref dialer, in badPack, effects);
        Assert.Equal(HandshakeMachine.RejectMac1, kind);
        Assert.Equal(-1, reply);
        Assert.Equal(0, fail);
        Assert.False(dialer.RemoteTokenKnown);

        // Present and verified: the frame proceeds exactly as its v3 twin would.
        HandshakeState ok = Handshake(offeredCrypto: true);
        HandshakeInput goodPunc = default;
        goodPunc.Kind = HandshakeInputKind.PuncBegin;
        goodPunc.CryptoBody = true;
        goodPunc.PinMatches = true;
        goodPunc.Mac1Present = true;
        goodPunc.Mac1Ok = true;
        goodPunc.FrameToken = 0x0BAD_C0DE;
        (kind, reply, _) = HandshakeStep(ref ok, in goodPunc, effects);
        Assert.Equal(HandshakeMachine.NeedKeys, kind);
        Assert.Equal(-1, reply);

        // Absent (v3 during the support window): nothing changes for today's shapes.
        HandshakeState v3 = Handshake(offeredCrypto: true);
        HandshakeInput plain = default;
        plain.Kind = HandshakeInputKind.PuncBegin;
        plain.CryptoBody = true;
        plain.PinMatches = true;
        plain.FrameToken = 0x0BAD_C0DE;
        Assert.Equal(HandshakeMachine.NeedKeys, HandshakeStep(ref v3, in plain, effects).Kind);
    }

    [Fact]
    public void Handshake_CryptoPackFailsClosed_AndSendsTheThirdFlightOnce()
    {
        HandshakeState s = Handshake(offeredCrypto: true);
        Span<Effect> effects = stackalloc Effect[2];

        // A stripped handshake never falls back to plaintext.
        HandshakeInput stripped = default;
        stripped.Kind = HandshakeInputKind.PackBegin;
        stripped.BodyPlausible = true;
        stripped.LengthClassOk = true;
        stripped.CryptoBody = false;
        stripped.FrameToken = 0xA0A0_1010;
        (long kind, _, long fail) = HandshakeStep(ref s, in stripped, effects);
        Assert.Equal(HandshakeMachine.RejectMixedMode, kind);
        Assert.Equal(HandshakeMachine.RejectMixedMode, fail);

        // A pinned static key that stops matching is a MITM: refused, failed.
        HandshakeInput mitm = default;
        mitm.Kind = HandshakeInputKind.PackBegin;
        mitm.BodyPlausible = true;
        mitm.LengthClassOk = true;
        mitm.CryptoBody = true;
        mitm.PinMatches = false;
        mitm.FrameToken = 0xA0A0_1010;
        (kind, _, fail) = HandshakeStep(ref s, in mitm, effects);
        Assert.Equal(HandshakeMachine.RejectPin, kind);
        Assert.Equal(HandshakeMachine.RejectPin, fail);

        // Keys rejected, then confirm rejected: each with its own kind, only confirm fails closed.
        HandshakeInput begin = default;
        begin.Kind = HandshakeInputKind.PackBegin;
        begin.BodyPlausible = true;
        begin.LengthClassOk = true;
        begin.CryptoBody = true;
        begin.PinMatches = true;
        begin.FrameToken = 0xA0A0_1010;
        begin.PeerToken = 0x7777_8888;
        Assert.Equal(HandshakeMachine.NeedKeys, HandshakeStep(ref s, in begin, effects).Kind);

        HandshakeInput keys = default;
        keys.Kind = HandshakeInputKind.PackKeys;
        keys.FrameToken = 0xA0A0_1010;
        keys.PeerToken = 0x7777_8888;
        keys.Accepted = false;
        Assert.Equal(HandshakeMachine.RejectPuncKeys, HandshakeStep(ref s, in keys, effects).Kind);
        Assert.False(s.RemoteTokenKnown);

        keys.Accepted = true;
        keys.ConfirmOk = false;
        (kind, _, fail) = HandshakeStep(ref s, in keys, effects);
        Assert.Equal(HandshakeMachine.RejectPackConfirm, kind);
        Assert.Equal(HandshakeMachine.RejectPackConfirm, fail);
        Assert.False(s.RemoteTokenKnown);

        // Success: verified keys latch the token, the confirm goes out once, and a
        // replayed PACK re-confirms without a second flight.
        keys.ConfirmOk = true;
        (kind, long reply, long none) = HandshakeStep(ref s, in keys, effects);
        Assert.Equal(HandshakeMachine.PeerConfirmed, kind);
        Assert.Equal(HandshakeMachine.ReplyHsck, reply);
        Assert.Equal(0, none);
        Assert.True(s.RemoteTokenKnown);
        Assert.Equal(0x7777_8888u, s.RemoteToken);

        (kind, reply, _) = HandshakeStep(ref s, in keys, effects);
        Assert.Equal(HandshakeMachine.PeerConfirmed, kind);
        Assert.Equal(-1, reply);
    }

    [Fact]
    public void Handshake_AnAuthenticatedTokenSurvivesEditedReplays()
    {
        HandshakeState s = Handshake(offeredCrypto: true);
        s.RemoteToken = 0x1111_2222;
        s.RemoteTokenKnown = true;
        s.RemoteTokenAuthenticated = true;
        Span<Effect> effects = stackalloc Effect[2];

        HandshakeInput edited = default;
        edited.Kind = HandshakeInputKind.PackBegin;
        edited.BodyPlausible = true;
        edited.LengthClassOk = true;
        edited.CryptoBody = true;
        edited.PinMatches = true;
        edited.FrameToken = 0xA0A0_1010;
        edited.PeerToken = 0x9999_9999; // the authenticated session's token, edited
        Assert.Equal(HandshakeMachine.RejectPackPeerToken, HandshakeStep(ref s, in edited, effects).Kind);
        Assert.Equal(0x1111_2222u, s.RemoteToken);
    }

    // ------------------------------------------------------------------ punch scheduler

    private static PunchState Punch(long connectTimeoutMs = 60_000) => PunchState.Create(connectTimeoutMs);

    private static PunchInput PunchTick(byte phase = (byte)ConnPhase.Punching, long now = 5000, long kickedAt = 0, long deadSince = -1)
    {
        PunchInput input = default;
        input.Kind = PunchInputKind.Tick;
        input.Phase = phase;
        input.NowMs = now;
        input.KickedAtMs = kickedAt;
        input.DeadSinceMs = deadSince;
        return input;
    }

    private static (bool Stop, bool Condemn, bool Lookup, bool Announce, bool Tcp, bool Relay, bool Direct, bool LinkLocal, long WakeAt) PunchFx(
        Span<Effect> effects, int n)
    {
        bool stop = false, condemn = false, lookup = false, announce = false, tcp = false;
        bool relay = false, direct = false, linkLocal = false;
        long wakeAt = 0;
        for (int i = 0; i < n; i++)
        {
            switch (effects[i].Kind)
            {
                case EffectKind.Notify:
                    switch ((PunchNotify)effects[i].Value)
                    {
                        case PunchNotify.Stop: stop = true; break;
                        case PunchNotify.CondemnDead: condemn = true; break;
                        case PunchNotify.Lookup: lookup = true; break;
                        case PunchNotify.Announce: announce = true; break;
                        case PunchNotify.TcpProbe: tcp = true; break;
                    }
                    break;
                case EffectKind.Transmit:
                    if (effects[i].Path == EffectPath.Relay) relay = true;
                    else if (effects[i].Path == EffectPath.DirectLinkLocal) linkLocal = true;
                    else if (effects[i].Path == EffectPath.Direct) direct = true;
                    break;
                case EffectKind.Arm:
                    wakeAt = effects[i].Value;
                    break;
            }
        }

        return (stop, condemn, lookup, announce, tcp, relay, direct, linkLocal, wakeAt);
    }

    [Fact]
    public void Punch_ConnectTimeoutCondemns_AndOnlyRealSessionsBeaconAfterward()
    {
        PunchState s = Punch(connectTimeoutMs: 5000);
        Span<Effect> effects = stackalloc Effect[8];

        // Before the deadline: no verdict, ordinary scheduling.
        PunchInput before = PunchTick(now: 5000);
        var pre = PunchFx(effects, PunchSchedulerMachine.Step(ref s, in before, new Tick(5000), effects));
        Assert.False(pre.Condemn);

        PunchInput deadline = PunchTick(now: 5001);
        int n = PunchSchedulerMachine.Step(ref s, in deadline, new Tick(5001), effects);
        var husk = PunchFx(effects, n);
        Assert.True(husk.Condemn);
        Assert.True(husk.Stop); // never-connected husks never beacon: no reflection amplification

        // A real session keeps beeping until the five-minute budget is spent.
        PunchState live = Punch(connectTimeoutMs: 5000);
        PunchInput condemned = PunchTick(now: 5001);
        condemned.ConnectedCompleted = true;
        var beacons = PunchFx(effects, PunchSchedulerMachine.Step(ref live, in condemned, new Tick(5001), effects));
        Assert.True(beacons.Condemn);
        Assert.False(beacons.Stop);
        Assert.True(beacons.Relay);
        Assert.Equal(5001 + PunchSchedulerMachine.DeadBeaconPaceMs, beacons.WakeAt);

        // Regression: on a host up longer than the budget, the condemn tick still sees
        // the PRE-stamp dead-since (0). The budget must read the condemn's own instant,
        // not the stale zero — or every long-lived host stops the beacon at birth and
        // dead sessions never revive.
        PunchState longUp = Punch(connectTimeoutMs: 5000);
        PunchInput lateCondemn = PunchTick(now: 10_000_000_000);
        lateCondemn.ConnectedCompleted = true;
        lateCondemn.DeadSinceMs = 0; // captured before the shell stamps it
        var stillBeacons = PunchFx(effects, PunchSchedulerMachine.Step(ref longUp, in lateCondemn, new Tick(0), effects));
        Assert.True(stillBeacons.Condemn);
        Assert.False(stillBeacons.Stop);
        Assert.True(stillBeacons.Relay);

        // An UNSTAMPED dead-since on an ordinary Dead tick keeps the old shell reading:
        // the budget reads as long spent and the loop goes quiet.
        PunchState unstamped = Punch();
        PunchInput stale = PunchTick(phase: (byte)ConnPhase.Dead, now: 10_000_000_000, deadSince: 0);
        Assert.True(PunchFx(effects, PunchSchedulerMachine.Step(ref unstamped, in stale, new Tick(0), effects)).Stop);

        // Dead past the budget: passive revival is all that is left.
        PunchInput spent = PunchTick(phase: (byte)ConnPhase.Dead, now: 5001 + PunchSchedulerMachine.DeadBeaconBudgetMs + 1, deadSince: 5001);
        var after = PunchFx(effects, PunchSchedulerMachine.Step(ref live, in spent, new Tick(6001), effects));
        Assert.True(after.Stop);
        Assert.False(after.Relay);

        // Inside the budget the beacon keeps a slow pace.
        PunchInput inside = PunchTick(phase: (byte)ConnPhase.Dead, now: 5001 + 1000, deadSince: 5001);
        var pacing = PunchFx(effects, PunchSchedulerMachine.Step(ref live, in inside, new Tick(6100), effects));
        Assert.False(pacing.Stop);
        Assert.True(pacing.Relay);
    }

    [Fact]
    public void Punch_OpenWithoutTcpStops_AndTheUpgradeBudgetIsPerRun()
    {
        PunchState s = Punch();
        Span<Effect> effects = stackalloc Effect[8];

        // Direct already won on UDP: nothing left to upgrade.
        PunchInput open = PunchTick(phase: (byte)ConnPhase.Open);
        open.OpenWithoutDirectTcp = true;
        var won = PunchFx(effects, PunchSchedulerMachine.Step(ref s, in open, new Tick(5000), effects));
        Assert.True(won.Stop);

        // Degraded poking is budgeted: MaxUpgradeAttempts rounds, then passive.
        PunchState degraded = Punch();
        PunchInput tick = PunchTick(phase: (byte)ConnPhase.Degraded);
        bool stopped = false;
        for (int i = 0; i <= PunchSchedulerMachine.MaxUpgradeAttempts; i++)
        {
            var r = PunchFx(effects, PunchSchedulerMachine.Step(ref degraded, in tick, new Tick(5000 + i * 1000), effects));
            stopped = r.Stop;
        }

        Assert.True(stopped);

        // A fresh kick resets the budget — a new run pokes again.
        PunchInput kick = default;
        kick.Kind = PunchInputKind.Kick;
        PunchSchedulerMachine.Step(ref degraded, in kick, new Tick(9999), Span<Effect>.Empty);
        var fresh = PunchFx(effects, PunchSchedulerMachine.Step(ref degraded, in tick, new Tick(10_000), effects));
        Assert.False(fresh.Stop);
    }

    [Fact]
    public void Punch_SymmetricTrickleThrottlesDirects_PredictionHoldsThem()
    {
        PunchState s = Punch();
        Span<Effect> effects = stackalloc Effect[8];
        PunchInput tick = PunchTick();
        tick.SymmetricHint = true;

        // Window open (never punched): directs go out and stamp the clock.
        var first = PunchFx(effects, PunchSchedulerMachine.Step(ref s, in tick, new Tick(5000), effects));
        Assert.True(first.Direct);
        Assert.True(first.Relay);

        // Half a second later the trickle window is closed: relays only.
        PunchInput throttledInput = PunchTick(now: 5500);
        throttledInput.SymmetricHint = true;
        var throttled = PunchFx(effects, PunchSchedulerMachine.Step(ref s, in throttledInput, new Tick(5500), effects));
        Assert.False(throttled.Direct);
        Assert.True(throttled.Relay);

        // A fresh window at +1s, but port prediction holds directs — and does not
        // consume the trickle stamp, so the window stays open for the next tick.
        PunchInput predicting = PunchTick(now: 6001);
        predicting.SymmetricHint = true;
        predicting.PredictionActive = true;
        var held = PunchFx(effects, PunchSchedulerMachine.Step(ref s, in predicting, new Tick(6001), effects));
        Assert.False(held.Direct);
        Assert.True(held.Relay);
        Assert.False(held.LinkLocal);

        PunchInput released = PunchTick(now: 6100);
        released.SymmetricHint = true;
        var resumed = PunchFx(effects, PunchSchedulerMachine.Step(ref s, in released, new Tick(6100), effects));
        Assert.True(resumed.Direct); // the window survived the hold
    }

    [Fact]
    public void Punch_LinkLocalWaitsForOrdinaryRoutes_AndTheExchangeGatesDirects()
    {
        PunchState s = Punch();
        Span<Effect> effects = stackalloc Effect[8];

        // Before the fallback delay: ordinary directs yes, link-local no.
        PunchInput early = PunchTick(now: 5000 + PunchSchedulerMachine.LinkLocalFallbackDelayMs - 1, kickedAt: 5000);
        var e = PunchFx(effects, PunchSchedulerMachine.Step(ref s, in early, new Tick(5599), effects));
        Assert.True(e.Direct);
        Assert.False(e.LinkLocal);

        PunchInput late = PunchTick(now: 5000 + PunchSchedulerMachine.LinkLocalFallbackDelayMs + 1, kickedAt: 5000);
        var l = PunchFx(effects, PunchSchedulerMachine.Step(ref s, in late, new Tick(5601), effects));
        Assert.True(l.LinkLocal);

        // The peer's candidate exchange gates directs; relays are always worth a datagram.
        PunchState exchanging = Punch();
        PunchInput waiting = PunchTick(now: 9000);
        waiting.AwaitExchange = true;
        waiting.PeerCandidatesReceived = false;
        var w = PunchFx(effects, PunchSchedulerMachine.Step(ref exchanging, in waiting, new Tick(9000), effects));
        Assert.False(w.Direct);
        Assert.False(w.LinkLocal);
        Assert.True(w.Relay);

        waiting.PeerCandidatesReceived = true;
        var ready = PunchFx(effects, PunchSchedulerMachine.Step(ref exchanging, in waiting, new Tick(9100), effects));
        Assert.True(ready.Direct);
        Assert.True(ready.LinkLocal); // past the delay, exchange done
    }

    [Fact]
    public void Punch_LookupAnnounceAndTcpCadences()
    {
        PunchState s = Punch();
        Span<Effect> effects = stackalloc Effect[8];

        // Lookup: pinned key + providers, retried at most once per LookupRetryMs.
        PunchInput lookup = PunchTick(now: 5000);
        lookup.PinnedLookupPossible = true;
        var first = PunchFx(effects, PunchSchedulerMachine.Step(ref s, in lookup, new Tick(5000), effects));
        Assert.True(first.Lookup);
        PunchInput soonInput = PunchTick(now: 5500);
        soonInput.PinnedLookupPossible = true;
        var soon = PunchFx(effects, PunchSchedulerMachine.Step(ref s, in soonInput, new Tick(5500), effects));
        Assert.False(soon.Lookup);
        PunchInput laterInput = PunchTick(now: 5000 + PunchSchedulerMachine.LookupRetryMs + 1);
        laterInput.PinnedLookupPossible = true;
        var later = PunchFx(effects, PunchSchedulerMachine.Step(ref s, in laterInput, new Tick(6001), effects));
        Assert.True(later.Lookup);

        // Announce: only relay-signaling sessions still punching, on the retry window.
        PunchState announcing = Punch();
        PunchInput announce = PunchTick(now: 5000);
        announce.RelaySignalingOnly = true;
        announce.Established = true;
        announce.AnnounceRetryDue = true;
        Assert.True(PunchFx(effects, PunchSchedulerMachine.Step(ref announcing, in announce, new Tick(5000), effects)).Announce);
        announce.Phase = (byte)ConnPhase.Degraded;
        Assert.False(PunchFx(effects, PunchSchedulerMachine.Step(ref announcing, in announce, new Tick(5200), effects)).Announce);

        // TCP: eligible after the kick delay, never before.
        PunchState tcp = Punch();
        PunchInput before = PunchTick(now: PunchSchedulerMachine.TcpKickDelayMs - 1);
        before.TcpEligible = true;
        Assert.False(PunchFx(effects, PunchSchedulerMachine.Step(ref tcp, in before, new Tick(1199), effects)).Tcp);
        PunchInput after = PunchTick(now: PunchSchedulerMachine.TcpKickDelayMs + 1);
        after.TcpEligible = true;
        Assert.True(PunchFx(effects, PunchSchedulerMachine.Step(ref tcp, in after, new Tick(1201), effects)).Tcp);
    }

    [Fact]
    public void Punch_PaceFollowsThePhase()
    {
        PunchState s = Punch();
        Span<Effect> effects = stackalloc Effect[8];
        long t = 10_000;
        foreach ((byte phase, long pace) in new[]
        {
            ((byte)ConnPhase.Punching, PunchSchedulerMachine.PunchPaceMs),
            ((byte)ConnPhase.Dead, PunchSchedulerMachine.DeadBeaconPaceMs),
            ((byte)ConnPhase.Degraded, PunchSchedulerMachine.UpgradePaceMs),
            ((byte)ConnPhase.Open, PunchSchedulerMachine.UpgradePaceMs),
        })
        {
            t += 5000;
            PunchInput pacing = PunchTick(phase: phase, now: t);
            var r = PunchFx(effects, PunchSchedulerMachine.Step(ref s, in pacing, new Tick(t), effects));
            Assert.False(r.Stop);
            Assert.Equal(t + pace, r.WakeAt);
        }
    }

    // ------------------------------------------------------------------ totality and span discipline

    [Fact]
    public void Machines_AdvanceStateEvenWhenTheEffectSpanIsFull()
    {
        PmtuState p = Pmtu();
        Span<Effect> one = stackalloc Effect[1];
        int n = PmtuStep(ref p, PmtuTick(), 1000, one);
        Assert.Equal(1, n); // the Transmit fit, the Arm did not — no throw
        Assert.True(p.Outstanding);
        Assert.Equal(1328, p.ProbeSize);

        // A zero-length span reports decisions only.
        int zero = PmtuStep(ref p, PmtuTick(), 2000, Span<Effect>.Empty);
        Assert.Equal(0, zero);

        KeepaliveState k = Keepalive();
        KeepaliveInput probeTick = default;
        probeTick.Kind = KeepaliveInputKind.ProbeTick;
        probeTick.PathEligible = true;
        probeTick.Path = EffectPath.Direct;
        Assert.Equal(0, KeepaliveStep(ref k, probeTick, 1000, Span<Effect>.Empty));
        Assert.True(k.ProbeOutstanding);
    }

    [Fact]
    public void Machines_TotalOnGarbageInput_SeededSweep()
    {
        Random rng = new(0x5EED);
        Span<Effect> effects = stackalloc Effect[4];
        PmtuState p = Pmtu();
        KeepaliveState k = Keepalive(intervalMs: 100, timeoutMs: 50, maxUnanswered: 3);
        PathSelectorState sel = PathSelectorState.Create(ConnPhase.Punching, PathSel.None);
        PunchState punch = Punch();
        HandshakeState hs = Handshake(offeredCrypto: true);

        for (int i = 0; i < 10_000; i++)
        {
            PmtuInput pi = default;
            pi.Kind = (PmtuInputKind)rng.Next(256); // deliberately includes invalid kinds
            pi.PathEligible = rng.Next(2) == 0;
            pi.IPv4 = rng.Next(2) == 0;
            pi.Nonce = rng.NextInt64(long.MinValue, long.MaxValue);
            pi.WireLength = rng.Next(-1000, 5000);
            int pn = PmtuMachine.Step(ref p, in pi, new Tick(rng.NextInt64(0, long.MaxValue / 2)), effects);
            Assert.InRange(pn, 0, effects.Length);
            // The wire figure is only ever a real confirmation: unprobed, or on [floor, ceiling].
            Assert.True(p.Wire == 0 || (p.Wire >= BaseWire && p.Wire <= Math.Max(CeilingV4, CeilingV6)));

            KeepaliveInput ki = default;
            ki.Kind = (KeepaliveInputKind)rng.Next(256);
            ki.PathEligible = rng.Next(2) == 0;
            ki.RecentActivity = rng.Next(2) == 0;
            ki.Path = rng.Next(3) - 1; // includes the invalid -1
            ki.Echo = rng.NextInt64(long.MinValue, long.MaxValue);
            int kn = KeepaliveMachine.Step(ref k, in ki, new Tick(rng.NextInt64(0, long.MaxValue / 2)), effects);
            Assert.InRange(kn, 0, effects.Length);
            Assert.True(k.UnansweredProbes is >= 0 and <= 3);
            Assert.True(k.ProbeNonce == 0 || k.ProbeNonce < 0);

            PathSelectorInput si = default;
            si.Kind = (PathSelectorInputKind)rng.Next(256);
            si.PeerConfirmed = rng.Next(2) == 0;
            si.RelaySignalingOnly = rng.Next(2) == 0;
            si.RelayUsable = rng.Next(2) == 0;
            si.ForcedPhase = (byte)rng.Next(256); // includes phases that are not ConnPhase values
            int sn = PathSelectorMachine.Step(ref sel, in si, new Tick(rng.NextInt64(0, long.MaxValue / 2)), effects);
            Assert.InRange(sn, 0, effects.Length);
            Assert.True(sel.Phase is >= (ConnPhase)0 and <= ConnPhase.Closed);
            Assert.True(sel.Path is >= (PathSel)0 and <= PathSel.Relay);
            if (sel.Phase == ConnPhase.Closed)
            {
                Assert.Equal(PathSel.None, sel.Path); // Closed always clears the path
            }

            PunchInput pin = default;
            pin.Kind = (PunchInputKind)rng.Next(256);
            pin.Phase = (byte)rng.Next(256);
            pin.NowMs = rng.NextInt64(0, long.MaxValue / 4);
            pin.KickedAtMs = rng.NextInt64(0, long.MaxValue / 4);
            pin.DeadSinceMs = rng.NextInt64(-10, long.MaxValue / 4);
            bool pb1 = rng.Next(2) == 0, pb2 = rng.Next(2) == 0, pb3 = rng.Next(2) == 0;
            pin.OpenWithoutDirectTcp = pb1;
            pin.ConnectedCompleted = pb2;
            pin.PinnedLookupPossible = pb3;
            pin.RelaySignalingOnly = rng.Next(2) == 0;
            pin.Established = rng.Next(2) == 0;
            pin.SymmetricHint = rng.Next(2) == 0;
            pin.PredictionActive = rng.Next(2) == 0;
            pin.AwaitExchange = rng.Next(2) == 0;
            pin.PeerCandidatesReceived = rng.Next(2) == 0;
            pin.TcpEligible = rng.Next(2) == 0;
            pin.AnnounceRetryDue = rng.Next(2) == 0;
            int pn2 = PunchSchedulerMachine.Step(ref punch, in pin, new Tick(0), effects);
            Assert.InRange(pn2, 0, effects.Length);
            bool punchStopped = false;
            for (int e = 0; e < pn2; e++)
            {
                if (effects[e].Kind == EffectKind.Notify && effects[e].Value == (long)PunchNotify.Stop) punchStopped = true;
                if (punchStopped)
                {
                    // A stopped scheduler emits nothing schedulable after the verdict.
                    Assert.NotEqual(EffectKind.Transmit, effects[e].Kind);
                    Assert.NotEqual(EffectKind.Arm, effects[e].Kind);
                }
            }

            Assert.True(punch.UpgradeAttempts is >= 0 and <= PunchSchedulerMachine.MaxUpgradeAttempts + 1);

            HandshakeInput hi = default;
            hi.Kind = (HandshakeInputKind)rng.Next(256);
            hi.CryptoBody = rng.Next(2) == 0;
            hi.PinMatches = rng.Next(2) == 0;
            hi.BodyPlausible = rng.Next(2) == 0;
            hi.LengthClassOk = rng.Next(2) == 0;
            hi.Accepted = rng.Next(2) == 0;
            hi.ConfirmOk = rng.Next(2) == 0;
            hi.FrameToken = unchecked((uint)rng.NextInt64());
            hi.PeerToken = unchecked((uint)rng.NextInt64());
            int hn = HandshakeMachine.Step(ref hs, in hi, new Tick(0), effects);
            Assert.InRange(hn, 0, effects.Length);
        }

        // Default-constructed states (all-zero options) stay total too.
        PmtuState pz = default;
        KeepaliveState kz = default;
        for (int i = 0; i < 10_000; i++)
        {
            PmtuInput pi = default;
            pi.Kind = (PmtuInputKind)rng.Next(256);
            pi.WireLength = rng.Next(-1000, 5000);
            PmtuMachine.Step(ref pz, in pi, new Tick(rng.NextInt64(long.MinValue / 2, long.MaxValue / 2)), effects);

            KeepaliveInput ki = default;
            ki.Kind = (KeepaliveInputKind)rng.Next(256);
            ki.Echo = rng.NextInt64(long.MinValue, long.MaxValue);
            KeepaliveMachine.Step(ref kz, in ki, new Tick(rng.NextInt64(long.MinValue / 2, long.MaxValue / 2)), effects);
        }
    }
}
