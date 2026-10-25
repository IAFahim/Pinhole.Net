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
