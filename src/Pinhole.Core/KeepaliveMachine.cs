using Pinhole.Crypto;

namespace Pinhole.Core;

public enum KeepaliveInputKind : byte
{
    MaintainTick = 0,
    ProbeTick = 1,
    ProbeAcked = 2,
    PathChanged = 3,
    RttSample = 4,
}

public struct KeepaliveInput
{
    public KeepaliveInputKind Kind;
    public bool PathEligible;   // MaintainTick: Open or Degraded; ProbeTick: the validated path is usable
    public bool RecentActivity; // ProbeTick: traffic arrived inside the idle window
    public int Path;            // ProbeTick: EffectPath.Direct or EffectPath.Relay
    public long Echo;           // ProbeAcked: the echoed probe nonce; RttSample: the echoed ping timestamp
}

// Liveness decisions: keepalive ping cadence, path-validation probe bookkeeping
// (outstanding nonce, deadline, unanswered escalation), and the RTT EWMA fed by
// answered caller pings. The shell owns the liveness clocks (last-rx ticks), the
// send counters, and everything socket-shaped.
public struct KeepaliveState
{
    public long NextKeepaliveTicks; // 0 fires on the first eligible tick
    public bool ProbeOutstanding;
    public long ProbeNonce;         // tick | KeepaliveMachine.ProbeMarker; direct probes only
    public long ProbeDeadlineTicks;
    public int UnansweredProbes;
    public double RttEwmaTicks;     // TimeSpan ticks; 0 = no sample yet
    public long KeepaliveIntervalMs; // 0 = keepalive off
    public long ProbeTimeoutMs;
    public int MaxUnansweredProbes;

    public static KeepaliveState Create(long keepaliveIntervalMs, long probeTimeoutMs, int maxUnansweredProbes)
    {
        KeepaliveState s = default;
        s.KeepaliveIntervalMs = keepaliveIntervalMs;
        s.ProbeTimeoutMs = probeTimeoutMs;
        s.MaxUnansweredProbes = maxUnansweredProbes;
        return s;
    }
}

public static class KeepaliveMachine
{
    // Sign bit marks a maintenance probe's timestamp; caller pings keep plain ticks so
    // RTT stats and monitoring counters never mix.
    public const long ProbeMarker = long.MinValue;

    public static int Step(ref KeepaliveState state, in KeepaliveInput input, Tick now, Span<Effect> effects)
    {
        switch (input.Kind)
        {
            case KeepaliveInputKind.MaintainTick:
                return StepMaintain(ref state, in input, now, effects);
            case KeepaliveInputKind.ProbeTick:
                return StepProbe(ref state, in input, now, effects);
            case KeepaliveInputKind.ProbeAcked:
                StepProbeAcked(ref state, in input);
                return 0;
            case KeepaliveInputKind.PathChanged:
                state.ProbeOutstanding = false;
                state.UnansweredProbes = 0;
                return 0;
            case KeepaliveInputKind.RttSample:
                StepRttSample(ref state, in input, now);
                return 0;
            default:
                return 0; // unknown input values are a no-op, never an exception
        }
    }

    private static int StepMaintain(ref KeepaliveState s, in KeepaliveInput input, Tick now, Span<Effect> effects)
    {
        // Value 0 on the Transmit: the shell stamps the ping with its own send-time tick.
        if (!input.PathEligible || s.KeepaliveIntervalMs <= 0)
        {
            return 0;
        }

        long nowMs = now.Milliseconds;
        if (nowMs < s.NextKeepaliveTicks)
        {
            return 0;
        }

        s.NextKeepaliveTicks = nowMs + s.KeepaliveIntervalMs;
        int count = 0;
        Effects.Add(effects, ref count, EffectKind.Transmit, EffectPath.Direct, 0, 0);
        Effects.Add(effects, ref count, EffectKind.Arm, EffectPath.Direct, 0, s.NextKeepaliveTicks);
        return count;
    }

    private static int StepProbe(ref KeepaliveState s, in KeepaliveInput input, Tick now, Span<Effect> effects)
    {
        if (!input.PathEligible || input.RecentActivity)
        {
            // Live traffic, or no path to validate: any half-finished probe sequence is
            // forgotten. The shell additionally drops its probe target/socket captures.
            s.ProbeOutstanding = false;
            s.UnansweredProbes = 0;
            return 0;
        }

        long nowMs = now.Milliseconds;
        if (s.ProbeOutstanding)
        {
            if (nowMs < s.ProbeDeadlineTicks)
            {
                return 0; // this probe's reply may still land
            }

            s.ProbeOutstanding = false;
            s.UnansweredProbes++;
            if (s.UnansweredProbes >= s.MaxUnansweredProbes)
            {
                s.UnansweredProbes = 0;
                int count = 0;
                Effects.Add(effects, ref count, EffectKind.Notify, input.Path, 0, 0);
                return count;
            }

            return 0; // the next tick sends the next probe
        }

        s.ProbeOutstanding = true;
        s.ProbeDeadlineTicks = nowMs + s.ProbeTimeoutMs;
        // Direct probes carry a marker nonce their pong must echo; relay probes ride
        // plain pings (the shell's own transmission), so no nonce is recorded.
        long value = 0;
        if (input.Path != EffectPath.Relay)
        {
            s.ProbeNonce = nowMs | ProbeMarker;
            value = s.ProbeNonce;
        }

        int written = 0;
        Effects.Add(effects, ref written, EffectKind.Transmit, input.Path, 0, value);
        Effects.Add(effects, ref written, EffectKind.Arm, input.Path, 0, s.ProbeDeadlineTicks);
        return written;
    }

    private static void StepProbeAcked(ref KeepaliveState s, in KeepaliveInput input)
    {
        // The shell has already proven the pong arrived from the endpoint and transport
        // the probe went to; nonce matching and the unanswered reset are the machine's.
        if (s.ProbeOutstanding && s.ProbeNonce == input.Echo)
        {
            s.ProbeOutstanding = false;
            s.UnansweredProbes = 0;
        }
    }

    private static void StepRttSample(ref KeepaliveState s, in KeepaliveInput input, Tick now)
    {
        long rttTicks = (now.Milliseconds - input.Echo) * TimeSpan.TicksPerMillisecond;
        s.RttEwmaTicks = s.RttEwmaTicks == 0 ? rttTicks : s.RttEwmaTicks + 0.25 * (rttTicks - s.RttEwmaTicks);
    }
}
