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
    public bool PathEligible;
    public bool RecentActivity;
    public int Path;
    public long Echo;
}

public struct KeepaliveState
{
    public long NextKeepaliveTicks;
    public bool ProbeOutstanding;
    public long ProbeNonce;
    public long ProbeDeadlineTicks;
    public int UnansweredProbes;
    public double RttEwmaTicks;
    public long KeepaliveIntervalMs;
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
                return 0;
        }
    }

    private static int StepMaintain(ref KeepaliveState s, in KeepaliveInput input, Tick now, Span<Effect> effects)
    {

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

            s.ProbeOutstanding = false;
            s.UnansweredProbes = 0;
            return 0;
        }

        long nowMs = now.Milliseconds;
        if (s.ProbeOutstanding)
        {
            if (nowMs < s.ProbeDeadlineTicks)
            {
                return 0;
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

            return 0;
        }

        s.ProbeOutstanding = true;
        s.ProbeDeadlineTicks = nowMs + s.ProbeTimeoutMs;

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
