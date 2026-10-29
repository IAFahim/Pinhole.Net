using Pinhole.Crypto;

namespace Pinhole.Core;

public enum PmtuInputKind : byte
{
    Tick = 0,
    PongAcked = 1,
    InboundEvidence = 2,
    PathMigrated = 3,
}

public struct PmtuInput
{
    public PmtuInputKind Kind;
    public bool PathEligible;
    public bool IPv4;
    public long Nonce;
    public int WireLength;
}

public struct PmtuState
{
    public int Wire;
    public bool VerifiedSize;
    public bool Outstanding;
    public long Nonce;
    public int ProbeSize;
    public int Tries;
    public long DeadlineTicks;
    public long NextProbeTicks;
    public int BaseWire;
    public int StepBytes;
    public int MaxAttempts;
    public int CeilingV4;
    public int CeilingV6;
    public long ReprobeIntervalMs;
    public long ProbeTimeoutMs;

    public static PmtuState Create(int baseWire, int stepBytes, int maxAttempts,
        int ceilingV4, int ceilingV6, long reprobeIntervalMs, long probeTimeoutMs)
    {
        PmtuState s = default;
        s.BaseWire = baseWire;
        s.StepBytes = stepBytes;
        s.MaxAttempts = maxAttempts;
        s.CeilingV4 = ceilingV4;
        s.CeilingV6 = ceilingV6;
        s.ReprobeIntervalMs = reprobeIntervalMs;
        s.ProbeTimeoutMs = probeTimeoutMs;
        return s;
    }
}

public static class PmtuMachine
{

    public const long ProbeMarker = 1L << 62;

    public static int Step(ref PmtuState state, in PmtuInput input, Tick now, Span<Effect> effects)
    {
        switch (input.Kind)
        {
            case PmtuInputKind.Tick:
                return StepTick(ref state, in input, now, effects);
            case PmtuInputKind.PongAcked:
                StepPongAcked(ref state, in input);
                return 0;
            case PmtuInputKind.InboundEvidence:
                StepInboundEvidence(ref state, in input);
                return 0;
            case PmtuInputKind.PathMigrated:
                StepPathMigrated(ref state);
                return 0;
            default:
                return 0;
        }
    }

    private static int StepTick(ref PmtuState s, in PmtuInput input, Tick now, Span<Effect> effects)
    {
        long nowMs = now.Milliseconds;
        if (!input.PathEligible)
        {

            if (s.Wire != 0 || s.Outstanding)
            {
                s.Wire = 0;
                s.Outstanding = false;
                s.NextProbeTicks = 0;
            }

            return 0;
        }

        if (s.Outstanding)
        {
            if (nowMs < s.DeadlineTicks)
            {
                return 0;
            }

            s.Tries++;
            if (s.Tries >= s.MaxAttempts)
            {

                s.Outstanding = false;
                if (s.ProbeSize == s.Wire && s.Wire > s.BaseWire)
                {

                    s.Wire = s.BaseWire;
                    s.VerifiedSize = false;
                    s.NextProbeTicks = 0;
                    return 0;
                }

                s.VerifiedSize = false;
                s.NextProbeTicks = nowMs + s.ReprobeIntervalMs;
                return AddArm(effects, s.NextProbeTicks);
            }
        }
        else if (nowMs < s.NextProbeTicks)
        {
            return 0;
        }
        else
        {
            int next;
            if (s.Wire > s.BaseWire && !s.VerifiedSize)
            {

                next = s.Wire;
            }
            else
            {
                next = NextSize(ref s, input.IPv4);
                if (next <= 0)
                {
                    s.NextProbeTicks = nowMs + s.ReprobeIntervalMs;
                    return AddArm(effects, s.NextProbeTicks);
                }
            }

            s.ProbeSize = next;
            s.Tries = 0;
            s.Outstanding = true;
        }

        s.Nonce = nowMs | ProbeMarker;
        s.DeadlineTicks = nowMs + s.ProbeTimeoutMs;
        int count = 0;
        Effects.Add(effects, ref count, EffectKind.Transmit, EffectPath.Direct, s.ProbeSize, s.Nonce);
        Effects.Add(effects, ref count, EffectKind.Arm, EffectPath.Direct, 0, s.DeadlineTicks);
        return count;
    }

    private static void StepPongAcked(ref PmtuState s, in PmtuInput input)
    {

        if (!s.Outstanding || s.Nonce != input.Nonce)
        {
            return;
        }

        s.Outstanding = false;
        if (s.ProbeSize > s.Wire)
        {
            s.Wire = s.ProbeSize;
            s.VerifiedSize = false;
        }
        else
        {
            s.VerifiedSize = true;
        }

        s.NextProbeTicks = 0;
    }

    private static void StepInboundEvidence(ref PmtuState s, in PmtuInput input)
    {

        int ceiling = input.IPv4 ? s.CeilingV4 : s.CeilingV6;
        if (input.WireLength >= s.BaseWire && input.WireLength > s.Wire && input.WireLength <= ceiling)
        {
            s.Wire = input.WireLength;
        }
    }

    private static void StepPathMigrated(ref PmtuState s)
    {

        if (s.Wire != 0 || s.Outstanding)
        {
            s.Wire = 0;
            s.Outstanding = false;
            s.VerifiedSize = false;
            s.NextProbeTicks = 0;
        }
    }

    private static int NextSize(ref PmtuState s, bool ipv4)
    {
        int ceiling = ipv4 ? s.CeilingV4 : s.CeilingV6;
        int floor = s.Wire > s.BaseWire ? s.Wire : s.BaseWire;
        return floor >= ceiling ? 0 : Math.Min(ceiling, floor + s.StepBytes);
    }

    private static int AddArm(Span<Effect> effects, long deadline)
    {
        int count = 0;
        Effects.Add(effects, ref count, EffectKind.Arm, EffectPath.Direct, 0, deadline);
        return count;
    }
}
