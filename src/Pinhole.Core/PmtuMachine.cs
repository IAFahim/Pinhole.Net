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
    public bool PathEligible; // Tick: Open, direct, UDP, remote known
    public bool IPv4;         // Tick/InboundEvidence: remote address family picks the ceiling
    public long Nonce;        // PongAcked: the nonce the pong echoed
    public int WireLength;    // InboundEvidence: wire bytes of the frame that just arrived
}

// RFC 8899-style path MTU discovery decisions. The presumed-good floor is never probed;
// padded pings climb from it, a confirmed size raises the app payload ceiling, and a size
// that stops traversing demotes the wire capacity back to the floor. Decision state only:
// the shell owns where a probe goes (target/socket fields) and the send counters.
public struct PmtuState
{
    public int Wire;          // confirmed wire capacity; 0 = unprobed
    public bool VerifiedSize; // the confirmed size itself was (re)verified
    public bool Outstanding;
    public long Nonce;        // tick | PmtuMachine.ProbeMarker
    public int ProbeSize;     // wire bytes of the outstanding probe
    public int Tries;
    public long DeadlineTicks;
    public long NextProbeTicks; // cooldown after a failed climb / park at the ceiling
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
    // Positive marker: an over-MTU probe's nonce cannot collide with path-probe nonces
    // (sign bit) or caller ping timestamps (plain ticks).
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
                return 0; // unknown input values are a no-op, never an exception
        }
    }

    private static int StepTick(ref PmtuState s, in PmtuInput input, Tick now, Span<Effect> effects)
    {
        long nowMs = now.Milliseconds;
        if (!input.PathEligible)
        {
            // Off the direct UDP path the measurement is void. VerifiedSize rides along
            // as-is; only a migration (new endpoint) resets it. ProbeSize/Tries/Deadline
            // are dead once Outstanding clears — the next climb rewrites them.
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
                return 0; // this probe's pong may still land
            }

            s.Tries++;
            if (s.Tries >= s.MaxAttempts)
            {
                // An over-MTU probe is silently dropped by the network, not errored, so
                // absence of a pong IS the measurement.
                s.Outstanding = false;
                if (s.ProbeSize == s.Wire && s.Wire > s.BaseWire)
                {
                    // The CONFIRMED size no longer traverses: the path's MTU shrank under
                    // us. Fall back to the guaranteed floor and re-climb.
                    s.Wire = s.BaseWire;
                    s.VerifiedSize = false;
                    s.NextProbeTicks = 0;
                    return 0;
                }

                // A failed climb starts the cooldown; the cycle after EVERY cooldown
                // re-verifies the confirmed size first (VerifiedSize cleared here).
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
                // RFC 8899 size re-verification: prove the CONFIRMED size still traverses
                // before climbing further, or a mid-connection MTU shrink blackholes
                // app-sized frames while small validation probes keep passing.
                next = s.Wire;
            }
            else
            {
                next = NextSize(ref s, input.IPv4);
                if (next <= 0)
                {
                    s.NextProbeTicks = nowMs + s.ReprobeIntervalMs; // ceiling reached; re-climb later
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
        // The shell has already proven the pong came from the endpoint the probe went to;
        // nonce ownership and confirmation bookkeeping are the machine's.
        if (!s.Outstanding || s.Nonce != input.Nonce)
        {
            return;
        }

        s.Outstanding = false;
        if (s.ProbeSize > s.Wire)
        {
            s.Wire = s.ProbeSize;
            s.VerifiedSize = false; // the new size earns its own re-verification later
        }
        else
        {
            s.VerifiedSize = true; // the confirmed size re-verified; keep climbing
        }

        s.NextProbeTicks = 0; // climb again on the next tick
    }

    private static void StepInboundEvidence(ref PmtuState s, in PmtuInput input)
    {
        // A datagram this size arrived, so the path carries it. Never lowers the floor.
        int ceiling = input.IPv4 ? s.CeilingV4 : s.CeilingV6;
        if (input.WireLength >= s.BaseWire && input.WireLength > s.Wire && input.WireLength <= ceiling)
        {
            s.Wire = input.WireLength;
        }
    }

    private static void StepPathMigrated(ref PmtuState s)
    {
        // The endpoint changed (roam, family switch): the confirmed MTU belongs to the
        // OLD path. Forget it and re-climb.
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
