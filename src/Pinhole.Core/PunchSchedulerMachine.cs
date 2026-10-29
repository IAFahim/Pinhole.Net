using Pinhole.Crypto;

namespace Pinhole.Core;

public enum PunchInputKind : byte
{
    Tick = 0,
    Kick = 1,
}

public enum PunchNotify : long
{
    Stop = 0,
    CondemnDead = 1,
    Lookup = 2,
    Announce = 3,
    TcpProbe = 4,
}

public struct PunchInput
{
    public PunchInputKind Kind;
    public byte Phase;
    public bool OpenWithoutDirectTcp;
    public bool ConnectedCompleted;
    public bool PinnedLookupPossible;
    public bool RelaySignalingOnly;
    public bool Established;
    public bool SymmetricHint;
    public bool PredictionActive;
    public bool AwaitExchange;
    public bool PeerCandidatesReceived;
    public bool TcpEligible;
    public bool AnnounceRetryDue;
    public long NowMs;
    public long KickedAtMs;
    public long DeadSinceMs;
}

public struct PunchState
{
    public int UpgradeAttempts;
    public long LastDirectPunchMs;
    public long LastLookupMs;
    public long ConnectTimeoutMs;

    public static PunchState Create(long connectTimeoutMs)
    {
        PunchState s = default;
        s.ConnectTimeoutMs = connectTimeoutMs;
        return s;
    }
}

public static class PunchSchedulerMachine
{

    public const long PunchPaceMs = 200;
    public const long UpgradePaceMs = 1000;
    public const long DeadBeaconPaceMs = 1000;
    public const long DeadBeaconBudgetMs = 300_000;
    public const long LookupRetryMs = 1000;
    public const long SymmetricDirectTrickleMs = 1000;
    public const long LinkLocalFallbackDelayMs = 600;
    public const long TcpKickDelayMs = 1200;
    public const int MaxUpgradeAttempts = 120;

    public static int Step(ref PunchState state, in PunchInput input, Tick now, Span<Effect> effects)
    {
        if (input.Kind == PunchInputKind.Kick)
        {
            state.UpgradeAttempts = 0;
            state.LastDirectPunchMs = 0;
            return 0;
        }

        if (input.Kind != PunchInputKind.Tick)
        {
            return 0;
        }

        ConnPhase phase = (ConnPhase)input.Phase;
        int count = 0;

        if (phase == ConnPhase.Closed || phase == ConnPhase.Open && input.OpenWithoutDirectTcp)
        {
            Effects.Add(effects, ref count, EffectKind.Notify, 0, 0, (long)PunchNotify.Stop);
            return count;
        }

        if (phase is ConnPhase.Degraded or ConnPhase.Open)
        {

            state.UpgradeAttempts++;
            if (state.UpgradeAttempts > MaxUpgradeAttempts)
            {
                Effects.Add(effects, ref count, EffectKind.Notify, 0, 0, (long)PunchNotify.Stop);
                return count;
            }
        }

        long deadSinceMs = input.DeadSinceMs;
        if (phase == ConnPhase.Punching && input.NowMs - input.KickedAtMs > state.ConnectTimeoutMs)
        {
            Effects.Add(effects, ref count, EffectKind.Notify, 0, 0, (long)PunchNotify.CondemnDead);

            if (!input.ConnectedCompleted)
            {
                Effects.Add(effects, ref count, EffectKind.Notify, 0, 0, (long)PunchNotify.Stop);
                return count;
            }

            phase = ConnPhase.Dead;
            deadSinceMs = input.NowMs;
        }

        if (phase == ConnPhase.Dead && deadSinceMs >= 0
            && input.NowMs - deadSinceMs > DeadBeaconBudgetMs)
        {
            Effects.Add(effects, ref count, EffectKind.Notify, 0, 0, (long)PunchNotify.Stop);
            return count;
        }

        bool punchDirects = !input.SymmetricHint
            || state.LastDirectPunchMs == 0
            || input.NowMs - state.LastDirectPunchMs >= SymmetricDirectTrickleMs;
        if (input.PredictionActive)
        {
            punchDirects = false;
        }

        if (punchDirects)
        {
            state.LastDirectPunchMs = input.NowMs;
        }

        if (punchDirects && input.AwaitExchange && !input.PeerCandidatesReceived)
        {
            punchDirects = false;
        }

        bool punchLinkLocal = punchDirects
            && input.NowMs - input.KickedAtMs >= LinkLocalFallbackDelayMs;

        Effects.Add(effects, ref count, EffectKind.Transmit, EffectPath.Relay, 0, 0);
        if (punchDirects)
        {
            Effects.Add(effects, ref count, EffectKind.Transmit, EffectPath.Direct, 0, 0);
        }

        if (punchLinkLocal)
        {
            Effects.Add(effects, ref count, EffectKind.Transmit, EffectPath.DirectLinkLocal, 0, 0);
        }

        if (input.PinnedLookupPossible && input.NowMs - state.LastLookupMs > LookupRetryMs)
        {
            state.LastLookupMs = input.NowMs;
            Effects.Add(effects, ref count, EffectKind.Notify, 0, 0, (long)PunchNotify.Lookup);
        }

        if (input.RelaySignalingOnly && input.Established
            && phase is ConnPhase.Punching or ConnPhase.Dead && input.AnnounceRetryDue)
        {
            Effects.Add(effects, ref count, EffectKind.Notify, 0, 0, (long)PunchNotify.Announce);
        }

        if (input.TcpEligible
            && (!input.AwaitExchange || input.PeerCandidatesReceived)
            && input.NowMs - input.KickedAtMs >= TcpKickDelayMs)
        {
            Effects.Add(effects, ref count, EffectKind.Notify, 0, 0, (long)PunchNotify.TcpProbe);
        }

        long pace = phase switch
        {
            ConnPhase.Dead => DeadBeaconPaceMs,
            ConnPhase.Degraded => UpgradePaceMs,
            ConnPhase.Open => UpgradePaceMs,
            _ => PunchPaceMs,
        };
        Effects.Add(effects, ref count, EffectKind.Arm, 0, 0, input.NowMs + pace);
        return count;
    }
}
