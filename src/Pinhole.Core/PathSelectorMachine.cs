using Pinhole.Crypto;

namespace Pinhole.Core;

public enum ConnPhase : byte
{
    Punching = 0,
    Open = 1,
    Degraded = 2,
    Dead = 3,
    Closed = 4,
}

public enum PathSel : byte
{
    None = 0,
    Direct = 1,
    Relay = 2,
}

public enum PathSelectorInputKind : byte
{
    DirectConfirmed = 0,
    RelayConfirmed = 1,
    DirectLost = 2,
    Forced = 3,
}

public struct PathSelectorInput
{
    public PathSelectorInputKind Kind;
    public bool PeerConfirmed;
    public bool RelaySignalingOnly;
    public bool RelayUsable;
    public byte ForcedPhase;
}

public struct PathSelectorState
{
    public ConnPhase Phase;
    public PathSel Path;

    public static PathSelectorState Create(ConnPhase phase, PathSel path)
    {
        PathSelectorState s = default;
        s.Phase = phase;
        s.Path = path;
        return s;
    }
}

public static class PathSelectorMachine
{

    public const long VerdictShift = 8;

    public static int Step(ref PathSelectorState state, in PathSelectorInput input, Tick now, Span<Effect> effects)
    {
        ConnPhase beforePhase = state.Phase;
        PathSel beforePath = state.Path;
        switch (input.Kind)
        {
            case PathSelectorInputKind.DirectConfirmed:

                if (state.Phase != ConnPhase.Closed)
                {
                    state.Phase = ConnPhase.Open;
                    state.Path = PathSel.Direct;
                }
                break;

            case PathSelectorInputKind.RelayConfirmed:

                if (state.Phase is ConnPhase.Punching or ConnPhase.Dead
                    && input.PeerConfirmed && !input.RelaySignalingOnly)
                {
                    state.Phase = ConnPhase.Degraded;
                    state.Path = PathSel.Relay;
                }
                break;

            case PathSelectorInputKind.DirectLost:

                if (state.Phase == ConnPhase.Open)
                {
                    if (input.RelayUsable)
                    {
                        state.Phase = ConnPhase.Degraded;
                        state.Path = PathSel.Relay;
                    }
                    else
                    {
                        state.Phase = ConnPhase.Punching;
                        state.Path = PathSel.None;
                    }
                }
                else if (state.Phase == ConnPhase.Degraded && !input.RelayUsable)
                {
                    state.Phase = ConnPhase.Punching;
                    state.Path = PathSel.None;
                }
                break;

            case PathSelectorInputKind.Forced:

                ConnPhase forced = (ConnPhase)input.ForcedPhase;
                if (forced is < (ConnPhase)0 or > ConnPhase.Closed)
                {
                    break;
                }

                state.Phase = forced;
                if (state.Phase == ConnPhase.Closed)
                {
                    state.Path = PathSel.None;
                }
                break;

            default:
                return 0;
        }

        if (state.Phase == beforePhase && state.Path == beforePath)
        {
            return 0;
        }

        long verdict = ((long)state.Phase << (int)VerdictShift) | (uint)(byte)state.Path;
        int count = 0;
        Effects.Add(effects, ref count, EffectKind.Notify, (int)state.Path, 0, verdict);
        return count;
    }
}
