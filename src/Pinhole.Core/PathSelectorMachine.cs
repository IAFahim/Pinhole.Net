using Pinhole.Crypto;

namespace Pinhole.Core;

// Machine-local mirrors of the shell's public enums (PinholeConnectionState, PathKind),
// same numeric values so the shell's casts are value-preserving both ways and the
// machine never references the assembly that references it.
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
    DirectConfirmed = 0, // an authenticated direct frame arrived (the shell vetted eligibility first)
    RelayConfirmed = 1,  // an authenticated relay frame arrived
    DirectLost = 2,      // path validation condemned the carrying path
    Forced = 3,          // a lifecycle verdict from outside (dead condemn, close, rebind)
}

public struct PathSelectorInput
{
    public PathSelectorInputKind Kind;
    public bool PeerConfirmed;      // RelayConfirmed: the handshake finished (null crypto counts as confirmed)
    public bool RelaySignalingOnly; // RelayConfirmed: the option forbids relay-carried sessions
    public bool RelayUsable;        // DirectLost: a relay leg is alive and confirmed, or permitted and ready
    public byte ForcedPhase;        // Forced: the ConnPhase to apply
}

// Which of the two routed paths carries the connection, and the connection's phase.
// Decision state only: the shell owns endpoint adoption, the since-stamps, the
// connected/incoming tasks and everything socket-shaped. One Notify effect is emitted
// when (Phase, Path) actually changed — the shell's per-site reactions differ and stay
// in the shell.
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
    // A Notify's Value packs the verdict: (new phase << 8) | new path.
    public const long VerdictShift = 8;

    public static int Step(ref PathSelectorState state, in PathSelectorInput input, Tick now, Span<Effect> effects)
    {
        ConnPhase beforePhase = state.Phase;
        PathSel beforePath = state.Path;
        switch (input.Kind)
        {
            case PathSelectorInputKind.DirectConfirmed:
                // Newest direct evidence wins whatever the connection was doing: a
                // restored path can have exactly its old address and must still promote
                // a relayed or pending session. Only Closed is absorbing — a closed
                // connection is never revived by stray frames.
                if (state.Phase != ConnPhase.Closed)
                {
                    state.Phase = ConnPhase.Open;
                    state.Path = PathSel.Direct;
                }
                break;

            case PathSelectorInputKind.RelayConfirmed:
                // The relay proves reachability, not the peer: only a confirmed
                // handshake may open a session, and never when the relay is reserved
                // for signaling. Relay evidence never upgrades an Open connection —
                // direct stays newest-wins.
                if (state.Phase is ConnPhase.Punching or ConnPhase.Dead
                    && input.PeerConfirmed && !input.RelaySignalingOnly)
                {
                    state.Phase = ConnPhase.Degraded;
                    state.Path = PathSel.Relay;
                }
                break;

            case PathSelectorInputKind.DirectLost:
                // The carrying path was condemned. With a usable relay leg the session
                // falls back to it; without one there is nothing to send on and the
                // connection returns to punching. A degraded session whose relay also
                // died falls the same way; a degraded session with a live relay keeps it.
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
                // Dead survives with its path (Dead is revivable; the path remembers
                // what a revival would restore). Closed clears it.
                ConnPhase forced = (ConnPhase)input.ForcedPhase;
                if (forced is < (ConnPhase)0 or > ConnPhase.Closed)
                {
                    break; // unknown phases are a no-op, never a corruption
                }

                state.Phase = forced;
                if (state.Phase == ConnPhase.Closed)
                {
                    state.Path = PathSel.None;
                }
                break;

            default:
                return 0; // unknown input values are a no-op, never an exception
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
