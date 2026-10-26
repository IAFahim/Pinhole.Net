using Pinhole.Crypto;

namespace Pinhole.Core;

public enum PunchInputKind : byte
{
    Tick = 0, // one scheduler pass: stop/condemn/gate/pace decisions
    Kick = 1, // a fresh punch was armed (new loop generation): reset the per-run counters
}

public enum PunchNotify : long
{
    Stop = 0,        // nothing left to schedule: the shell ends its loop
    CondemnDead = 1, // connect timeout while punching: transition Dead, stamp dead-since
    Lookup = 2,      // the lookup cadence fired: re-resolve the pinned endpoint key
    Announce = 3,    // relay-signaling retry window: re-announce candidates
    TcpProbe = 4,    // the TCP kick delay passed: try the direct-TCP paths
}

public struct PunchInput
{
    public PunchInputKind Kind;
    public byte Phase;                // ConnPhase while this tick runs
    public bool OpenWithoutDirectTcp; // Open on UDP with no TCP link: direct already won
    public bool ConnectedCompleted;   // a session existed once: post-Dead beacons are worth sending
    public bool PinnedLookupPossible; // a pinned endpoint key and lookup providers exist
    public bool RelaySignalingOnly;
    public bool Established;          // the crypto handshake derived keys
    public bool SymmetricHint;        // the peer advertised a symmetric NAT: relay-first scheduling
    public bool PredictionActive;     // port prediction is running or measuring: hold directs
    public bool AwaitExchange;        // the initial candidate exchange has not landed
    public bool PeerCandidatesReceived;
    public bool TcpEligible;          // TCP transport exists, crypto offered, no TCP link held
    public bool AnnounceRetryDue;     // the announce retry window (1s) has passed
    public long NowMs;
    public long KickedAtMs;           // monotonic; suspend-proof by construction
    public long DeadSinceMs;          // -1 when never condemned
}

// Hole-punch scheduling decisions: the connect-timeout condemn with its post-Dead
// beacon budget, the upgrade-attempt cap once a session exists, the symmetric-NAT
// direct trickle, the link-local fallback delay, the candidate-exchange gate, the
// lookup and announce retry cadences, the TCP kick delay, and the per-phase pace.
// The shell owns candidates, sockets, the generation counter and every send.
public struct PunchState
{
    public int UpgradeAttempts;    // Degraded/Open poking budget; reset by a Kick
    public long LastDirectPunchMs; // 0 = never; the symmetric trickle clock
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
    // Cadences the engine hardcoded as privates; they move here so the machine and the
    // shell quote one source.
    public const long PunchPaceMs = 200;
    public const long UpgradePaceMs = 1000;
    public const long DeadBeaconPaceMs = 1000;
    public const long DeadBeaconBudgetMs = 300_000; // five minutes of post-Dead beacons
    public const long LookupRetryMs = 1000;         // must subdivide the shortest ConnectTimeout
    public const long SymmetricDirectTrickleMs = 1000;
    public const long LinkLocalFallbackDelayMs = 600;
    public const long TcpKickDelayMs = 1200;
    public const int MaxUpgradeAttempts = 120;      // then passive: peer frames can still open direct

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
            return 0; // unknown input values are a no-op, never an exception
        }

        ConnPhase phase = (ConnPhase)input.Phase;
        int count = 0;

        // An Open connection without a TCP link has nothing left to upgrade: direct
        // already won. Closed is terminal for the loop.
        if (phase == ConnPhase.Closed || phase == ConnPhase.Open && input.OpenWithoutDirectTcp)
        {
            Effects.Add(effects, ref count, EffectKind.Notify, 0, 0, (long)PunchNotify.Stop);
            return count;
        }

        if (phase is ConnPhase.Degraded or ConnPhase.Open)
        {
            // Stop poking; direct can still open passively from the peer's frames.
            state.UpgradeAttempts++;
            if (state.UpgradeAttempts > MaxUpgradeAttempts)
            {
                Effects.Add(effects, ref count, EffectKind.Notify, 0, 0, (long)PunchNotify.Stop);
                return count;
            }
        }

        // Dead-since as this tick sees it: the input's stamp on ordinary ticks, and the
        // condemn's own instant on the tick that performs it (the shell stamps the field
        // only after this step returns — a stale zero there would read as a long-expired
        // budget and stop the beacon the moment it is condemned).
        long deadSinceMs = input.DeadSinceMs;
        if (phase == ConnPhase.Punching && input.NowMs - input.KickedAtMs > state.ConnectTimeoutMs)
        {
            Effects.Add(effects, ref count, EffectKind.Notify, 0, 0, (long)PunchNotify.CondemnDead);
            // A real session keeps a slow beacon so the peer can revive us; a husk that
            // never completed a handshake never beacons — no reflection amplification.
            if (!input.ConnectedCompleted)
            {
                Effects.Add(effects, ref count, EffectKind.Notify, 0, 0, (long)PunchNotify.Stop);
                return count;
            }

            // The shell transitions before acting on the rest of this tick's effects, so
            // every later gate (announce eligibility, pace, budget) sees the condemned phase.
            phase = ConnPhase.Dead;
            deadSinceMs = input.NowMs;
        }

        if (phase == ConnPhase.Dead && deadSinceMs >= 0
            && input.NowMs - deadSinceMs > DeadBeaconBudgetMs)
        {
            Effects.Add(effects, ref count, EffectKind.Notify, 0, 0, (long)PunchNotify.Stop);
            return count; // beacon budget spent; passive revival still works
        }

        // A symmetric hint is scheduling advice, not a ban: relay candidates carry the
        // session — per-destination mappings make public reflexives hopeless — while
        // direct candidates keep a slow trickle. Port prediction holds directs entirely
        // so its measurement is not disturbed.
        bool punchDirects = !input.SymmetricHint
            || state.LastDirectPunchMs == 0 // never punched: the window starts open
            || input.NowMs - state.LastDirectPunchMs >= SymmetricDirectTrickleMs;
        if (input.PredictionActive)
        {
            punchDirects = false;
        }

        if (punchDirects)
        {
            state.LastDirectPunchMs = input.NowMs;
        }

        // Direct candidates also wait for the peer's candidate exchange and, for
        // link-local fallbacks, for ordinary routes to have had their chance.
        if (punchDirects && input.AwaitExchange && !input.PeerCandidatesReceived)
        {
            punchDirects = false;
        }

        bool punchLinkLocal = punchDirects
            && input.NowMs - input.KickedAtMs >= LinkLocalFallbackDelayMs;

        // Relays are always worth a datagram: they carry the session regardless of the
        // NAT shape and the exchange state.
        Effects.Add(effects, ref count, EffectKind.Transmit, EffectPath.Relay, 0, 0);
        if (punchDirects)
        {
            Effects.Add(effects, ref count, EffectKind.Transmit, EffectPath.Direct, 0, 0);
        }

        if (punchLinkLocal)
        {
            Effects.Add(effects, ref count, EffectKind.Transmit, EffectPath.DirectLinkLocal, 0, 0);
        }

        // A stuck punch whose ticket pins an endpoint key asks the lookup providers
        // where the peer is NOW; the cadence must subdivide a connection deadline.
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
