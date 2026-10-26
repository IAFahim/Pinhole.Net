using Pinhole.Core;
using Pinhole.Crypto;

namespace Pinhole.Sim;

// The exact Step shape of every Pinhole.Core machine, as a delegate so the
// driver is generic over state and input without the machines sharing a type.
// TInput stays invariant: it sits in an `in` parameter, which is an input and
// output position to the variance checker.
public delegate int MachineStep<TState, TInput>(ref TState state, in TInput input, Tick now, Span<Effect> effects);

// Machine-level simulation driver: steps one sans-IO machine on a SimClock and
// records every emitted effect into a canonical, hashable log. The clock and
// RNG are handed in — the driver never invents time or randomness — so a run is
// a pure function of its seed. Scenario code drives it like the shells do:
// advance the clock, deliver inputs, inspect effects.
internal sealed class MachineSim<TState, TInput>
{
    // PmtuMachine's busiest tick writes two effects (Transmit + Arm); 16 slots
    // gives every current machine headroom. Effects.Add silently drops beyond
    // the span, so a future machine that outgrows this is clipped, not crashed.
    private const int EffectSlots = 16;

    private readonly MachineStep<TState, TInput> _step;
    private readonly Effect[] _effects = new Effect[EffectSlots];
    private TState _state;
    private int _lastWritten;

    public MachineSim(TState state, MachineStep<TState, TInput> step, SimClock clock, IRandom random)
    {
        _state = state;
        _step = step;
        Clock = clock;
        Random = random;
        Log = new EffectLog();
    }

    public SimClock Clock { get; }

    public IRandom Random { get; }

    public EffectLog Log { get; }

    public ref TState State => ref _state;

    public long EffectsLogged => Log.EffectCount;

    // What the last Step call emitted — the scenario reads this to interpret
    // effects (e.g. answer a Transmit) the way a shell would.
    public ReadOnlySpan<Effect> LastEffects => _effects.AsSpan(0, _lastWritten);

    // Step the machine at the clock's current time and append what it emitted.
    public int Step(in TInput input)
    {
        int written = _step(ref _state, in input, Clock.Now, _effects);
        _lastWritten = written;
        long nowMs = Clock.NowMs;
        for (int i = 0; i < written; i++)
        {
            Log.Append(nowMs, in _effects[i]);
        }

        return written;
    }
}
