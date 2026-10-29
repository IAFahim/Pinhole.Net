using Pinhole.Core;
using Pinhole.Crypto;

namespace Pinhole.Sim;

public delegate int MachineStep<TState, TInput>(ref TState state, in TInput input, Tick now, Span<Effect> effects);

internal sealed class MachineSim<TState, TInput>
{

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

    public ReadOnlySpan<Effect> LastEffects => _effects.AsSpan(0, _lastWritten);

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
