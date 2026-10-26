using Pinhole.Crypto;

namespace Pinhole.Sim;

// Deterministic time source for simulation: a bare millisecond counter the test
// advances explicitly. Hands out the same Tick value the production shells build
// from a real monotonic clock, so machines cannot tell a simulation from reality.
public sealed class SimClock
{
    private long _nowMs;

    public SimClock(long startMilliseconds = 0)
    {
        _nowMs = startMilliseconds;
    }

    public long NowMs => _nowMs;

    public Tick Now => Tick.FromMilliseconds(_nowMs);

    // Advance by a (possibly zero) duration and return the new now. Negative steps
    // are refused: a logical clock that runs backwards is a scenario bug.
    public Tick Advance(long milliseconds)
    {
        if (milliseconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(milliseconds), "the logical clock only moves forward");
        }

        _nowMs += milliseconds;
        return Now;
    }

    // Jump forward to an absolute time if it lies in the future; idempotent.
    public Tick AdvanceTo(long milliseconds)
    {
        if (milliseconds > _nowMs)
        {
            _nowMs = milliseconds;
        }

        return Now;
    }
}
