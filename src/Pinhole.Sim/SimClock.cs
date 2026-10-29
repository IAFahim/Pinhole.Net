using Pinhole.Crypto;

namespace Pinhole.Sim;

public sealed class SimClock
{
    private long _nowMs;

    public SimClock(long startMilliseconds = 0)
    {
        _nowMs = startMilliseconds;
    }

    public long NowMs => _nowMs;

    public Tick Now => Tick.FromMilliseconds(_nowMs);

    public Tick Advance(long milliseconds)
    {
        if (milliseconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(milliseconds), "the logical clock only moves forward");
        }

        _nowMs += milliseconds;
        return Now;
    }

    public Tick AdvanceTo(long milliseconds)
    {
        if (milliseconds > _nowMs)
        {
            _nowMs = milliseconds;
        }

        return Now;
    }
}
