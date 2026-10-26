namespace Pinhole.Sim;

// Randomness as an input, mirroring Tick: scenarios draw every stochastic decision
// from an instance they were handed, so a seed pins a whole run. No member may
// reach for ambient state (Random.Shared, Environment, clock) — that is the
// property P4 (same seed => identical effect-log hash) is built on.
public interface IRandom
{
    // Uniform over the full 64-bit range.
    ulong NextULong();

    // Uniform in [0, exclusiveMax); exclusiveMax must be positive.
    long NextLong(long exclusiveMax);

    // True with the given probability (0 = never, 1 = always).
    bool Chance(double probability);
}

public sealed class SimRandom : IRandom
{
    private readonly Random _rng;

    public SimRandom(int seed)
    {
        _rng = new Random(seed);
    }

    public ulong NextULong()
    {
        // Two 31-bit draws composed; System.Random exposes no NextUInt64.
        return ((ulong)(uint)_rng.Next() << 32) | (uint)_rng.Next();
    }

    public long NextLong(long exclusiveMax) => _rng.NextInt64(exclusiveMax);

    public bool Chance(double probability) => _rng.NextDouble() < probability;
}
