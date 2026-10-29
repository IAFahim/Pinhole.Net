namespace Pinhole.Sim;

public interface IRandom
{

    ulong NextULong();

    long NextLong(long exclusiveMax);

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

        return ((ulong)(uint)_rng.Next() << 32) | (uint)_rng.Next();
    }

    public long NextLong(long exclusiveMax) => _rng.NextInt64(exclusiveMax);

    public bool Chance(double probability) => _rng.NextDouble() < probability;
}
