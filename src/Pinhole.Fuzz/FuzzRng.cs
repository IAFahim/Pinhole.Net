namespace Pinhole.Fuzz;

public sealed class FuzzRng
{
    private ulong _s0;

    private ulong _s1;

    public FuzzRng(ulong seed)
    {
        _s0 = Mix(seed);
        _s1 = Mix(seed ^ 0x9E3779B97F4A7C15UL);
        if ((_s0 | _s1) == 0UL)
        {
            _s1 = 1UL;
        }
    }

    public ulong Next()
    {
        ulong s0 = _s0;
        ulong s1 = _s1;
        ulong result = s0 + s1;
        _s0 = s1;
        s0 ^= s0 << 23;
        _s1 = s0 ^ s1 ^ (s0 >> 17) ^ (s1 >> 26);
        return result;
    }

    public int NextInt(int exclusiveHigh) => exclusiveHigh <= 1 ? 0 : (int)(Next() % (ulong)exclusiveHigh);

    private static ulong Mix(ulong x)
    {
        x += 0x9E3779B97F4A7C15UL;
        x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9UL;
        x = (x ^ (x >> 27)) * 0x94D049BB133111EBUL;
        return x ^ (x >> 31);
    }
}
