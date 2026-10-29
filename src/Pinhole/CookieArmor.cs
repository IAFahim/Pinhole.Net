using System.Security.Cryptography;

namespace Pinhole;

internal sealed class CookieArmor
{
    public const long EpochMs = 120_000;
    public const int LoadWindowMs = 10_000;

    public const int PerSourceThreshold = 64;

    public const int GlobalThreshold = 512;

    public const int MaxSources = 64;

    private readonly object _gate = new();
    private readonly Func<long> _clock;
    private byte[] _secretCurrent = RandomNumberGenerator.GetBytes(32);
    private byte[] _secretPrevious = RandomNumberGenerator.GetBytes(32);
    private long _epochIndex = long.MinValue;

    private readonly byte[][] _sourceKeys = new byte[MaxSources][];
    private readonly long[] _sourceWindowStart = new long[MaxSources];
    private readonly int[] _sourceCount = new int[MaxSources];
    private int _sourceFill;
    private long _globalWindowStart;
    private int _globalCount;

    public CookieArmor(Func<long>? clock = null)
    {
        _clock = clock ?? (static () => Environment.TickCount64);
    }

    public int TrackedSources
    {
        get
        {
            lock (_gate)
            {
                return _sourceFill;
            }
        }
    }

    public byte Mint(Span<byte> destination, ReadOnlySpan<byte> sourceKey)
    {
        lock (_gate)
        {
            RotateIfDue(_clock());
            CryptoWire.CookieFor(destination, _secretCurrent, sourceKey);
            return (byte)(_epochIndex & 0xFF);
        }
    }

    public bool VerifyMac2(ReadOnlySpan<byte> frame, ReadOnlySpan<byte> sourceKey)
    {
        lock (_gate)
        {
            RotateIfDue(_clock());
            Span<byte> cookie = stackalloc byte[CryptoWire.CookieLength];
            CryptoWire.CookieFor(cookie, _secretCurrent, sourceKey);
            if (CryptoWire.VerifyMac2(frame, cookie))
            {
                return true;
            }

            CryptoWire.CookieFor(cookie, _secretPrevious, sourceKey);
            return CryptoWire.VerifyMac2(frame, cookie);
        }
    }

    public bool NotePuncAndCheckLoad(ReadOnlySpan<byte> sourceKey, long now)
    {
        lock (_gate)
        {
            bool globalHot = CountWindow(ref _globalWindowStart, ref _globalCount, now) >= GlobalThreshold;
            int slot = FindOrAdd(sourceKey, now);
            bool sourceHot = _sourceCount[slot] >= PerSourceThreshold;
            return globalHot || sourceHot;
        }
    }

    private int CountWindow(ref long windowStart, ref int count, long now)
    {
        if (now - windowStart >= LoadWindowMs)
        {
            windowStart = now;
            count = 0;
        }

        count = count == int.MaxValue ? count : count + 1;
        return count;
    }

    private int FindOrAdd(ReadOnlySpan<byte> sourceKey, long now)
    {
        for (int i = 0; i < _sourceFill; i++)
        {
            if (_sourceKeys[i].AsSpan().SequenceEqual(sourceKey))
            {
                CountWindow(ref _sourceWindowStart[i], ref _sourceCount[i], now);
                return i;
            }
        }

        int slot = _sourceFill < MaxSources ? _sourceFill++ : EvictColdest(now);
        _sourceKeys[slot] = sourceKey.ToArray();
        _sourceWindowStart[slot] = now;
        _sourceCount[slot] = 1;
        return slot;
    }

    private int EvictColdest(long now)
    {
        int coldest = 0;
        for (int i = 1; i < MaxSources; i++)
        {
            if (_sourceWindowStart[i] < _sourceWindowStart[coldest]
                || _sourceWindowStart[i] == _sourceWindowStart[coldest] && _sourceCount[i] < _sourceCount[coldest])
            {
                coldest = i;
            }
        }

        return coldest;
    }

    private void RotateIfDue(long now)
    {
        long epoch = now / EpochMs;
        if (epoch == _epochIndex)
        {
            return;
        }

        _secretPrevious = _secretCurrent;
        _secretCurrent = RandomNumberGenerator.GetBytes(32);
        _epochIndex = epoch;
    }
}
