namespace Pinhole;

internal sealed class StrangerLedger
{
    public const long WindowMs = CookieArmor.LoadWindowMs;

    public const int PricedRepliesPerWindow = 3;

    public const int MaxSources = CookieArmor.MaxSources;

    private readonly object _gate = new();
    private readonly Func<long> _clock;

    private readonly byte[][] _sourceKeys = new byte[MaxSources][];
    private readonly long[] _sourceWindowStart = new long[MaxSources];
    private readonly int[] _sourceCount = new int[MaxSources];
    private readonly uint[] _sourceTokens = new uint[MaxSources];
    private int _sourceFill;

    public StrangerLedger(Func<long>? clock = null)
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

    public bool TryCharge(ReadOnlySpan<byte> sourceKey, long now, uint token)
    {
        lock (_gate)
        {
            int slot = FindOrAdd(sourceKey, now);
            if (token != 0 && token == _sourceTokens[slot])
            {
                return true;
            }

            if (_sourceCount[slot] >= PricedRepliesPerWindow)
            {
                return false;
            }

            _sourceCount[slot]++;
            _sourceTokens[slot] = token;
            return true;
        }
    }

    public void NoteValidated(ReadOnlySpan<byte> sourceKey, long now)
    {
        lock (_gate)
        {
            for (int i = 0; i < _sourceFill; i++)
            {
                if (_sourceKeys[i].AsSpan().SequenceEqual(sourceKey))
                {
                    _sourceWindowStart[i] = now;
                    _sourceCount[i] = 0;
                    _sourceTokens[i] = 0;
                    return;
                }
            }
        }
    }

    private int FindOrAdd(ReadOnlySpan<byte> sourceKey, long now)
    {
        for (int i = 0; i < _sourceFill; i++)
        {
            if (_sourceKeys[i].AsSpan().SequenceEqual(sourceKey))
            {
                RollIfDue(i, now);
                return i;
            }
        }

        int slot = _sourceFill < MaxSources ? _sourceFill++ : EvictColdest();
        _sourceKeys[slot] = sourceKey.ToArray();
        _sourceWindowStart[slot] = now;
        _sourceCount[slot] = 0;
        _sourceTokens[slot] = 0;
        return slot;
    }

    private void RollIfDue(int slot, long now)
    {
        if (now - _sourceWindowStart[slot] >= WindowMs)
        {
            _sourceWindowStart[slot] = now;
            _sourceCount[slot] = 0;
            _sourceTokens[slot] = 0;
        }
    }

    private int EvictColdest()
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
}
