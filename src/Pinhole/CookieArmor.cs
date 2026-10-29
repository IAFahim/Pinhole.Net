using System.Security.Cryptography;

namespace Pinhole;

// mac2/cookie armor state (R5 phase 2), the responder's half of the WireGuard cookie
// idea. Two bounded pieces:
//
//   - The jar: a rotating 32-byte secret; the cookie for a source address is
//     BLAKE3-Keyed(secret, sourceAddress)[..16]. The secret rotates every CookieEpochMs
//     and the previous epoch stays valid, so a cookie minted in epoch N-1 still answers
//     in epoch N (in-flight handshakes survive rotation); epoch N-2 is refused because
//     that secret is gone.
//
//   - The load table: which sources the responder is answering with cookies. A fixed
//     window of LoadWindowMs counts mac1-valid PUNCs that earned no session yet — per
//     source (a single-source flood) and globally (a spoofed-source flood, where every
//     PUNC arrives from a fresh address and no per-source count can ever trip). Both
//     counters live in bounded memory: one global window and a fixed-size source table
//     whose coldest entry is evicted when a new source arrives.
//
// The class holds no sockets, no clocks, and no handshake state; the engine feeds it a
// monotonic now (a Func<long> seam lets tests drive epochs deterministically).
internal sealed class CookieArmor
{
    public const long EpochMs = 120_000;
    public const int LoadWindowMs = 10_000;

    // An honest dialer punches at one PUNC per candidate per PunchPaceMs (200 ms) = 5/s
    // per candidate; a healthy dial completes in well under the window, so even a
    // several-candidate dial stays far below 64 counted PUNCs from its one source
    // address. A single-source flood crosses it in a fraction of a second.
    public const int PerSourceThreshold = 64;

    // The global arm catches what per-source counting structurally cannot: a spoofed
    // flood where every PUNC wears a fresh source address. 512 in 10 s is ~51 PUNCs/s
    // sustained engine-wide — an honest node's concurrent dials (each <= 5/s per
    // candidate) do not reach it; floods do by orders of magnitude.
    public const int GlobalThreshold = 512;

    // Bounded memory for the source table: evict the coldest window when full.
    public const int MaxSources = 64;

    private readonly object _gate = new();
    private readonly Func<long> _clock;
    private byte[] _secretCurrent = RandomNumberGenerator.GetBytes(32);
    private byte[] _secretPrevious = RandomNumberGenerator.GetBytes(32);
    private long _epochIndex = long.MinValue; // first use rotates both secrets away

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

    // Writes the 16-byte cookie for this source into destination and returns the minting
    // epoch's tag (the epoch number as u8 — diagnostics on the wire; verification itself
    // tries the two live secrets and never trusts it).
    public byte Mint(Span<byte> destination, ReadOnlySpan<byte> sourceKey)
    {
        lock (_gate)
        {
            RotateIfDue(_clock());
            CryptoWire.CookieFor(destination, _secretCurrent, sourceKey);
            return (byte)(_epochIndex & 0xFF);
        }
    }

    // True when the frame's mac2 extension verifies under the cookie for this source
    // address, trying both live epochs. A cookie minted for any other source — or any
    // epoch older than the previous — cannot pass: the recomputed key differs.
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

    // Counts one mac1-valid, session-less PUNC from this source and reports whether the
    // source is now under load (its own window tripped, or the global window did). The
    // packet that crosses a threshold trips the gate for itself: count, then verdict.
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

        return coldest; // the least recently (re)armed entry; a flood cycling sources evicts these
    }

    private void RotateIfDue(long now)
    {
        long epoch = now / EpochMs;
        if (epoch == _epochIndex)
        {
            return;
        }

        // One hop regardless of how many epochs passed: anything older than the previous
        // epoch is unreachable by design, so skipping ahead just drops both old secrets.
        _secretPrevious = _secretCurrent;
        _secretCurrent = RandomNumberGenerator.GetBytes(32);
        _epochIndex = epoch;
    }
}
