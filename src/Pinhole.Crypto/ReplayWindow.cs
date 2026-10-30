using System.Runtime.CompilerServices;

namespace Pinhole.Crypto;

public struct ReplayWindow : IEquatable<ReplayWindow>
{
    public const int CapacityBits = 1024;
    private const int WordBits = 64;
    private const int WordCount = CapacityBits / WordBits;

    [InlineArray(WordCount)]
    private struct WordVector
    {
        private ulong _element;
    }

    public ulong Highest;
    private WordVector _bits;

    public bool Admits(ulong counter)
    {
        if (counter > Highest)
        {
            return true;
        }

        ulong age = Highest - counter;
        if (age >= CapacityBits)
        {
            return false;
        }

        ulong position = counter % CapacityBits;
        ulong word = _bits[(int)(position / WordBits)];
        return (word >> (int)(position % WordBits) & 1UL) == 0;
    }

    public ReplayWindow Mark(ulong counter)
    {
        if (counter > Highest)
        {
            ReplayWindow next = this;
            ulong advance = counter - Highest;
            if (advance >= CapacityBits)
            {
                next = default;
            }
            else
            {
                for (ulong evicted = Highest + 1; evicted <= counter; evicted++)
                {
                    ulong position = evicted % CapacityBits;
                    next._bits[(int)(position / WordBits)] &= ~(1UL << (int)(position % WordBits));
                }
            }

            ulong markPosition = counter % CapacityBits;
            next.Highest = counter;
            next._bits[(int)(markPosition / WordBits)] |= 1UL << (int)(markPosition % WordBits);
            return next;
        }

        ulong age = Highest - counter;
        if (age >= CapacityBits)
        {
            return this;
        }

        ReplayWindow marked = this;
        ulong markedPosition = counter % CapacityBits;
        marked._bits[(int)(markedPosition / WordBits)] |= 1UL << (int)(markedPosition % WordBits);
        return marked;
    }

    public bool Equals(ReplayWindow other)
    {
        if (Highest != other.Highest)
        {
            return false;
        }

        for (int i = 0; i < WordCount; i++)
        {
            if (_bits[i] != other._bits[i])
            {
                return false;
            }
        }

        return true;
    }

    public override bool Equals(object? obj) => obj is ReplayWindow other && Equals(other);

    public override int GetHashCode()
    {
        HashCode hash = default;
        hash.Add(Highest);
        for (int i = 0; i < WordCount; i++)
        {
            hash.Add(_bits[i]);
        }

        return hash.ToHashCode();
    }
}
