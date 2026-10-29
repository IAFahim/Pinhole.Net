namespace Pinhole.Crypto;

public struct Ledger : IEquatable<Ledger>
{
    public long Capacity { get; }

    public long Outstanding { get; private set; }

    public long Available => Capacity - Outstanding;

    public Ledger(long capacity)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(capacity);
        Capacity = capacity;
    }

    public bool TryReserve(long amount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(amount);
        if (amount > Available)
        {
            return false;
        }

        Outstanding += amount;
        return true;
    }

    public void Release(long amount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(amount);
        if (amount > Outstanding)
        {
            throw new InvalidOperationException("release exceeds outstanding credit");
        }

        Outstanding -= amount;
    }

    public bool Equals(Ledger other) => Capacity == other.Capacity && Outstanding == other.Outstanding;

    public override bool Equals(object? obj) => obj is Ledger other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(Capacity, Outstanding);
}
