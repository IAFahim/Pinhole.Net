namespace Pinhole.Crypto;

// Credit ledger for shared budgets (the pacer pie, relay grants, connection caps):
// Outstanding never exceeds Capacity, reserves are all-or-nothing, and releases must
// return previously reserved credit. Conservation invariant for any operation
// sequence: Outstanding equals the sum of live reservations, and is zero at
// quiescence. Relocates to Pinhole.Core with the sans-IO machines.
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
