namespace Pinhole.Crypto;

public readonly struct Tick : IEquatable<Tick>, IComparable<Tick>
{
    public long Milliseconds { get; }

    public Tick(long milliseconds)
    {
        Milliseconds = milliseconds;
    }

    public static Tick FromMilliseconds(long milliseconds) => new(milliseconds);

    public static Tick FromTimeSpan(TimeSpan span) => new(checked((long)span.TotalMilliseconds));

    public long MillisecondsSince(Tick earlier) => checked(Milliseconds - earlier.Milliseconds);

    public bool Equals(Tick other) => Milliseconds == other.Milliseconds;

    public int CompareTo(Tick other) => Milliseconds.CompareTo(other.Milliseconds);

    public override bool Equals(object? obj) => obj is Tick other && Equals(other);

    public override int GetHashCode() => Milliseconds.GetHashCode();

    public static bool operator <(Tick left, Tick right) => left.Milliseconds < right.Milliseconds;

    public static bool operator >(Tick left, Tick right) => left.Milliseconds > right.Milliseconds;

    public static bool operator <=(Tick left, Tick right) => left.Milliseconds <= right.Milliseconds;

    public static bool operator >=(Tick left, Tick right) => left.Milliseconds >= right.Milliseconds;
}
