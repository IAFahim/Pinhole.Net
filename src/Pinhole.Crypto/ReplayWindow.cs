namespace Pinhole.Crypto;

// A 64-counter sliding replay window as one immutable value: Highest is the newest
// marked counter, Bitmap bit i records whether counter Highest - i is already marked
// (bit 0 = Highest itself). Admits accepts anything above Highest and, within the 64
// below it, anything whose bit is clear. Mark on a counter below the window is a
// no-op (the caller checked Admits first); the caller contract is check-then-mark.
// Two windows can be compared for equality to snapshot receive state.
public readonly struct ReplayWindow : IEquatable<ReplayWindow>
{
    public readonly ulong Highest;
    public readonly ulong Bitmap;

    public ReplayWindow(ulong highest, ulong bitmap)
    {
        Highest = highest;
        Bitmap = bitmap;
    }

    public bool Admits(ulong counter) =>
        counter > Highest || (Highest - counter < 64 && ((Bitmap >> (int)(Highest - counter)) & 1UL) == 0);

    public ReplayWindow Mark(ulong counter) => counter > Highest
        ? new ReplayWindow(counter, (counter - Highest >= 64 ? 0UL : Bitmap << (int)(counter - Highest)) | 1UL)
        : Highest - counter < 64
            ? new ReplayWindow(Highest, Bitmap | (1UL << (int)(Highest - counter)))
            : this; // below the window: already rejected, no state change

    public bool Equals(ReplayWindow other) => Highest == other.Highest && Bitmap == other.Bitmap;

    public override bool Equals(object? obj) => obj is ReplayWindow other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(Highest, Bitmap);
}
