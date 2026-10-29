namespace Pinhole.Crypto;

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
            : this;

    public bool Equals(ReplayWindow other) => Highest == other.Highest && Bitmap == other.Bitmap;

    public override bool Equals(object? obj) => obj is ReplayWindow other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(Highest, Bitmap);
}
