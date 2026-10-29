namespace Pinhole.Core;

public enum EffectKind : byte
{
    Transmit = 0,
    Deliver = 1,
    Arm = 2,
    Notify = 3,
    Close = 4,
}

public struct Effect
{
    public EffectKind Kind;
    public int Path;
    public int Offset;
    public int Length;
    public long Value;
}

public static class EffectPath
{
    public const int Direct = 0;
    public const int Relay = 1;

    public const int DirectLinkLocal = 2;
}

internal static class Effects
{
    public static void Add(Span<Effect> list, ref int count, EffectKind kind, int path, int length, long value)
    {
        if (count >= list.Length)
        {
            return;
        }

        list[count] = new Effect { Kind = kind, Path = path, Length = length, Value = value };
        count++;
    }
}
