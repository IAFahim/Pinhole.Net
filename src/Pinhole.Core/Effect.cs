namespace Pinhole.Core;

public enum EffectKind : byte
{
    Transmit = 0,
    Deliver = 1,
    Arm = 2,
    Notify = 3,
    Close = 4,
}

// One effect per slot, written by machines into a caller-supplied span (stackalloc at the
// call site; never allocated). Offset/Length address bytes of a Transmit/Deliver buffer;
// Value carries the per-kind payload (nonce, deadline tick, counter).
public struct Effect
{
    public EffectKind Kind;
    public int Path;
    public int Offset;
    public int Length;
    public long Value;
}

// Path tags for effects whose target is one of the two routed paths. The Pinhole.Net
// shells interpret these; machines only ever compare and echo them.
public static class EffectPath
{
    public const int Direct = 0;
    public const int Relay = 1;
}

// Machines never throw on a full span: they emit what fits and report the written count,
// so a caller that passes Span<Effect>.Empty gets the decision without the effects.
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
