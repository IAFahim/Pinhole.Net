namespace Pinhole.Fuzz;

public sealed class Mutator
{
    private static readonly byte[] Interesting =
        [0x00, 0x01, 0x02, 0x03, 0x0F, 0x10, 0x3F, 0x40, 0x41, 0x7E, 0x7F, 0x80, 0x81, 0xBF, 0xC0, 0xC1, 0xFE, 0xFF];

    private readonly FuzzRng _rng;

    public Mutator(FuzzRng rng)
    {
        _rng = rng;
    }

    public byte[] Apply(byte[] input, byte[][] pool, out string op)
    {
        switch (_rng.NextInt(8))
        {
            case 0:
                return FlipBits(input, out op);
            case 1:
                return SpillInteresting(input, out op);
            case 2:
                return Splice(input, pool, out op);
            case 3:
                return Duplicate(input, out op);
            case 4:
                return Delete(input, out op);
            case 5:
                return InsertInteresting(input, out op);
            case 6:
                return InsertRandom(input, out op);
            default:
                return Truncate(input, out op);
        }
    }

    private byte[] FlipBits(byte[] input, out string op)
    {
        if (input.Length == 0)
        {
            return InsertInteresting(input, out op);
        }

        int position = _rng.NextInt(input.Length);
        byte mask = (byte)(1 << _rng.NextInt(8));
        byte[] result = (byte[])input.Clone();
        result[position] ^= mask;
        op = $"flip@{position}:0x{mask:X2}";
        return result;
    }

    private byte[] SpillInteresting(byte[] input, out string op)
    {
        byte value = Interesting[_rng.NextInt(Interesting.Length)];
        if (input.Length == 0)
        {
            op = $"spill@0=0x{value:X2}";
            return [value];
        }

        int position = _rng.NextInt(input.Length);
        byte[] result = (byte[])input.Clone();
        result[position] = value;
        op = $"spill@{position}=0x{value:X2}";
        return result;
    }

    private byte[] Splice(byte[] input, byte[][] pool, out string op)
    {
        byte[] donor = pool[_rng.NextInt(pool.Length)];
        if (donor.Length == 0 || input.Length == 0)
        {
            op = "splice-skip";
            return (byte[])input.Clone();
        }

        int from = _rng.NextInt(donor.Length);
        int length = 1 + _rng.NextInt(donor.Length - from);
        int at = _rng.NextInt(input.Length);
        byte[] result = new byte[input.Length + length];
        input.AsSpan(0, at).CopyTo(result);
        donor.AsSpan(from, length).CopyTo(result.AsSpan(at));
        input.AsSpan(at).CopyTo(result.AsSpan(at + length));
        op = $"splice@{at}<-pool[{from}..{from + length})";
        return result;
    }

    private byte[] Duplicate(byte[] input, out string op)
    {
        if (input.Length == 0)
        {
            op = "dup-skip";
            return input;
        }

        int start = _rng.NextInt(input.Length);
        int length = 1 + _rng.NextInt(input.Length - start);
        byte[] result = new byte[input.Length + length];
        input.CopyTo(result);
        input.AsSpan(start, length).CopyTo(result.AsSpan(input.Length));
        op = $"dup@{start}+{length}";
        return result;
    }

    private byte[] Delete(byte[] input, out string op)
    {
        if (input.Length == 0)
        {
            op = "del-skip";
            return input;
        }

        int start = _rng.NextInt(input.Length);
        int length = 1 + _rng.NextInt(input.Length - start);
        byte[] result = new byte[input.Length - length];
        input.AsSpan(0, start).CopyTo(result);
        input.AsSpan(start + length).CopyTo(result.AsSpan(start));
        op = $"del@{start}+{length}";
        return result;
    }

    private byte[] InsertInteresting(byte[] input, out string op)
    {
        int count = 1 + _rng.NextInt(4);
        byte[] run = new byte[count];
        for (int i = 0; i < count; i++)
        {
            run[i] = Interesting[_rng.NextInt(Interesting.Length)];
        }

        return Insert(input, run, out op, "ins");
    }

    private byte[] InsertRandom(byte[] input, out string op)
    {
        int count = 1 + _rng.NextInt(16);
        byte[] run = new byte[count];
        for (int i = 0; i < count; i++)
        {
            run[i] = (byte)_rng.NextInt(256);
        }

        return Insert(input, run, out op, "rnd");
    }

    private byte[] Insert(byte[] input, byte[] run, out string op, string tag)
    {
        int at = _rng.NextInt(input.Length + 1);
        byte[] result = new byte[input.Length + run.Length];
        input.AsSpan(0, at).CopyTo(result);
        run.CopyTo(result, at);
        input.AsSpan(at).CopyTo(result.AsSpan(at + run.Length));
        op = $"{tag}@{at}={Convert.ToHexString(run)}";
        return result;
    }

    private byte[] Truncate(byte[] input, out string op)
    {
        if (input.Length == 0)
        {
            op = "trunc-skip";
            return input;
        }

        int keep = _rng.NextInt(input.Length);
        op = $"trunc@{keep}";
        return input[..keep];
    }
}
