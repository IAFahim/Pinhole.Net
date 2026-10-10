using System.Buffers.Binary;
using System.Text;

namespace Pinhole.Moq;

internal sealed class MoqWriter
{
    private readonly MemoryStream _buffer = new();
    public void Integer(ulong value)
    {
        if (value >= (1UL << 62)) throw new ArgumentOutOfRangeException(nameof(value));
        var length = value < 64 ? 1 : value < 16384 ? 2 : value < 1073741824 ? 4 : 8;
        Span<byte> bytes = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        bytes[8 - length] |= (byte)((length == 1 ? 0 : length == 2 ? 1 : length == 4 ? 2 : 3) << 6);
        _buffer.Write(bytes[(8 - length)..]);
    }
    public void Byte(byte value) => _buffer.WriteByte(value);
    public void Bytes(ReadOnlySpan<byte> value) => _buffer.Write(value);
    public void Blob(ReadOnlySpan<byte> value) { Integer((ulong)value.Length); Bytes(value); }
    public void Text(string value) => Blob(Encoding.UTF8.GetBytes(value));
    public void Namespace(string value) { Integer(1); Text(value); }
    public void Parameters(params (ulong Key, object Value)[] pairs)
    {
        Integer((ulong)pairs.Length);
        ulong previous = 0;
        foreach (var pair in pairs.OrderBy(x => x.Key))
        {
            Integer(pair.Key - previous); previous = pair.Key;
            if ((pair.Key & 1) == 0) Integer((ulong)pair.Value);
            else Blob((byte[])pair.Value);
        }
    }
    public byte[] ToArray() => _buffer.ToArray();
    public byte[] Message(ulong type)
    {
        var payload = ToArray();
        if (payload.Length > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(type));
        var result = new MoqWriter(); result.Integer(type);
        result.Byte((byte)(payload.Length >> 8)); result.Byte((byte)payload.Length); result.Bytes(payload);
        return result.ToArray();
    }
}

internal sealed class MoqReader(byte[] data)
{
    private int _offset;
    public int Remaining => data.Length - _offset;
    public ulong Integer()
    {
        var first = Byte(); var length = 1 << (first >> 6); ulong value = (ulong)(first & 0x3f);
        for (var i = 1; i < length; i++) value = (value << 8) | Byte();
        return value;
    }
    public byte Byte()
    {
        if (_offset >= data.Length) throw new MoqProtocolException("Truncated MoQ field");
        return data[_offset++];
    }
    public byte[] Blob(int maximum = 4096)
    {
        var length = Integer();
        if (length > (ulong)maximum || length > (ulong)Remaining) throw new MoqProtocolException("Invalid MoQ field length");
        var result = data.AsSpan(_offset, (int)length).ToArray(); _offset += (int)length; return result;
    }
    public string Text() => new UTF8Encoding(false, true).GetString(Blob());
    public string Namespace()
    {
        var count = Integer();
        // The public API publishes exactly one UTF-8 namespace element.
        // Joining multiple elements with '/' would conflate distinct protocol names.
        if (count != 1) throw new MoqProtocolException("Only single-element namespaces are supported");
        return Text();
    }
    public Dictionary<ulong, object> Parameters()
    {
        var count = Integer();
        if (count > 128) throw new MoqProtocolException("Too many MoQ parameters");
        return Pairs((int)count);
    }
    public Dictionary<ulong, object> Extensions() => Pairs(null);
    private Dictionary<ulong, object> Pairs(int? count)
    {
        var result = new Dictionary<ulong, object>(); ulong key = 0;
        for (var i = 0; count.HasValue ? i < count.Value : Remaining > 0; i++)
        {
            if (i >= 128) throw new MoqProtocolException("Too many MoQ fields");
            key = checked(key + Integer());
            var value = (key & 1) == 0 ? (object)Integer() : Blob(ushort.MaxValue);
            if (!result.TryAdd(key, value)) throw new MoqProtocolException("Duplicate MoQ parameter");
        }
        return result;
    }
    public void End() { if (Remaining != 0) throw new MoqProtocolException("Trailing MoQ fields"); }
}

internal static class MoqStreamWire
{
    public static async ValueTask<ulong?> ReadIntegerAsync(Stream stream, CancellationToken cancellationToken)
    {
        var bytes = new byte[8]; var read = await stream.ReadAsync(bytes.AsMemory(0, 1), cancellationToken);
        if (read == 0) return null;
        var length = 1 << (bytes[0] >> 6); ulong value = (ulong)(bytes[0] & 0x3f);
        await stream.ReadExactlyAsync(bytes.AsMemory(1, length - 1), cancellationToken);
        for (var i = 1; i < length; i++) value = (value << 8) | bytes[i];
        return value;
    }
    public static async ValueTask<ulong> RequiredIntegerAsync(Stream stream, CancellationToken cancellationToken) =>
        await ReadIntegerAsync(stream, cancellationToken) ?? throw new MoqProtocolException("Truncated MoQ stream");
    public static async Task<(ulong Type, byte[] Payload)> ReadMessageAsync(Stream stream, CancellationToken cancellationToken)
    {
        var type = await RequiredIntegerAsync(stream, cancellationToken);
        var header = new byte[2]; await stream.ReadExactlyAsync(header, cancellationToken);
        var payload = new byte[BinaryPrimitives.ReadUInt16BigEndian(header)];
        await stream.ReadExactlyAsync(payload, cancellationToken); return (type, payload);
    }
}

public sealed class MoqProtocolException(string message) : IOException(message);
public sealed class MoqRequestException(ulong code) : IOException($"MoQ request rejected (code {code})")
{
    public ulong ErrorCode { get; } = code;
}
