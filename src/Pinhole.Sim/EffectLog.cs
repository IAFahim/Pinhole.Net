using System.Buffers.Binary;
using Pinhole.Core;
using Pinhole.Crypto;

namespace Pinhole.Sim;

internal sealed class EffectLog
{
    internal const int RecordBytes = 8 + 1 + 4 + 4 + 4 + 8;

    private byte[] _bytes = new byte[RecordBytes * 64];
    private int _length;

    public long EffectCount { get; private set; }

    public void Append(long tickMs, in Effect effect)
    {
        if (_length + RecordBytes > _bytes.Length)
        {
            Array.Resize(ref _bytes, _bytes.Length * 2);
        }

        BinaryPrimitives.WriteInt64LittleEndian(_bytes.AsSpan(_length), tickMs);
        _bytes[_length + 8] = (byte)effect.Kind;
        BinaryPrimitives.WriteInt32LittleEndian(_bytes.AsSpan(_length + 9), effect.Path);
        BinaryPrimitives.WriteInt32LittleEndian(_bytes.AsSpan(_length + 13), effect.Offset);
        BinaryPrimitives.WriteInt32LittleEndian(_bytes.AsSpan(_length + 17), effect.Length);
        BinaryPrimitives.WriteInt64LittleEndian(_bytes.AsSpan(_length + 21), effect.Value);
        _length += RecordBytes;
        EffectCount++;
    }

    public byte[] Hash() => Blake3.Hash(_bytes.AsSpan(0, _length));
}
