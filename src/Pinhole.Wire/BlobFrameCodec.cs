using System.Buffers.Binary;

namespace Pinhole.Wire;

// A zero-copy view of a parsed blob frame: scalars are decoded up front, and
// every byte region (session id, chunk data, ...) is an offset+length into the
// input span, so the hot receive path allocates nothing (audit H-05). A view is
// only meaningful after BlobFrameCodec.TryParse returned true; a default view
// reads as type 0 with empty spans and zero scalars, never out of range.
public readonly ref struct BlobFrameView
{
    private readonly ReadOnlySpan<byte> _frame;
    private readonly int _sessionIdStart;
    private readonly int _sessionIdLength;
    private readonly int _nonceStart;
    private readonly int _nonceLength;
    private readonly int _sealedHeadStart;
    private readonly int _sealedHeadLength;
    private readonly int _chunkCvStart;
    private readonly int _chunkCvLength;
    private readonly int _chunkDataStart;
    private readonly int _chunkDataLength;
    private readonly int _siblingCvsStart;
    private readonly int _siblingCvsLength;

    public byte Type { get; }
    public ulong Stream { get; }
    public byte Version { get; }
    public long TotalBytes { get; }
    public long TotalChunks { get; }
    public long StartChunk { get; }
    public int Count { get; }
    public long Index { get; }

    internal BlobFrameView(byte type, ReadOnlySpan<byte> frame)
    {
        _frame = frame;
        _sessionIdStart = 0;
        _sessionIdLength = 0;
        _nonceStart = 0;
        _nonceLength = 0;
        _sealedHeadStart = 0;
        _sealedHeadLength = 0;
        _chunkCvStart = 0;
        _chunkCvLength = 0;
        _chunkDataStart = 0;
        _chunkDataLength = 0;
        _siblingCvsStart = 0;
        _siblingCvsLength = 0;
        Type = type;
        Stream = WirePrimitives.TryReadU64Be(frame[1..], out ulong stream) ? stream : 0;
        Version = 0;
        TotalBytes = 0;
        TotalChunks = 0;
        StartChunk = 0;
        Count = 0;
        Index = 0;

        int body = frame.Length - BlobFrameCodec.HeaderLength;
        switch (type)
        {
            case BlobFrameCodec.TypeHello:
                if (body == 0)
                {
                    Version = 1;
                }
                else if (body == BlobFrameCodec.SessionIdLength)
                {
                    Version = 2;
                    _sessionIdStart = BlobFrameCodec.HeaderLength;
                    _sessionIdLength = BlobFrameCodec.SessionIdLength;
                }
                else
                {
                    Version = frame[9];
                    _sessionIdStart = BlobFrameCodec.HeaderLength + 1;
                    _sessionIdLength = BlobFrameCodec.SessionIdLength;
                }

                break;
            case BlobFrameCodec.TypeWelcome:
                Version = frame[9];
                _sessionIdStart = 10;
                _sessionIdLength = BlobFrameCodec.SessionIdLength;
                _nonceStart = 10 + BlobFrameCodec.SessionIdLength;
                _nonceLength = BlobFrameCodec.SessionIdLength;
                _sealedHeadStart = 10 + 2 * BlobFrameCodec.SessionIdLength;
                _sealedHeadLength = BlobFrameCodec.SealedHeadLength;
                break;
            case BlobFrameCodec.TypeHead:
                TotalBytes = BinaryPrimitives.ReadInt64LittleEndian(frame.Slice(9, 8));
                TotalChunks = BinaryPrimitives.ReadInt64LittleEndian(frame.Slice(17, 8));
                break;
            case BlobFrameCodec.TypeReq:
                StartChunk = BinaryPrimitives.ReadInt64LittleEndian(frame.Slice(9, 8));
                Count = BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(17, 2));
                break;
            case BlobFrameCodec.TypeChunk:
                Index = BinaryPrimitives.ReadInt64LittleEndian(frame.Slice(9, 8));
                _chunkCvStart = 17;
                _chunkCvLength = 32;
                _chunkDataStart = 49;
                _chunkDataLength = frame.Length - 49;
                break;
            case BlobFrameCodec.TypeProof:
                Index = BinaryPrimitives.ReadInt64LittleEndian(frame.Slice(9, 8));
                Count = frame[17];
                _siblingCvsStart = 18;
                _siblingCvsLength = Count * 32;
                break;
        }
    }

    public readonly ReadOnlySpan<byte> SessionId => _frame.Slice(_sessionIdStart, _sessionIdLength);

    public readonly ReadOnlySpan<byte> ProviderNonce => _frame.Slice(_nonceStart, _nonceLength);

    public readonly ReadOnlySpan<byte> SealedHead => _frame.Slice(_sealedHeadStart, _sealedHeadLength);

    public readonly ReadOnlySpan<byte> ChunkCv => _frame.Slice(_chunkCvStart, _chunkCvLength);

    public readonly ReadOnlySpan<byte> ChunkData => _frame.Slice(_chunkDataStart, _chunkDataLength);

    public readonly ReadOnlySpan<byte> SiblingCvs => _frame.Slice(_siblingCvsStart, _siblingCvsLength);

    public readonly ReadOnlySpan<byte> Sibling(int index) => SiblingCvs.Slice(32 * index, 32);
}

// Span-based codec for the blob transport frames, byte-compatible with
// BlobWire.Frame.TryParse. Layout: u8 type, u64 BE stream id, then a per-type
// body with no length prefix (the enclosing transport delimits frames).
//
// Acceptance rules, preserved exactly from the existing parser:
//   Hello    body 0 (v1), 32 (v2), or 33 with leading version byte 3 (v3) or
//            4 (v4); 33 with any other version byte, or any other length,
//            rejects
//   Welcome  body exactly 1+64+49 with leading version byte 3 or 4
//   Bye      body empty
//   Head     body 16; TotalBytes >= 0 and TotalChunks == ceil(TotalBytes/1024)
//   Req      body 10; StartChunk >= 0 and Count in [1, 64]
//   Chunk    body in [41, 1064]; Index >= 0; data (body[40..]) non-empty
//   Proof    body exactly 9 + count*32; runIndex >= 0 and count <= 64
//   anything else (short frames, unknown types) rejects
// The Write side defaults to the legacy v3 Hello/Welcome and emits the v4
// forms when asked. The v1/v2 Hello forms are recognized receive-side only so
// callers can refuse them explicitly (wire v1/v2 are refused by design, issue
// #49) and have no writer. Unlike BlobWire.Head and BlobWire.Request, the
// writers refuse to emit what the parser would reject.
public static class BlobFrameCodec
{
    public const byte TypeHello = 1;
    public const byte TypeHead = 2;
    public const byte TypeReq = 3;
    public const byte TypeChunk = 4;
    public const byte TypeBye = 5;
    public const byte TypeWelcome = 6;
    public const byte TypeProof = 7;
    public const byte ProtocolVersion = 3;
    public const byte CurrentVersion = 4;

    public const int HeaderLength = 9;
    public const int SessionIdLength = 32;

    // 8-byte counter + a sealed 25-byte Head frame + 16-byte tag, opaque here
    public const int SealedHeadLength = 8 + 25 + 16;

    public const int MaxChunkData = 1024;
    public const int MaxRequestCount = 64;
    public const int MaxProofSiblings = 64;

    public const int HelloV1Length = HeaderLength;
    public const int HelloV2Length = HeaderLength + SessionIdLength;
    public const int HelloV3Length = HelloV2Length + 1;
    public const int HelloV4Length = HelloV3Length; // same shape, version byte 4
    public const int WelcomeLength = HeaderLength + 1 + 2 * SessionIdLength + SealedHeadLength;
    public const int WelcomeV4Length = WelcomeLength; // same shape, version byte 4
    public const int ProofMinLength = HeaderLength + 8 + 1; // runIndex + count byte, no siblings
    public const int ProofMaxLength = HeaderLength + 8 + 1 + MaxProofSiblings * 32;
    public const int HeadLength = HeaderLength + 16;
    public const int RequestLength = HeaderLength + 10;
    public const int ChunkMinLength = HeaderLength + 8 + 32 + 1;
    public const int ChunkMaxLength = HeaderLength + 8 + 32 + MaxChunkData;

    public static bool TryParse(ReadOnlySpan<byte> frame, out BlobFrameView view)
    {
        view = default;
        if (frame.Length < HeaderLength)
        {
            return false;
        }

        switch (frame[0])
        {
            case TypeHello:
            {
                int body = frame.Length - HeaderLength;
                if (body != 0 && body != SessionIdLength
                    && (body != 1 + SessionIdLength
                        || frame[HeaderLength] is not (ProtocolVersion or CurrentVersion)))
                {
                    return false;
                }

                break;
            }
            case TypeWelcome:
            {
                if (frame.Length != WelcomeLength || frame[HeaderLength] is not (ProtocolVersion or CurrentVersion))
                {
                    return false;
                }

                break;
            }
            case TypeBye:
            {
                if (frame.Length != HeaderLength)
                {
                    return false;
                }

                break;
            }
            case TypeHead:
            {
                if (frame.Length != HeadLength)
                {
                    return false;
                }

                long totalBytes = BinaryPrimitives.ReadInt64LittleEndian(frame.Slice(9, 8));
                long totalChunks = BinaryPrimitives.ReadInt64LittleEndian(frame.Slice(17, 8));
                if (totalBytes < 0 || totalChunks != ChunkCount(totalBytes))
                {
                    return false; // only (0, 0) represents the empty blob; lying counts reject
                }

                break;
            }
            case TypeReq:
            {
                if (frame.Length != RequestLength)
                {
                    return false;
                }

                long startChunk = BinaryPrimitives.ReadInt64LittleEndian(frame.Slice(9, 8));
                int count = BinaryPrimitives.ReadUInt16LittleEndian(frame.Slice(17, 2));
                if (startChunk < 0 || count is < 1 or > MaxRequestCount)
                {
                    return false;
                }

                break;
            }
            case TypeChunk:
            {
                if (frame.Length is < ChunkMinLength or > ChunkMaxLength)
                {
                    return false;
                }

                if (BinaryPrimitives.ReadInt64LittleEndian(frame.Slice(9, 8)) < 0)
                {
                    return false;
                }

                break;
            }
            case TypeProof:
            {
                if (frame.Length is < ProofMinLength or > ProofMaxLength)
                {
                    return false;
                }

                int count = frame[17];
                if (BinaryPrimitives.ReadInt64LittleEndian(frame.Slice(9, 8)) < 0 || count > MaxProofSiblings
                    || frame.Length != ProofMinLength + count * 32)
                {
                    return false; // count promises a sibling run that is not exactly there
                }

                break;
            }
            default:
                return false;
        }

        view = new BlobFrameView(frame[0], frame);
        return true;
    }

    public static long ChunkCount(long totalBytes) =>
        totalBytes / MaxChunkData + (totalBytes % MaxChunkData == 0 ? 0 : 1);

    public static int WriteHello(Span<byte> destination, ulong stream, ReadOnlySpan<byte> sessionId,
        byte version = ProtocolVersion)
    {
        CheckVersion(version);
        if (sessionId.Length != SessionIdLength)
        {
            throw new ArgumentException($"session id must be {SessionIdLength} bytes", nameof(sessionId));
        }

        if (destination.Length < HelloV3Length)
        {
            ThrowTooSmall();
        }

        destination[0] = TypeHello;
        WirePrimitives.WriteU64Be(destination.Slice(1, 8), stream);
        destination[9] = version;
        sessionId.CopyTo(destination.Slice(10, SessionIdLength));
        return HelloV3Length;
    }

    public static int WriteWelcome(Span<byte> destination, ulong stream, ReadOnlySpan<byte> sessionId,
        ReadOnlySpan<byte> providerNonce, ReadOnlySpan<byte> sealedHead, byte version = ProtocolVersion)
    {
        CheckVersion(version);
        if (sessionId.Length != SessionIdLength || providerNonce.Length != SessionIdLength
            || sealedHead.Length != SealedHeadLength)
        {
            throw new ArgumentException(
                $"Welcome requires two {SessionIdLength}-byte nonces and a {SealedHeadLength}-byte sealed Head");
        }

        if (destination.Length < WelcomeLength)
        {
            ThrowTooSmall();
        }

        destination[0] = TypeWelcome;
        WirePrimitives.WriteU64Be(destination.Slice(1, 8), stream);
        destination[9] = version;
        sessionId.CopyTo(destination.Slice(10, SessionIdLength));
        providerNonce.CopyTo(destination.Slice(10 + SessionIdLength, SessionIdLength));
        sealedHead.CopyTo(destination.Slice(10 + 2 * SessionIdLength, SealedHeadLength));
        return WelcomeLength;
    }

    private static void CheckVersion(byte version)
    {
        if (version is not (ProtocolVersion or CurrentVersion))
        {
            throw new ArgumentOutOfRangeException(nameof(version), "blob protocol version must be 3 or 4");
        }
    }

    public static int WriteBye(Span<byte> destination, ulong stream)
    {
        if (destination.Length < HeaderLength)
        {
            ThrowTooSmall();
        }

        destination[0] = TypeBye;
        WirePrimitives.WriteU64Be(destination.Slice(1, 8), stream);
        return HeaderLength;
    }

    public static int WriteHead(Span<byte> destination, ulong stream, long totalBytes, long totalChunks)
    {
        if (totalBytes < 0 || totalChunks != ChunkCount(totalBytes))
        {
            throw new ArgumentException("Head must carry the exact chunk count for totalBytes", nameof(totalChunks));
        }

        if (destination.Length < HeadLength)
        {
            ThrowTooSmall();
        }

        destination[0] = TypeHead;
        WirePrimitives.WriteU64Be(destination.Slice(1, 8), stream);
        BinaryPrimitives.WriteInt64LittleEndian(destination.Slice(9, 8), totalBytes);
        BinaryPrimitives.WriteInt64LittleEndian(destination.Slice(17, 8), totalChunks);
        return HeadLength;
    }

    public static int WriteRequest(Span<byte> destination, ulong stream, long startChunk, int count)
    {
        if (startChunk < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(startChunk), "chunk indices are never negative");
        }

        if (count is < 1 or > MaxRequestCount)
        {
            throw new ArgumentOutOfRangeException(nameof(count), $"requests carry 1..{MaxRequestCount} chunks");
        }

        if (destination.Length < RequestLength)
        {
            ThrowTooSmall();
        }

        destination[0] = TypeReq;
        WirePrimitives.WriteU64Be(destination.Slice(1, 8), stream);
        BinaryPrimitives.WriteInt64LittleEndian(destination.Slice(9, 8), startChunk);
        WirePrimitives.WriteU16Le(destination.Slice(17, 2), (ushort)count);
        return RequestLength;
    }

    public static int WriteChunk(Span<byte> destination, ulong stream, long index, ReadOnlySpan<byte> chunkCv,
        ReadOnlySpan<byte> data)
    {
        if (index < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index), "chunk indices are never negative");
        }

        if (chunkCv.Length != 32)
        {
            throw new ArgumentException("chunk chaining value must be 32 bytes", nameof(chunkCv));
        }

        if (data.Length is < 1 or > MaxChunkData)
        {
            throw new ArgumentOutOfRangeException(nameof(data), $"chunk data is 1..{MaxChunkData} bytes");
        }

        int total = HeaderLength + 8 + 32 + data.Length;
        if (destination.Length < total)
        {
            ThrowTooSmall();
        }

        destination[0] = TypeChunk;
        WirePrimitives.WriteU64Be(destination.Slice(1, 8), stream);
        BinaryPrimitives.WriteInt64LittleEndian(destination.Slice(9, 8), index);
        chunkCv.CopyTo(destination.Slice(17, 32));
        data.CopyTo(destination.Slice(49, data.Length));
        return total;
    }

    // Sibling CVs run bottom-up: from the verified run's root toward the file root.
    public static int WriteProof(Span<byte> destination, ulong stream, long runIndex, ReadOnlySpan<byte> siblingCvs)
    {
        if (runIndex < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(runIndex), "run indices are never negative");
        }

        if (siblingCvs.Length % 32 != 0 || siblingCvs.Length / 32 > MaxProofSiblings)
        {
            throw new ArgumentException($"sibling CVs are 0..{MaxProofSiblings} 32-byte values", nameof(siblingCvs));
        }

        int total = ProofMinLength + siblingCvs.Length;
        if (destination.Length < total)
        {
            ThrowTooSmall();
        }

        destination[0] = TypeProof;
        WirePrimitives.WriteU64Be(destination.Slice(1, 8), stream);
        BinaryPrimitives.WriteInt64LittleEndian(destination.Slice(9, 8), runIndex);
        destination[17] = (byte)(siblingCvs.Length / 32);
        siblingCvs.CopyTo(destination.Slice(18, siblingCvs.Length));
        return total;
    }

    private static void ThrowTooSmall() => throw new ArgumentException("destination span too small");
}
