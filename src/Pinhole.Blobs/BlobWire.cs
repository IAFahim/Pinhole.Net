using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using ChaChaPoly = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;
using Org.BouncyCastle.Crypto.Parameters;

namespace Pinhole.Blobs;

/// <summary>The blob-layer wire protocol: small frames tunneled inside Pinhole Data
/// datagrams, optionally wrapped in ChaCha20-Poly1305 so the public relays forward nothing
/// but ciphertext. One blob stream per BLAKE3 root (its first 8 bytes, big endian, are the
/// stream id); the downloader drives with range requests, the provider answers with
/// self-describing verified chunks. Frame sizes are tuned so the largest (a 1 KiB chunk)
/// stays under the connection's 1200-byte datagram budget, encrypted included.</summary>
internal static class BlobWire
{
    internal const byte TypeHello = 1;
    internal const byte TypeHead = 2;
    internal const byte TypeReq = 3;
    internal const byte TypeChunk = 4;
    internal const byte TypeBye = 5;

    public const int MaxChunkData = Blake3.ChunkSize; // 1024
    public const int MaxRequestCount = 64;

    public static ulong StreamId(byte[] root) => BinaryPrimitives.ReadUInt64BigEndian(root.AsSpan(0, 8));

    private delegate void BodyWriter(Span<byte> body);

    private static byte[] Build(byte type, ulong stream, int bodyLength, BodyWriter write)
    {
        byte[] frame = new byte[9 + bodyLength];
        frame[0] = type;
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(1), stream);
        write(frame.AsSpan(9));
        return frame;
    }

    public static byte[] Hello(ulong stream) => Build(TypeHello, stream, 0, static _ => { });

    public static byte[] Bye(ulong stream) => Build(TypeBye, stream, 0, static _ => { });

    public static byte[] Head(ulong stream, long totalBytes, long totalChunks) =>
        Build(TypeHead, stream, 16, body =>
        {
            BinaryPrimitives.WriteInt64LittleEndian(body, totalBytes);
            BinaryPrimitives.WriteInt64LittleEndian(body[8..], totalChunks);
        });

    public static byte[] Request(ulong stream, long startChunk, int count) =>
        Build(TypeReq, stream, 10, body =>
        {
            BinaryPrimitives.WriteInt64LittleEndian(body, startChunk);
            BinaryPrimitives.WriteUInt16LittleEndian(body[8..], (ushort)count);
        });

    // Built without the shared BodyWriter helper: spans cannot be captured in the lambda.
    public static byte[] Chunk(ulong stream, long index, ReadOnlySpan<byte> cv, ReadOnlySpan<byte> data)
    {
        byte[] frame = new byte[9 + 8 + 32 + data.Length];
        frame[0] = TypeChunk;
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(1), stream);
        BinaryPrimitives.WriteInt64LittleEndian(frame.AsSpan(9), index);
        cv.CopyTo(frame.AsSpan(17));
        data.CopyTo(frame.AsSpan(49));
        return frame;
    }

    /// <summary>Parsed view over one plaintext blob frame. Copies the chunk payload (and
    /// only it): frames are short-lived, chunks live until applied to the sink.</summary>
    public readonly record struct Frame
    {
        public byte Type { get; init; }
        public ulong Stream { get; init; }
        public long TotalBytes { get; init; }
        public long TotalChunks { get; init; }
        public long StartChunk { get; init; }
        public int Count { get; init; }
        public long Index { get; init; }
        public byte[]? ChunkCv { get; init; }
        public byte[]? ChunkData { get; init; }

        public static bool TryParse(ReadOnlySpan<byte> frame, out Frame f)
        {
            f = default;
            if (frame.Length < 9)
            {
                return false;
            }

            byte type = frame[0];
            ulong stream = BinaryPrimitives.ReadUInt64BigEndian(frame[1..]);
            ReadOnlySpan<byte> body = frame[9..];
            switch (type)
            {
                case TypeHello:
                case TypeBye:
                    if (!body.IsEmpty)
                    {
                        return false;
                    }

                    f = new Frame { Type = type, Stream = stream };
                    return true;
                case TypeHead:
                    if (body.Length != 16)
                    {
                        return false;
                    }

                    f = new Frame
                    {
                        Type = type,
                        Stream = stream,
                        TotalBytes = BinaryPrimitives.ReadInt64LittleEndian(body),
                        TotalChunks = BinaryPrimitives.ReadInt64LittleEndian(body[8..]),
                    };
                    return f.TotalBytes >= 0 && f.TotalChunks >= 0; // (0,0) is the empty blob
                case TypeReq:
                    if (body.Length != 10)
                    {
                        return false;
                    }

                    f = new Frame
                    {
                        Type = type,
                        Stream = stream,
                        StartChunk = BinaryPrimitives.ReadInt64LittleEndian(body),
                        Count = BinaryPrimitives.ReadUInt16LittleEndian(body[8..]),
                    };
                    return f.StartChunk >= 0 && f.Count is >= 1 and <= MaxRequestCount;
                case TypeChunk:
                    if (body.Length is < 41 or > 8 + 32 + MaxChunkData)
                    {
                        return false;
                    }

                    var cv = new byte[32];
                    body.Slice(8, 32).CopyTo(cv);
                    var data = body[40..].ToArray();
                    f = new Frame
                    {
                        Type = type,
                        Stream = stream,
                        Index = BinaryPrimitives.ReadInt64LittleEndian(body),
                        ChunkCv = cv,
                        ChunkData = data,
                    };
                    return f.Index >= 0 && data.Length > 0;
                default:
                    return false;
            }
        }
    }

    /// <summary>Per-direction frame encryption. The key is HKDF-SHA256 over the ticket's
    /// pre-shared key, salted with the content root, so two tickets never share a stream
    /// cipher even when a caller reuses a key. Nonces are (role, 64-bit frame counter); the
    /// counter rides in the clear ahead of the ciphertext and receivers reject replayed or
    /// regressed counters — a replayer can at most duplicate a frame the ARQ layer already
    /// de-duplicates.</summary>
    internal sealed class Cipher
    {
        private const byte DownloaderRole = 0;
        private const byte ProviderRole = 1;
        private readonly KeyParameter _key;

        private Cipher(KeyParameter key) => _key = key;

        public static Cipher? For(byte[]? psk, byte[] root)
        {
            if (psk is null)
            {
                return null;
            }

            var hkdf = new HkdfBytesGenerator(new Sha256Digest());
            hkdf.Init(new HkdfParameters(psk, root, Encoding.UTF8.GetBytes("pinhole-blobs-v1")));
            var key = new byte[32];
            hkdf.GenerateBytes(key, 0, 32);
            return new Cipher(new KeyParameter(key));
        }

        public static byte[] FreshKey() => RandomNumberGenerator.GetBytes(32);

        public byte[] Seal(bool asProvider, ulong counter, ReadOnlySpan<byte> plaintext)
        {
            var aead = new ChaChaPoly();
            Span<byte> nonce = stackalloc byte[12];
            BuildNonce(nonce, asProvider, counter);
            aead.Init(true, new AeadParameters(_key, 128, nonce.ToArray()));
            byte[] input = plaintext.ToArray();
            byte[] output = new byte[8 + input.Length + 16];
            BinaryPrimitives.WriteUInt64LittleEndian(output, counter);
            int n = aead.ProcessBytes(input, 0, input.Length, output, 8);
            aead.DoFinal(output, 8 + n);
            return output;
        }

        public bool TryOpen(bool fromProvider, ReadOnlySpan<byte> wire, ulong maxSeenCounter, out byte[] plaintext, out ulong counter)
        {
            plaintext = Array.Empty<byte>();
            counter = 0;
            if (wire.Length < 8 + 16)
            {
                return false;
            }

            counter = BinaryPrimitives.ReadUInt64LittleEndian(wire);
            if (counter <= maxSeenCounter)
            {
                return false; // replay or regression; the ARQ layer tolerates loss, not lies
            }

            var aead = new ChaChaPoly();
            Span<byte> nonce = stackalloc byte[12];
            BuildNonce(nonce, fromProvider, counter);
            aead.Init(false, new AeadParameters(_key, 128, nonce.ToArray()));
            byte[] input = wire.ToArray();
            byte[] buf = new byte[input.Length];
            try
            {
                int n = aead.ProcessBytes(input, 8, input.Length - 8, buf, 0);
                n += aead.DoFinal(buf, n);
                plaintext = buf[..n];
                return true;
            }
            catch (InvalidCipherTextException)
            {
                return false;
            }
        }

        private static void BuildNonce(Span<byte> nonce, bool provider, ulong counter)
        {
            nonce[0] = provider ? ProviderRole : DownloaderRole;
            BinaryPrimitives.WriteUInt64LittleEndian(nonce[1..], counter);
            nonce[9..].Clear();
        }
    }
}
