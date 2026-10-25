using System.Buffers.Binary;
using System.Security.Cryptography;
using Pinhole.Crypto;

namespace Pinhole.Blobs;

internal static class BlobWire
{
    internal const byte TypeHello = 1;
    internal const byte TypeHead = 2;
    internal const byte TypeReq = 3;
    internal const byte TypeChunk = 4;
    internal const byte TypeBye = 5;
    internal const byte TypeWelcome = 6;
    internal const byte TypeProof = 7;
    internal const byte ProtocolVersion = 3;
    internal const byte CurrentVersion = 4;

    public const int MaxChunkData = Blake3.ChunkSize; // 1024
    public const int MaxRequestCount = 64;
    public const int MaxProofSiblings = 64;

    public const int SessionIdLength = 32;
    private const int SealedHeadLength = 8 + 25 + 16;

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

    // Built without the shared BodyWriter helper, like Chunk: spans cannot be captured
    // in the lambda.
    public static byte[] Hello(ulong stream, ReadOnlySpan<byte> sessionId, byte version = ProtocolVersion)
    {
        CheckVersion(version);
        if (sessionId.Length != SessionIdLength)
        {
            throw new ArgumentException("session id must be 32 bytes", nameof(sessionId));
        }

        byte[] frame = new byte[10 + SessionIdLength];
        frame[0] = TypeHello;
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(1), stream);
        frame[9] = version;
        sessionId.CopyTo(frame.AsSpan(10));
        return frame;
    }

    public static byte[] Welcome(ulong stream, ReadOnlySpan<byte> sessionId, ReadOnlySpan<byte> providerNonce,
        ReadOnlySpan<byte> sealedHead, byte version = ProtocolVersion)
    {
        CheckVersion(version);
        if (sessionId.Length != SessionIdLength || providerNonce.Length != SessionIdLength
            || sealedHead.Length != SealedHeadLength)
        {
            throw new ArgumentException("Welcome requires two 32-byte nonces and a sealed Head");
        }

        byte[] frame = new byte[10 + 2 * SessionIdLength + SealedHeadLength];
        frame[0] = TypeWelcome;
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(1), stream);
        frame[9] = version;
        sessionId.CopyTo(frame.AsSpan(10));
        providerNonce.CopyTo(frame.AsSpan(10 + SessionIdLength));
        sealedHead.CopyTo(frame.AsSpan(10 + 2 * SessionIdLength));
        return frame;
    }

    private static void CheckVersion(byte version)
    {
        if (version is not (ProtocolVersion or CurrentVersion))
        {
            throw new ArgumentOutOfRangeException(nameof(version), "blob protocol version must be 3 or 4");
        }
    }

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

    // Sibling CVs run bottom-up: from the verified run's root toward the file root.
    public static byte[] Proof(ulong stream, long runIndex, ReadOnlySpan<byte> siblingCvs32Each)
    {
        if (siblingCvs32Each.Length % SessionIdLength != 0
            || siblingCvs32Each.Length / SessionIdLength > MaxProofSiblings)
        {
            throw new ArgumentException($"sibling CVs are 0..{MaxProofSiblings} 32-byte values", nameof(siblingCvs32Each));
        }

        byte[] frame = new byte[9 + 8 + 1 + siblingCvs32Each.Length];
        frame[0] = TypeProof;
        BinaryPrimitives.WriteUInt64BigEndian(frame.AsSpan(1), stream);
        BinaryPrimitives.WriteInt64LittleEndian(frame.AsSpan(9), runIndex);
        frame[17] = (byte)(siblingCvs32Each.Length / SessionIdLength);
        siblingCvs32Each.CopyTo(frame.AsSpan(18));
        return frame;
    }

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
        public byte[]? SiblingCvs { get; init; } // Proof: count * 32 concatenated sibling CVs

        public byte[]? SessionId { get; init; }
        public byte Version { get; init; }
        public byte[]? ProviderNonce { get; init; }
        public byte[]? SealedHead { get; init; }

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
                    if (body.Length is not (0 or SessionIdLength)
                        && (body.Length != 1 + SessionIdLength || body[0] is not (ProtocolVersion or CurrentVersion)))
                    {
                        return false;
                    }

                    f = new Frame
                    {
                        Type = type,
                        Stream = stream,
                        Version = body.IsEmpty ? (byte)1 : body.Length == SessionIdLength ? (byte)2 : body[0],
                        SessionId = body.IsEmpty ? null : body.Length == SessionIdLength ? body.ToArray() : body[1..].ToArray(),
                    };
                    return true;
                case TypeWelcome:
                    if (body.Length != 1 + 2 * SessionIdLength + SealedHeadLength
                        || body[0] is not (ProtocolVersion or CurrentVersion))
                    {
                        return false;
                    }

                    f = new Frame
                    {
                        Type = type,
                        Stream = stream,
                        Version = body[0],
                        SessionId = body.Slice(1, SessionIdLength).ToArray(),
                        ProviderNonce = body.Slice(1 + SessionIdLength, SessionIdLength).ToArray(),
                        SealedHead = body[(1 + 2 * SessionIdLength)..].ToArray(),
                    };
                    return true;
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
                    return f.TotalBytes >= 0 && f.TotalChunks == f.TotalBytes / Blake3.ChunkSize
                        + (f.TotalBytes % Blake3.ChunkSize == 0 ? 0 : 1); // overflow-safe; only (0,0) is empty
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
                case TypeProof:
                    if (body.Length is < 9 or > 9 + MaxProofSiblings * SessionIdLength)
                    {
                        return false;
                    }

                    int siblings = body[8];
                    long runIndex = BinaryPrimitives.ReadInt64LittleEndian(body);
                    if (runIndex < 0 || siblings > MaxProofSiblings
                        || body.Length != 9 + siblings * SessionIdLength)
                    {
                        return false;
                    }

                    f = new Frame
                    {
                        Type = type,
                        Stream = stream,
                        Index = runIndex,
                        Count = siblings,
                        SiblingCvs = body[9..].ToArray(),
                    };
                    return true;
                default:
                    return false;
            }
        }
    }

    internal sealed class DownloadSession
    {
        private readonly byte[]? _psk;
        private readonly byte[] _root;
        private Cipher? _cipher;
        private byte[]? _providerNonce;
        private ulong _watermark;

        public byte[] SessionId { get; }

        public DownloadSession(byte[]? psk, byte[] root, byte[]? sessionId = null)
        {
            _psk = psk?.ToArray();
            _root = root.ToArray();
            SessionId = (sessionId ?? Cipher.FreshSessionId()).ToArray();
        }

        public byte[] Seal(ulong counter, byte[] plain)
        {
            if (_psk is null)
            {
                return plain;
            }

            return (_cipher ?? throw new InvalidOperationException("the provider has not authenticated a Welcome"))
                .Seal(asProvider: false, counter, plain);
        }

        public bool TryOpen(ReadOnlySpan<byte> payload, ulong stream, out Frame frame)
        {
            frame = default;
            if (_psk is null)
            {
                return Frame.TryParse(payload, out frame) && frame.Stream == stream;
            }

            // Try ordinary ciphertext first after negotiation. A failed open never changes
            // the watermark, so an unsealed Welcome can safely be checked afterwards.
            if (_cipher is not null && _cipher.TryOpen(fromProvider: true, payload, ref _watermark, out byte[] plain))
            {
                return Frame.TryParse(plain, out frame) && frame.Stream == stream;
            }

            if (!Frame.TryParse(payload, out Frame welcome) || welcome.Type != TypeWelcome || welcome.Stream != stream
                || !welcome.SessionId.AsSpan().SequenceEqual(SessionId)
                || (_providerNonce is not null && !_providerNonce.AsSpan().SequenceEqual(welcome.ProviderNonce)))
            {
                Telemetry.FrameRejected("blob", "welcome-unverified");
                return false;
            }

            Cipher candidate = _cipher ?? Cipher.For(_psk, _root, SessionId, welcome.ProviderNonce!, welcome.Version)!;
            ulong candidateWatermark = _watermark;
            if (!candidate.TryOpen(fromProvider: true, welcome.SealedHead!, ref candidateWatermark, out byte[] head)
                || !Frame.TryParse(head, out frame) || frame.Type != TypeHead || frame.Stream != stream)
            {
                Telemetry.FrameRejected("blob", "welcome-unverified");
                return false;
            }

            _cipher = candidate;
            _providerNonce ??= welcome.ProviderNonce;
            _watermark = candidateWatermark;
            WelcomeNonceSeen?.Invoke(SessionId, welcome.ProviderNonce!);
            return true;
        }
    }

    internal static Action<byte[], byte[]>? WelcomeNonceSeen;

    internal sealed class Cipher
    {
        private const byte DownloaderRole = 0;
        private const byte ProviderRole = 1;
        private readonly Aead _aead;

        // Callers seal on one task and open on another (client pump vs run loop), and a
        // BCL AEAD instance is not thread-safe — the per-call BouncyCastle engines were.
        private readonly object _gate = new();

        private Cipher(ReadOnlySpan<byte> key) => _aead = Aead.CreateChaCha20Poly1305(key);

        public static Cipher? For(byte[]? psk, byte[] root, ReadOnlySpan<byte> sessionId, ReadOnlySpan<byte> providerNonce,
            byte version = ProtocolVersion)
        {
            if (psk is null)
            {
                return null;
            }

            if (psk.Length != 32 || root.Length != 32 || sessionId.Length != SessionIdLength
                || providerNonce.Length != SessionIdLength)
            {
                throw new ArgumentException("PSK, root, and each session nonce must be 32 bytes");
            }

            Span<byte> salt = stackalloc byte[root.Length + 2 * SessionIdLength];
            root.AsSpan().CopyTo(salt);
            sessionId.CopyTo(salt[root.Length..]);
            providerNonce.CopyTo(salt[(root.Length + SessionIdLength)..]);
            return Derive(psk, salt, Info(version));
        }

        // The HKDF info string is the only v3/v4 difference; role byte and counters are shared.
        private static ReadOnlySpan<byte> Info(byte version) => version switch
        {
            ProtocolVersion => "pinhole-blobs-v3"u8,
            CurrentVersion => "pinhole-blobs-v4"u8,
            _ => throw new ArgumentOutOfRangeException(nameof(version), "blob protocol version must be 3 or 4"),
        };

        public static LegacyDetector ForLegacy(byte[] psk, byte[] root) => new(psk, root);

        internal static Cipher ForLegacyEmulation(byte[] psk, byte[] root) => Derive(psk, root, "pinhole-blobs-v1"u8);

        // The salt/info inputs are a wire-format promise: they must stay byte-identical
        // to what the BouncyCastle implementation fed HKDF (RFC 5869 is deterministic).
        private static Cipher Derive(ReadOnlySpan<byte> psk, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info)
        {
            Span<byte> key = stackalloc byte[Aead.KeySize];
            HKDF.DeriveKey(HashAlgorithmName.SHA256, psk, key, salt, info);
            return new Cipher(key);
        }

        public static byte[] FreshKey() => RandomNumberGenerator.GetBytes(32);

        public static byte[] FreshSessionId() => RandomNumberGenerator.GetBytes(SessionIdLength);

        public byte[] Seal(bool asProvider, ulong counter, ReadOnlySpan<byte> plaintext)
        {
            Span<byte> nonce = stackalloc byte[Aead.NonceSize];
            BuildNonce(nonce, asProvider, counter);
            byte[] output = new byte[8 + plaintext.Length + Aead.TagSize];
            BinaryPrimitives.WriteUInt64LittleEndian(output, counter);
            lock (_gate)
            {
                _aead.Seal(nonce, [], plaintext, output.AsSpan(8));
            }

            return output;
        }

        public bool TryOpen(bool fromProvider, ReadOnlySpan<byte> wire, ref ulong watermark, out byte[] plaintext)
        {
            plaintext = Array.Empty<byte>();
            if (wire.Length < 8 + Aead.TagSize)
            {
                return false;
            }

            ulong candidate = BinaryPrimitives.ReadUInt64LittleEndian(wire);
            if (candidate <= watermark)
            {
                return false; // replay or regression; the ARQ layer tolerates loss, not lies
            }

            Span<byte> nonce = stackalloc byte[Aead.NonceSize];
            BuildNonce(nonce, fromProvider, candidate);
            byte[] plain = new byte[wire.Length - 8 - Aead.TagSize];
            lock (_gate)
            {
                if (!_aead.TryOpen(nonce, [], wire[8..], plain))
                {
                    return false; // forged or corrupted in flight: the watermark does not move
                }
            }

            plaintext = plain;
            watermark = candidate; // committed only after the tag verifies
            return true;
        }

        private static void BuildNonce(Span<byte> nonce, bool provider, ulong counter)
        {
            nonce[0] = provider ? ProviderRole : DownloaderRole;
            BinaryPrimitives.WriteUInt64LittleEndian(nonce[1..], counter);
            nonce[9..].Clear();
        }

        internal sealed class LegacyDetector
        {
            private readonly Cipher _inner;

            internal LegacyDetector(byte[] psk, byte[] root) => _inner = Derive(psk, root, "pinhole-blobs-v1"u8);

            public bool TryOpen(bool fromProvider, ReadOnlySpan<byte> wire, ref ulong watermark, out byte[] plaintext) =>
                _inner.TryOpen(fromProvider, wire, ref watermark, out plaintext);
        }
    }

    // ------------------------------------------------------------------ send-path transition tolerance

    internal static readonly TimeSpan RideOutBudget = TimeSpan.FromSeconds(30);

    private static readonly TimeSpan RideOutPace = TimeSpan.FromMilliseconds(50);

    internal static async ValueTask SendRidingOutPathlessnessAsync(Pinhole.PinholeConnection conn, byte[] wire, CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                conn.Send(wire);
                return;
            }
            catch (InvalidOperationException) when (conn.State != Pinhole.PinholeConnectionState.Closed && sw.Elapsed < RideOutBudget)
            {
                await Task.Delay(RideOutPace, ct).ConfigureAwait(false);
            }
        }
    }
}
