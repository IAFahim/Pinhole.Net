using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Pinhole.Crypto;

namespace Pinhole;

public enum PinholeEncryption
{
    Required = 0,

    Optional = 1,

    Disabled = 2,
}

internal static class CryptoWire
{
    public const int HeaderLength = 9;
    public const int TokenLength = 4;
    public const int EphemeralLength = 32;
    public const int StaticKeyLength = 32;
    public const int ConfirmLength = 16;
    public const int CounterLength = 8;
    public const int TagLength = 16;
    public const int SealedOverhead = CounterLength + TagLength;

    public const int PuncLegacyBody = TokenLength;
    public const int PuncCryptoBody = TokenLength + EphemeralLength + StaticKeyLength;
    public const int PackLegacyBody = 2 * TokenLength;
    public const int PackCryptoBody = 2 * TokenLength + EphemeralLength + StaticKeyLength + ConfirmLength;
    public const int HsckBody = TokenLength + ConfirmLength;

    public const byte HandshakeV4Marker = 0x04;
    public const int Mac1Length = 16;
    public const int Mac1ExtLength = 1 + Mac1Length;
    public const int PuncCryptoBodyV4 = PuncCryptoBody + Mac1ExtLength;
    public const int PackCryptoBodyV4 = PackCryptoBody + Mac1ExtLength;

    public const byte Mac2Marker = 0x05;
    public const int Mac2Length = 16;
    public const int Mac2ExtLength = 1 + Mac2Length;
    public const int PuncCryptoBodyV4Mac2 = PuncCryptoBodyV4 + Mac2ExtLength;

    public const int CookieLength = 16;
    public const int CookieBody = TokenLength + 1 + CookieLength;
    public const int CookieFrameLength = HeaderLength + CookieBody;

    public const int KemBody = TokenLength + HybridKem.CiphertextLength;

    public static void WriteMac1Ext(Span<byte> frame, ReadOnlySpan<byte> responderStaticPub)
    {
        frame[^Mac1ExtLength] = HandshakeV4Marker;
        Span<byte> digest = stackalloc byte[Blake3.DigestLength];
        Blake3.HashKeyed(responderStaticPub, frame[..^Mac1Length], digest);
        digest[..Mac1Length].CopyTo(frame[^Mac1Length..]);
    }

    public static bool VerifyMac1(ReadOnlySpan<byte> frame, ReadOnlySpan<byte> responderStaticPub)
    {
        if (frame.Length < HeaderLength + Mac1ExtLength || frame[^Mac1ExtLength] != HandshakeV4Marker)
        {
            return false;
        }

        Span<byte> digest = stackalloc byte[Blake3.DigestLength];
        Blake3.HashKeyed(responderStaticPub, frame[..^Mac1Length], digest);
        return CryptographicOperations.FixedTimeEquals(frame[^Mac1Length..], digest[..Mac1Length]);
    }

    public static bool HasMac2(ReadOnlySpan<byte> frame) =>
        frame.Length >= HeaderLength + Mac1ExtLength + Mac2ExtLength && frame[^Mac2ExtLength] == Mac2Marker;

    public static ReadOnlySpan<byte> Mac1View(ReadOnlySpan<byte> frame) =>
        HasMac2(frame) ? frame[..^Mac2ExtLength] : frame;

    public static void WriteMac2Ext(Span<byte> frame, ReadOnlySpan<byte> cookie)
    {
        frame[^Mac2ExtLength] = Mac2Marker;
        Span<byte> digest = stackalloc byte[Blake3.DigestLength];
        Blake3.HashKeyed(CookieKey(stackalloc byte[CookieKeyLength], cookie), frame[..^Mac2Length], digest);
        digest[..Mac2Length].CopyTo(frame[^Mac2Length..]);
    }

    public static bool VerifyMac2(ReadOnlySpan<byte> frame, ReadOnlySpan<byte> cookie)
    {
        if (frame.Length < HeaderLength + Mac1ExtLength + Mac2ExtLength || frame[^Mac2ExtLength] != Mac2Marker)
        {
            return false;
        }

        Span<byte> digest = stackalloc byte[Blake3.DigestLength];
        Blake3.HashKeyed(CookieKey(stackalloc byte[CookieKeyLength], cookie), frame[..^Mac2Length], digest);
        return CryptographicOperations.FixedTimeEquals(frame[^Mac2Length..], digest[..Mac2Length]);
    }

    private static Span<byte> CookieKey(Span<byte> destination, ReadOnlySpan<byte> cookie)
    {
        cookie.CopyTo(destination);
        destination[CookieLength..].Clear();
        return destination;
    }

    public const int CookieKeyLength = 32;

    public static void CookieFor(Span<byte> destination, ReadOnlySpan<byte> rotatingSecret, ReadOnlySpan<byte> sourceAddress)
    {
        Span<byte> digest = stackalloc byte[Blake3.DigestLength];
        Blake3.HashKeyed(rotatingSecret, sourceAddress, digest);
        digest[..CookieLength].CopyTo(destination);
    }

    public const string KnockMac1Label = "pinhole-knock-mac1-v1";

    internal static ReadOnlySpan<byte> KnockMac1LabelBytes => "pinhole-knock-mac1-v1"u8;

    public static void KnockMac1Key(Span<byte> destination, ReadOnlySpan<byte> responderStaticPub, ReadOnlySpan<byte> knock)
    {
        Span<byte> material = stackalloc byte[StaticKeyLength + ConnectionString.MaxKnockLength];
        responderStaticPub.CopyTo(material);
        knock.CopyTo(material[StaticKeyLength..]);
        Blake3.HashDeriveKey(KnockMac1LabelBytes, material[..(StaticKeyLength + knock.Length)], destination);
    }
}

internal sealed class NodeIdentity
{
    public const int KeyLength = 32;

    private readonly byte[] _private;
    public byte[] PublicKey { get; }

    public NodeIdentity(byte[]? seed = null)
    {
        _private = (seed ?? RandomNumberGenerator.GetBytes(KeyLength)).ToArray();
        if (_private.Length != KeyLength)
        {
            throw new ArgumentException($"identity seed must be {KeyLength} bytes", nameof(seed));
        }

        PublicKey = new X25519PrivateKeyParameters(_private, 0).GeneratePublicKey().GetEncoded();
    }

    internal byte[] ExportPrivateSeed() => (byte[])_private.Clone();

    public static (byte[] Private, byte[] Public) NewEphemeral()
    {
        byte[] priv = RandomNumberGenerator.GetBytes(KeyLength);
        return (priv, new X25519PrivateKeyParameters(priv, 0).GeneratePublicKey().GetEncoded());
    }

    internal static byte[] X25519Agree(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublic)
    {
        var agreement = new X25519Agreement();
        agreement.Init(new X25519PrivateKeyParameters(privateKey.ToArray(), 0));
        byte[] shared = new byte[KeyLength];
        try
        {
            agreement.CalculateAgreement(new X25519PublicKeyParameters(peerPublic.ToArray(), 0), shared, 0);
        }
        catch (InvalidOperationException ex)
        {

            throw new CryptographicException("peer public key is a low-order point", ex);
        }

        return shared.AsSpan().IndexOfAnyExcept((byte)0) >= 0
            ? shared
            : throw new CryptographicException("peer public key is a low-order point");
    }
}

internal sealed class SessionKeys
{
    public required byte[] TranscriptHash { get; init; }
    public required byte[] LoToHiKey { get; init; }
    public required byte[] HiToLoKey { get; init; }
    public required byte[] LoToHiSalt { get; init; }
    public required byte[] HiToLoSalt { get; init; }
    public required byte[] LoConfirm { get; init; }
    public required byte[] HiConfirm { get; init; }
}

internal static class KeySchedule
{
    public const string TranscriptLabel = "pinhole-hs1";
    public const string Info = "pinhole-session-v1";
    public const string RekeyInfo = "pinhole-rekey-v1";

    public const string KnockPskLabel = "pinhole-knock-psk-v1";

    private static ReadOnlySpan<byte> KnockPskLabelBytes => "pinhole-knock-psk-v1"u8;

    public const string MlKemPskLabel = "pinhole-mlkem768-psk-v1";

    private static ReadOnlySpan<byte> MlKemPskLabelBytes => "pinhole-mlkem768-psk-v1"u8;

    public static SessionKeys Derive(
        ulong myPeerId,
        ReadOnlySpan<byte> myEphPrivate,
        ReadOnlySpan<byte> myStaticPrivate,
        ulong peerPeerId,
        ReadOnlySpan<byte> peerEphPublic,
        ReadOnlySpan<byte> peerStaticPublic,
        ReadOnlySpan<byte> knock = default,
        ReadOnlySpan<byte> mlkemSecret = default)
    {
        bool iAmLo = myPeerId < peerPeerId;
        byte[] ee = NodeIdentity.X25519Agree(myEphPrivate, peerEphPublic);

        byte[] se = iAmLo
            ? NodeIdentity.X25519Agree(myStaticPrivate, peerEphPublic)
            : NodeIdentity.X25519Agree(myEphPrivate, peerStaticPublic);
        byte[] es = iAmLo
            ? NodeIdentity.X25519Agree(myEphPrivate, peerStaticPublic)
            : NodeIdentity.X25519Agree(myStaticPrivate, peerEphPublic);

        var ikm = new byte[3 * NodeIdentity.KeyLength
            + (knock.IsEmpty ? 0 : NodeIdentity.KeyLength)
            + (mlkemSecret.IsEmpty ? 0 : NodeIdentity.KeyLength)];
        ee.CopyTo(ikm, 0);
        se.CopyTo(ikm, NodeIdentity.KeyLength);
        es.CopyTo(ikm, 2 * NodeIdentity.KeyLength);
        int tail = 3 * NodeIdentity.KeyLength;
        if (!knock.IsEmpty)
        {
            Span<byte> psk = stackalloc byte[NodeIdentity.KeyLength];
            Blake3.HashDeriveKey(KnockPskLabelBytes, knock, psk);
            psk.CopyTo(ikm.AsSpan(tail));
            tail += NodeIdentity.KeyLength;
        }

        if (!mlkemSecret.IsEmpty)
        {
            Span<byte> psk = stackalloc byte[NodeIdentity.KeyLength];
            Blake3.HashDeriveKey(MlKemPskLabelBytes, mlkemSecret, psk);
            psk.CopyTo(ikm.AsSpan(tail));
        }

        byte[] myEphPublic = new X25519PrivateKeyParameters(myEphPrivate.ToArray(), 0).GeneratePublicKey().GetEncoded();
        byte[] myStaticPublic = new X25519PrivateKeyParameters(myStaticPrivate.ToArray(), 0).GeneratePublicKey().GetEncoded();
        byte[] th = TranscriptHash(
            iAmLo ? myPeerId : peerPeerId,
            iAmLo ? peerPeerId : myPeerId,
            iAmLo ? myEphPublic : peerEphPublic.ToArray(),
            iAmLo ? myStaticPublic : peerStaticPublic.ToArray(),
            iAmLo ? peerEphPublic.ToArray() : myEphPublic,
            iAmLo ? peerStaticPublic.ToArray() : myStaticPublic);

        byte[] okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 136, th, System.Text.Encoding.ASCII.GetBytes(Info));
        return new SessionKeys
        {
            TranscriptHash = th,

            LoToHiKey = okm[..32],
            HiToLoKey = okm[32..64],
            LoToHiSalt = okm[128..132],
            HiToLoSalt = okm[132..136],
            LoConfirm = ConfirmMac(okm[64..96], th),
            HiConfirm = ConfirmMac(okm[96..128], th),
        };
    }

    public static byte[] TranscriptHash(ulong loPeerId, ulong hiPeerId, ReadOnlySpan<byte> loEph, ReadOnlySpan<byte> loStatic, ReadOnlySpan<byte> hiEph, ReadOnlySpan<byte> hiStatic)
    {
        var buf = new byte[TranscriptLabel.Length + 8 + 8 + 4 * NodeIdentity.KeyLength];
        int pos = System.Text.Encoding.ASCII.GetBytes(TranscriptLabel, buf);
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(pos), loPeerId);
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(pos + 8), hiPeerId);
        loEph.CopyTo(buf.AsSpan(pos + 16));
        loStatic.CopyTo(buf.AsSpan(pos + 16 + NodeIdentity.KeyLength));
        hiEph.CopyTo(buf.AsSpan(pos + 16 + 2 * NodeIdentity.KeyLength));
        hiStatic.CopyTo(buf.AsSpan(pos + 16 + 3 * NodeIdentity.KeyLength));
        return SHA256.HashData(buf);
    }

    public static byte[] Rekey(ReadOnlySpan<byte> currentKey, ReadOnlySpan<byte> transcriptHash)
    {
        byte[] next = GC.AllocateUninitializedArray<byte>(32);
        HKDF.DeriveKey(HashAlgorithmName.SHA256, currentKey, next, transcriptHash, System.Text.Encoding.ASCII.GetBytes(RekeyInfo));
        return next;
    }

    private static byte[] ConfirmMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> transcript) =>
        HMACSHA256.HashData(key, transcript)[..CryptoWire.ConfirmLength];
}

internal sealed class FrameSealer : IDisposable
{
    private const int DefaultEpochFrames = 1 << 28;

    private readonly byte[] _transcriptHash;
    private readonly byte[] _nonceSalt;
    private readonly int _epochFrames;
    private readonly object _gate = new();

    private byte[] _key;
    private AesGcm? _aes;
    private AesGcm? _prevAes;
    private uint _epoch;
    private bool _disposed;

    private ulong _nextCounter = 1;
    private ReplayWindow _recvWindow;

    public FrameSealer(SessionKeys keys, bool iAmLo, bool sending, int epochFrames = DefaultEpochFrames)
    {
        _transcriptHash = keys.TranscriptHash;
        _epochFrames = epochFrames;
        bool loToHi = sending == iAmLo;
        _nonceSalt = loToHi ? keys.LoToHiSalt : keys.HiToLoSalt;
        _key = loToHi ? keys.LoToHiKey : keys.HiToLoKey;
    }

    public int Seal(Span<byte> destination, ReadOnlySpan<byte> headerAndToken, ReadOnlySpan<byte> plaintext)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(FrameSealer));
            }

            ulong counter = _nextCounter++;
            uint epoch = (uint)((counter - 1) / (ulong)_epochFrames);
            if (_aes is null)
            {
                _aes = new AesGcm(_key, CryptoWire.TagLength);
            }
            else if (epoch != _epoch)
            {

                while (_epoch < epoch)
                {
                    _key = KeySchedule.Rekey(_key, _transcriptHash);
                    _epoch++;
                }

                _aes.Dispose();
                _aes = new AesGcm(_key, CryptoWire.TagLength);
            }

            Span<byte> nonce = stackalloc byte[12];
            _nonceSalt.CopyTo(nonce);
            BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], counter);
            BinaryPrimitives.WriteUInt64LittleEndian(destination, counter);
            Span<byte> ct = destination.Slice(CryptoWire.CounterLength, plaintext.Length);
            Span<byte> tag = destination.Slice(CryptoWire.CounterLength + plaintext.Length, CryptoWire.TagLength);
            Span<byte> aad = stackalloc byte[CryptoWire.HeaderLength + CryptoWire.TokenLength + CryptoWire.CounterLength];
            headerAndToken.CopyTo(aad);
            BinaryPrimitives.WriteUInt64LittleEndian(aad[(CryptoWire.HeaderLength + CryptoWire.TokenLength)..], counter);
            _aes.Encrypt(nonce, plaintext, ct, tag, aad);
            return CryptoWire.CounterLength + plaintext.Length + CryptoWire.TagLength;
        }
    }

    public bool Open(ReadOnlySpan<byte> frame, Span<byte> plaintext, out int plaintextLength)
    {
        plaintextLength = 0;
        ReadOnlySpan<byte> sealedBody = frame[(CryptoWire.HeaderLength + CryptoWire.TokenLength)..];
        if (sealedBody.Length < CryptoWire.CounterLength + CryptoWire.TagLength)
        {
            return false;
        }

        ulong counter = BinaryPrimitives.ReadUInt64LittleEndian(sealedBody);
        if (counter == 0)
        {
            return false;
        }

        uint epoch = (uint)((counter - 1) / (ulong)_epochFrames);
        lock (_gate)
        {
            if (_disposed)
            {
                return false;
            }

            if (!_recvWindow.Admits(counter))
            {
                return false;
            }

            AesGcm aes;
            byte[]? candidateKey = null;
            if (epoch == _epoch)
            {
                _aes ??= new AesGcm(_key, CryptoWire.TagLength);
                aes = _aes;
            }
            else if (epoch == _epoch + 1)
            {
                candidateKey = KeySchedule.Rekey(_key, _transcriptHash);
                aes = new AesGcm(candidateKey, CryptoWire.TagLength);
            }
            else if (epoch + 1 == _epoch && _prevAes is not null)
            {
                aes = _prevAes;
            }
            else
            {
                return false;
            }

            ReadOnlySpan<byte> ciphertext = sealedBody[CryptoWire.CounterLength..];
            int plainLen = ciphertext.Length - CryptoWire.TagLength;
            if (plaintext.Length < plainLen)
            {
                if (candidateKey is not null)
                {
                    aes.Dispose();
                }

                return false;
            }

            Span<byte> nonce = stackalloc byte[12];
            _nonceSalt.CopyTo(nonce);
            BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], counter);
            bool opened;
            try
            {
                aes.Decrypt(nonce, ciphertext[..^CryptoWire.TagLength], ciphertext[^CryptoWire.TagLength..], plaintext[..plainLen],
                    frame[..(CryptoWire.HeaderLength + CryptoWire.TokenLength + CryptoWire.CounterLength)]);
                opened = true;
            }
            catch (CryptographicException)
            {
                opened = false;
            }

            if (!opened)
            {
                if (candidateKey is not null)
                {
                    aes.Dispose();
                }

                return false;
            }

            _recvWindow = _recvWindow.Mark(counter);
            if (candidateKey is not null)
            {
                _prevAes?.Dispose();
                _prevAes = _aes;
                _aes = aes;
                _key = candidateKey;
                _epoch = epoch;
            }

            plaintextLength = plainLen;
            return true;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _aes?.Dispose();
            _prevAes?.Dispose();
        }
    }
}

internal sealed class ConnectionCrypto
{
    private readonly byte[] _ephPrivate;
    private readonly byte[] _staticPrivate;
    private readonly byte[]? _knock;
    private byte[]? _mlkemSecret;

    public required ulong MyPeerId { get; init; }
    public required ulong PeerPeerId { get; init; }
    public byte[] MyEphPublic { get; }
    public byte[] MyStaticPublic { get; }

    public byte[]? MlKemCiphertext { get; }
    public bool HybridPending => _mlkemSecret is not null;
    public bool HybridLatched { get; private set; }

    public byte[]? PeerEphPublic { get; private set; }
    public byte[]? PeerStaticPublic { get; private set; }
    public SessionKeys? Keys { get; private set; }
    public FrameSealer? Send { get; private set; }
    public FrameSealer? Recv { get; private set; }
    public bool PeerConfirmed { get; private set; }
    public long Rejected;

    [System.Diagnostics.CodeAnalysis.SetsRequiredMembers]
    private ConnectionCrypto(byte[] ephPrivate, byte[] ephPublic, byte[] staticPrivate, byte[] staticPublic,
        ulong myPeerId, ulong peerPeerId, byte[]? knock, byte[]? mlkemSecret, byte[]? mlkemCiphertext)
    {
        _ephPrivate = ephPrivate;
        MyEphPublic = ephPublic;
        _staticPrivate = staticPrivate;
        MyStaticPublic = staticPublic;
        MyPeerId = myPeerId;
        PeerPeerId = peerPeerId;
        _knock = knock;
        _mlkemSecret = mlkemSecret;
        MlKemCiphertext = mlkemCiphertext;
    }

    public static ConnectionCrypto New(NodeIdentity identity, ulong myPeerId, ulong peerPeerId,
        byte[]? knock = null, ReadOnlySpan<byte> mlKemPublicKey = default)
    {
        (byte[] ephPrivate, byte[] ephPublic) = NodeIdentity.NewEphemeral();
        byte[]? mlkemSecret = null;
        byte[]? mlkemCiphertext = null;
        if (!mlKemPublicKey.IsEmpty)
        {
            if (!HybridKem.IsSupported || mlKemPublicKey.Length != HybridKem.PublicKeyLength)
            {
                throw new CryptographicException("the ticket's ML-KEM public key cannot be used for encapsulation");
            }

            (byte[] ciphertext, byte[] sharedSecret)? encapsulated = HybridKem.Encapsulate(mlKemPublicKey);
            if (encapsulated is not { } pair)
            {
                throw new CryptographicException("ML-KEM encapsulation failed");
            }

            mlkemCiphertext = pair.ciphertext;
            mlkemSecret = pair.sharedSecret;
        }

        return new ConnectionCrypto(ephPrivate, ephPublic, identity.ExportPrivateSeed(), identity.PublicKey,
            myPeerId, peerPeerId, knock?.ToArray(), mlkemSecret, mlkemCiphertext);
    }

    public bool Established => Keys is not null;

    public void AbandonHybridHold()
    {
        if (Keys is null)
        {
            _mlkemSecret = null;
        }
    }

    private void LatchKeys(SessionKeys keys)
    {
        Keys = keys;
        bool iAmLo = MyPeerId < PeerPeerId;
        Send?.Dispose();
        Recv?.Dispose();
        Send = new FrameSealer(keys, iAmLo, sending: true);
        Recv = new FrameSealer(keys, iAmLo, sending: false);
    }

    public bool TryPeerKeys(ReadOnlySpan<byte> eph, ReadOnlySpan<byte> stat)
    {
        if (Keys is not null)
        {
            return PeerEphPublic.AsSpan().SequenceEqual(eph) && PeerStaticPublic.AsSpan().SequenceEqual(stat);
        }

        if (PeerEphPublic is not null)
        {
            return false;
        }

        try
        {
            SessionKeys keys = KeySchedule.Derive(MyPeerId, _ephPrivate, _staticPrivate, PeerPeerId, eph, stat, _knock, _mlkemSecret);
            PeerEphPublic = eph.ToArray();
            PeerStaticPublic = stat.ToArray();
            LatchKeys(keys);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public bool TrySupersedeUnconfirmed(ReadOnlySpan<byte> eph, ReadOnlySpan<byte> stat, ReadOnlySpan<byte> confirm,
        bool allowUnexposedIncoming = false)
    {

        if (PeerConfirmed && !allowUnexposedIncoming || Keys is null)
        {
            return false;
        }

        try
        {
            SessionKeys trial = KeySchedule.Derive(MyPeerId, _ephPrivate, _staticPrivate, PeerPeerId, eph, stat, _knock, _mlkemSecret);
            ReadOnlySpan<byte> expected = MyPeerId < PeerPeerId ? trial.HiConfirm : trial.LoConfirm;
            if (!CryptographicOperations.FixedTimeEquals(confirm, expected))
            {
                return false;
            }

            PeerEphPublic = eph.ToArray();
            PeerStaticPublic = stat.ToArray();
            LatchKeys(trial);
            Interlocked.Increment(ref SupersededLatches);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public bool ClassicalConfirmMatches(ReadOnlySpan<byte> eph, ReadOnlySpan<byte> stat, ReadOnlySpan<byte> confirm)
    {
        if (_mlkemSecret is null || Keys is null)
        {
            return false;
        }

        try
        {
            SessionKeys classical = KeySchedule.Derive(MyPeerId, _ephPrivate, _staticPrivate, PeerPeerId, eph, stat, _knock);
            ReadOnlySpan<byte> expected = MyPeerId < PeerPeerId ? classical.HiConfirm : classical.LoConfirm;
            return CryptographicOperations.FixedTimeEquals(confirm, expected);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public bool TryUpgradeHybrid(ReadOnlySpan<byte> mlkemSecret)
    {
        if (Keys is null || PeerEphPublic is null || PeerStaticPublic is null || PeerConfirmed || HybridLatched)
        {
            return false;
        }

        try
        {
            SessionKeys hybrid = KeySchedule.Derive(MyPeerId, _ephPrivate, _staticPrivate, PeerPeerId,
                PeerEphPublic, PeerStaticPublic, _knock, mlkemSecret);
            LatchKeys(hybrid);
            HybridLatched = true;
            Interlocked.Increment(ref SupersededLatches);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public long SupersededLatches;

    public byte[] MyConfirm() => MyPeerId < PeerPeerId ? Keys!.LoConfirm : Keys!.HiConfirm;

    public byte[]? ExpectedPeerConfirm() => Keys is null ? null : MyPeerId < PeerPeerId ? Keys.HiConfirm : Keys.LoConfirm;

    public bool VerifyPeerConfirm(ReadOnlySpan<byte> confirm) =>
        ExpectedPeerConfirm() is { } expected && confirm.SequenceEqual(expected);

    public void MarkPeerConfirmed() => PeerConfirmed = true;

    public void CountRejected()
    {
        Interlocked.Increment(ref Rejected);
        Telemetry.FrameRejected("session", "unverified");
    }

    private long _keyRejectCaptured;
    private volatile string _keyRejectDetail = "";

    public string KeyRejectSummary => _keyRejectDetail;

    public string MyEphPrefix => HexPrefix(MyEphPublic);

    public void NoteKeyReject(ReadOnlySpan<byte> arrivingEph)
    {
        if (Interlocked.Exchange(ref _keyRejectCaptured, 1) == 1) return;
        _keyRejectDetail = $"[{(Keys is not null ? "derived" : "underived")}"
            + $" stored-eph={HexPrefix(PeerEphPublic)}"
            + $" arriving-eph={HexPrefix(arrivingEph)}"
            + $" my-eph={HexPrefix(MyEphPublic)}]";
    }

    private static string HexPrefix(ReadOnlySpan<byte> key) =>
        key.IsEmpty ? "-" : Convert.ToHexString(key[..4]).ToLowerInvariant();
}
