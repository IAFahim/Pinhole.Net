using System.Buffers.Binary;
using System.Net;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Pinhole;

/// <summary>An application-supplied address-lookup provider, following iroh's address-lookup
/// design: the node signs its current reachability and pushes it to one or more providers;
/// a dialer whose cached addresses are dead asks the same providers for the peer's current
/// record and verifies it against the key pinned in its connection string. Implement this
/// to front an existing directory you trust or operate — signed DNS, pkarr, or an
/// iroh-style lookup service — over whatever transport they speak; the built-in
/// <c>Pinhole.Rendezvous</c> UDP introducer (see <see cref="PinholeOptions.RendezvousEndpoints"/>)
/// is one such provider. Both operations are best-effort: providers are availability
/// dependencies, never authorities — nothing a provider returns is trusted before its
/// Ed25519 signature verifies against the pinned endpoint key.</summary>
public interface IPinholeLookupProvider
{
    /// <summary>Delivers the node's current signed record (opaque bytes from
    /// <see cref="AddressRecord"/> encoding). Fire-and-fortry semantics: returning normally
    /// means "accepted for serving", throwing means "unreachable" and costs the publisher a
    /// backoff interval, never a failure.</summary>
    Task PublishAsync(ReadOnlyMemory<byte> signedRecord, CancellationToken ct);

    /// <summary>Returns the peer's current signed record, or null when this provider does
    /// not know the peer. The bytes are untrusted until verified by the caller.</summary>
    Task<byte[]?> ResolveAsync(ulong peerId, CancellationToken ct);
}

/// <summary>A peer's signed statement of where it is reachable right now: direct and
/// server-reflexive endpoints, bound to its Ed25519 endpoint key with a monotonic sequence
/// and a freshness expiry. Records carry public keys and addresses only — never session
/// keys, pre-shared secrets, or TURN credentials — so a public directory learns reachability
/// metadata but holds nothing that could impersonate the peer or decrypt its traffic.
/// Verification is always against an externally pinned key (<see cref="TryParseVerified"/>);
/// parsing without one exists only for transport, not for trust.</summary>
public sealed class AddressRecord
{
    /// <summary>Ed25519 public keys are 32 bytes.</summary>
    public const int EndpointKeyLength = 32;

    /// <summary>Ed25519 signatures are 64 bytes.</summary>
    public const int SignatureLength = 64;

    /// <summary>The most endpoints one record may carry.</summary>
    public const int MaxEndpoints = 16;

    private const byte WireVersion = 1;

    /// <summary>The publisher's peer ID — a locator hint. A record whose ID matches the
    /// dialer's expectation but whose key does not is discarded: IDs never authorize peers.</summary>
    public ulong PeerId { get; init; }

    /// <summary>The publisher's Ed25519 endpoint public key. Must equal the key the verifier
    /// pinned out-of-band (from a v3 connection string) or the record is rejected.</summary>
    public byte[] EndpointKey { get; init; } = [];

    /// <summary>Monotonic publish sequence (unix-time milliseconds at signing). A record at
    /// or below the highest sequence already adopted for the peer is a replay or rollback.</summary>
    public ulong Sequence { get; init; }

    /// <summary>When the record stops being fresh. Verification fails at or after this
    /// instant, so a stale record can only deny availability, never redirect.</summary>
    public DateTimeOffset ExpiresAtUtc { get; init; }

    /// <summary>Direct and server-reflexive endpoints the publisher is reachable on.</summary>
    public IReadOnlyList<IPEndPoint> Endpoints { get; init; } = [];

    /// <summary>Canonical unsigned body: everything but the signature, in a fixed layout so
    /// both endpoints sign and verify identical bytes.</summary>
    public byte[] Encode()
    {
        if (Endpoints.Count > MaxEndpoints)
        {
            throw new InvalidOperationException($"records carry at most {MaxEndpoints} endpoints");
        }

        if (EndpointKey is not { Length: EndpointKeyLength })
        {
            throw new InvalidOperationException($"endpoint keys are {EndpointKeyLength} bytes");
        }

        var payload = new MemoryStream(32 + Endpoints.Count * 19);
        payload.WriteByte(WireVersion);
        WriteU64(payload, PeerId);
        payload.Write(EndpointKey);
        WriteU64(payload, Sequence);
        WriteU64(payload, (ulong)ExpiresAtUtc.ToUnixTimeSeconds());
        payload.WriteByte((byte)Endpoints.Count);
        foreach (IPEndPoint ep in Endpoints)
        {
            byte[] raw = ep.Address.GetAddressBytes();
            payload.WriteByte((byte)raw.Length);
            payload.Write(raw);
            payload.WriteByte((byte)(ep.Port >> 8));
            payload.WriteByte((byte)ep.Port);
        }

        return payload.ToArray();
    }

    /// <summary>Body plus its Ed25519 signature — the bytes <see cref="IPinholeLookupProvider"/>
    /// transports. Signing is the publisher's job (the node's endpoint identity), so this
    /// stays internal to the library.</summary>
    internal byte[] EncodeSigned(RelayIdentity signer)
    {
        byte[] body = Encode();
        byte[] wire = new byte[body.Length + SignatureLength];
        body.CopyTo(wire, 0);
        signer.SignBody(body).CopyTo(wire, body.Length);
        return wire;
    }

    /// <summary>Strict verified parse: the record must carry exactly the expected peer ID and
    /// endpoint key, be unexpired, and bear a valid Ed25519 signature over its canonical
    /// body. Anything else — wrong key, forged signature, tampered fields, stale freshness,
    /// malformed layout — returns false. This is the only way library code adopts endpoints
    /// from a lookup provider.</summary>
    public static bool TryParseVerified(
        ReadOnlySpan<byte> wire,
        ulong expectedPeerId,
        ReadOnlySpan<byte> expectedEndpointKey,
        DateTimeOffset now,
        out AddressRecord? record)
    {
        record = null;
        if (expectedEndpointKey.Length != EndpointKeyLength || wire.Length < MinimumLength + SignatureLength)
        {
            return false;
        }

        ReadOnlySpan<byte> body = wire[..^SignatureLength];
        ReadOnlySpan<byte> signature = wire[^SignatureLength..];

        // Field reads are bounds-checked against the body; a truncated record fails here.
        if (body[0] != WireVersion)
        {
            return false;
        }

        ulong peerId = BinaryPrimitives.ReadUInt64LittleEndian(body[1..]);
        byte[] key = body[9..41].ToArray();
        ulong sequence = BinaryPrimitives.ReadUInt64LittleEndian(body[41..]);
        long expires = BinaryPrimitives.ReadInt64LittleEndian(body[49..]);
        int count = body[57];
        if (count > MaxEndpoints || peerId != expectedPeerId || !key.AsSpan().SequenceEqual(expectedEndpointKey))
        {
            return false;
        }

        if (DateTimeOffset.FromUnixTimeSeconds(expires) <= now)
        {
            return false;
        }

        var verifier = new Ed25519Signer();
        verifier.Init(false, new Ed25519PublicKeyParameters(key.ToArray(), 0));
        verifier.BlockUpdate(body.ToArray(), 0, body.Length);
        if (!verifier.VerifySignature(signature.ToArray()))
        {
            return false;
        }

        int pos = 58;
        var endpoints = new IPEndPoint[count];
        for (int i = 0; i < count; i++)
        {
            int family = body[pos++];
            if (family is not 4 and not 16 || pos + family + 2 > body.Length)
            {
                return false;
            }

            endpoints[i] = new IPEndPoint(
                new IPAddress(body.Slice(pos, family)),
                BinaryPrimitives.ReadUInt16BigEndian(body.Slice(pos + family)));
            pos += family + 2;
        }

        if (pos != body.Length)
        {
            return false; // trailing bytes mean the signature covered something we didn't parse
        }

        record = new AddressRecord
        {
            PeerId = peerId,
            EndpointKey = key,
            Sequence = sequence,
            ExpiresAtUtc = DateTimeOffset.FromUnixTimeSeconds(expires),
            Endpoints = endpoints,
        };
        return true;
    }

    private const int MinimumLength = 58; // version + id + key + sequence + expiry + count

    private static void WriteU64(MemoryStream payload, ulong value)
    {
        Span<byte> tmp = stackalloc byte[8];
        BitConverter.TryWriteBytes(tmp, value);
        payload.Write(tmp);
    }
}

/// <summary>The node's Ed25519 endpoint identity derivation: the X25519 session-identity
/// seed is also the root from which the endpoint (and relay-handshake) key is expanded, so
/// one persisted 32-byte seed restores the full key set — X25519 static key, Ed25519
/// endpoint key, and the peer ID derived from the latter.</summary>
internal static class EndpointIdentity
{
    public const string DerivationLabel = "pinhole-endpoint-ed25519-v1";

    /// <summary>HKDF expansion of the identity seed into the Ed25519 endpoint seed — a
    /// distinct domain from the X25519 static key (which uses the seed directly), so neither
    /// key can ever be computed from the other's public half.</summary>
    public static byte[]? DeriveEndpointSeed(byte[]? identitySeed) =>
        identitySeed is null
            ? null
            : System.Security.Cryptography.HKDF.DeriveKey(
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                identitySeed,
                32,
                salt: null,
                info: Encoding.ASCII.GetBytes(DerivationLabel));
}
