using System.Buffers.Binary;
using System.Net;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Pinhole;

public interface IPinholeLookupProvider
{
    Task PublishAsync(ReadOnlyMemory<byte> signedRecord, CancellationToken ct);

    Task<byte[]?> ResolveAsync(ulong peerId, CancellationToken ct);
}

public sealed class AddressRecord
{
    public const int EndpointKeyLength = 32;

    public const int SignatureLength = 64;

    public const int MaxEndpoints = 16;

    public const int MaxRelayedEndpoints = 4;

    private const byte WireVersion1 = 1;
    private const byte WireVersion2 = 2;

    public ulong PeerId { get; init; }

    public byte[] EndpointKey { get; init; } = [];

    public ulong Sequence { get; init; }

    public DateTimeOffset ExpiresAtUtc { get; init; }

    public IReadOnlyList<IPEndPoint> Endpoints { get; init; } = [];

    public IReadOnlyList<IPEndPoint> RelayedEndpoints { get; init; } = [];

    public byte[] Encode()
    {
        if (Endpoints.Count > MaxEndpoints)
        {
            throw new InvalidOperationException($"records carry at most {MaxEndpoints} endpoints");
        }

        if (RelayedEndpoints.Count > MaxRelayedEndpoints)
        {
            throw new InvalidOperationException($"records carry at most {MaxRelayedEndpoints} relayed endpoints");
        }

        if (EndpointKey is not { Length: EndpointKeyLength })
        {
            throw new InvalidOperationException($"endpoint keys are {EndpointKeyLength} bytes");
        }

        var payload = new MemoryStream(32 + (Endpoints.Count + RelayedEndpoints.Count) * 19);
        payload.WriteByte(RelayedEndpoints.Count > 0 ? WireVersion2 : WireVersion1);
        WriteU64(payload, PeerId);
        payload.Write(EndpointKey);
        WriteU64(payload, Sequence);
        WriteU64(payload, (ulong)ExpiresAtUtc.ToUnixTimeSeconds());
        WriteEndpointList(payload, Endpoints);
        if (RelayedEndpoints.Count > 0)
        {
            WriteEndpointList(payload, RelayedEndpoints);
        }

        return payload.ToArray();
    }

    internal byte[] EncodeSigned(RelayIdentity signer)
    {
        byte[] body = Encode();
        byte[] wire = new byte[body.Length + SignatureLength];
        body.CopyTo(wire, 0);
        signer.SignBody(body).CopyTo(wire, body.Length);
        return wire;
    }

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

        if (body[0] is not (WireVersion1 or WireVersion2) || body.Length < MinimumLength)
        {
            return false;
        }

        ulong peerId = BinaryPrimitives.ReadUInt64LittleEndian(body[1..]);
        byte[] key = body[9..41].ToArray();
        ulong sequence = BinaryPrimitives.ReadUInt64LittleEndian(body[41..]);
        long expires = BinaryPrimitives.ReadInt64LittleEndian(body[49..]);
        if (peerId != expectedPeerId || !key.AsSpan().SequenceEqual(expectedEndpointKey))
        {
            return false;
        }

        if (expires <= now.ToUnixTimeSeconds())
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

        int pos = 57;
        int directCount = body[pos++];
        if (!TryReadEndpointList(body, MaxEndpoints, ref pos, directCount, out IPEndPoint[] endpoints))
        {
            return false;
        }

        IPEndPoint[] relayed = [];
        if (body[0] == WireVersion2)
        {
            if (pos >= body.Length)
            {
                return false;
            }

            int relayedCount = body[pos++];
            if (!TryReadEndpointList(body, MaxRelayedEndpoints, ref pos, relayedCount, out relayed))
            {
                return false;
            }
        }

        if (pos != body.Length)
        {
            return false;
        }

        if (expires is < -62135596800 || expires > 253402300799)
        {
            return false;
        }

        record = new AddressRecord
        {
            PeerId = peerId,
            EndpointKey = key,
            Sequence = sequence,
            ExpiresAtUtc = DateTimeOffset.FromUnixTimeSeconds(expires),
            Endpoints = endpoints,
            RelayedEndpoints = relayed,
        };
        return true;
    }

    private const int MinimumLength = 58;

    private static void WriteU64(MemoryStream payload, ulong value)
    {
        Span<byte> tmp = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(tmp, value);
        payload.Write(tmp);
    }

    private static void WriteEndpointList(MemoryStream payload, IReadOnlyList<IPEndPoint> endpoints)
    {
        payload.WriteByte((byte)endpoints.Count);
        foreach (IPEndPoint ep in endpoints)
        {
            byte[] raw = ep.Address.GetAddressBytes();
            payload.WriteByte((byte)raw.Length);
            payload.Write(raw);
            payload.WriteByte((byte)(ep.Port >> 8));
            payload.WriteByte((byte)ep.Port);
        }
    }

    private static bool TryReadEndpointList(ReadOnlySpan<byte> body, int cap, ref int pos, int count, out IPEndPoint[] endpoints)
    {
        endpoints = [];
        if (count > cap)
        {
            return false;
        }

        var parsed = new IPEndPoint[count];
        for (int i = 0; i < count; i++)
        {
            if (pos >= body.Length)
            {
                return false;
            }

            int family = body[pos++];
            if (family is not 4 and not 16 || pos + family + 2 > body.Length)
            {
                return false;
            }

            parsed[i] = new IPEndPoint(
                new IPAddress(body.Slice(pos, family)),
                BinaryPrimitives.ReadUInt16BigEndian(body.Slice(pos + family)));
            pos += family + 2;
        }

        endpoints = parsed;
        return true;
    }
}

internal static class EndpointIdentity
{
    public const string DerivationLabel = "pinhole-endpoint-ed25519-v1";

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
