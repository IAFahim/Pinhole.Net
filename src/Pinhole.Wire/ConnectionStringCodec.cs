using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Pinhole.Wire;

// Wire-level mirror of the values Pinhole.ConnectionString carries. The enums
// re-declare the wire codes (they cannot be shared with the Pinhole assembly
// without taking a reference); the numeric values are the format.
public enum WireCandidateKind : byte
{
    Direct = 1,

    Reflexive = 2,

    Relay = 3,

    IrohRelay = 4,

    DerpRelay = 5,
}

public enum WireNatHint : byte
{
    Unknown = 0,

    Cone = 1,

    Symmetric = 2,
}

// One decoded candidate. Field ownership follows the wire: Address is always
// present, Relay* fields only for the kinds that carry them. Extraneous fields
// are ignored by Write, exactly like the reference CandidateCodec.
public readonly record struct CandidateData(
    WireCandidateKind Kind,
    IPEndPoint? Address,
    IPEndPoint? RelayServer,
    string? Username,
    string? Credential,
    string? RelayUrl,
    byte[]? RelayKey);

// The decoded connection-string body. A successful TryRead materializes the
// arrays, endpoints and strings this struct owns; rejects and the string layer
// below allocate nothing. Version is derived from key presence, never stored.
public readonly record struct ConnectionStringData(
    ulong PeerId,
    WireNatHint NatHint,
    CandidateData[]? Candidates,
    byte[]? StaticKey,
    byte[]? EndpointKey)
{
    public byte Version => EndpointKey is not null ? ConnectionStringCodec.BodyVersion3
        : StaticKey is not null ? ConnectionStringCodec.BodyVersion2
        : ConnectionStringCodec.BodyVersion1;
}

// Canonical codec for the "pinhole1:<base64url>" connection string:
//   body[0]  version (1 = bare, 2 = +static key, 3 = +static+endpoint keys)
//   body[1]  flags: exactly the key-presence bits for that version
//   body[2]  peer id, u64 LE
//   body[10] NAT hint (0..2)
//   body[11] candidate count (1..32; zero is not canonical)
//   candidates, then the v2/v3 key tail(s). No trailing bytes.
// Candidate: endpoint (family byte 4|16, raw address bytes, u16 BE port),
// kind byte, then per-kind extras (relay: server endpoint + two short ASCII
// texts; https relays: short ASCII URL + 32-byte key).
// Canonicality enforced on read beyond the reference parser: candidate lists
// are non-empty and duplicate-free, short texts are strict 7-bit ASCII, and the
// base64url layer accepts only the unpadded, zero-trailing-bit form. TryRead
// returns false on any malformed input and never throws on wire bytes; Write
// throws ArgumentException-family errors for programmer mistakes only.
public static class ConnectionStringCodec
{
    public const string Scheme = "pinhole1";

    public const int MaxCandidates = 32;

    public const int StaticKeyLength = 32;

    public const int EndpointKeyLength = 32;

    public const int RelayKeyLength = 32;

    public const int MaxShortTextBytes = 64;

    public const int HeaderLength = 12;

    public const int MaxBodyLength = HeaderLength + MaxCandidates * MaxCandidateLength + StaticKeyLength + EndpointKeyLength;

    public const int MaxEncodedLength = MaxBodyLength;

    // "pinhole1:" (9 chars) plus one base64 character per 3 payload bytes, unpadded
    public const int MaxStringLength = 9 + 4 * (MaxBodyLength / 3);

    internal const byte BodyVersion1 = 1;

    internal const byte BodyVersion2 = 2;

    internal const byte BodyVersion3 = 3;

    private const byte FlagsHasStaticKey = 1;

    private const byte FlagsHasEndpointKey = 2;

    private const int AddressLengthV4 = 4;

    private const int AddressLengthV6 = 16;

    private const int MaxEndpointLength = 1 + AddressLengthV6 + 2;

    private const int MaxCandidateLength = MaxEndpointLength + 1 + MaxEndpointLength + 2 * (1 + MaxShortTextBytes);

    private const int MinBodyLength = 13;

    public static bool TryRead(ReadOnlySpan<byte> body, out ConnectionStringData value, out int consumed)
    {
        value = default;
        consumed = 0;
        if (body.Length < MinBodyLength)
        {
            return false;
        }

        byte version = body[0];
        if (version is not (BodyVersion1 or BodyVersion2 or BodyVersion3))
        {
            return false;
        }

        bool hasStaticKey = version >= BodyVersion2;
        bool hasEndpointKey = version == BodyVersion3;
        byte wantedFlags = (byte)((hasStaticKey ? FlagsHasStaticKey : 0) | (hasEndpointKey ? FlagsHasEndpointKey : 0));
        if (body[1] != wantedFlags)
        {
            return false;
        }

        if (!WirePrimitives.TryReadU64Le(body.Slice(2, 8), out ulong peerId))
        {
            return false;
        }

        byte hint = body[10];
        if (hint > (byte)WireNatHint.Symmetric)
        {
            return false;
        }

        int count = body[11];
        if (count is < 1 or > MaxCandidates)
        {
            return false;
        }

        var candidates = new CandidateData[count];
        Span<int> starts = stackalloc int[MaxCandidates];
        Span<int> ends = stackalloc int[MaxCandidates];
        int pos = HeaderLength;
        for (int i = 0; i < count; i++)
        {
            starts[i] = pos;
            if (!TryReadCandidate(body, ref pos, out CandidateData candidate))
            {
                return false;
            }

            ends[i] = pos;
            for (int j = 0; j < i; j++)
            {
                // duplicate candidates are not canonical: the encoded bytes are compared directly
                if (body[starts[i]..ends[i]].SequenceEqual(body[starts[j]..ends[j]]))
                {
                    return false;
                }
            }

            candidates[i] = candidate;
        }

        byte[]? staticKey = null;
        byte[]? endpointKey = null;
        int remaining = body.Length - pos;
        if (version == BodyVersion2)
        {
            if (remaining != StaticKeyLength)
            {
                return false;
            }

            staticKey = body[^StaticKeyLength..].ToArray();
        }
        else if (version == BodyVersion3)
        {
            if (remaining != StaticKeyLength + EndpointKeyLength)
            {
                return false;
            }

            staticKey = body.Slice(body.Length - StaticKeyLength - EndpointKeyLength, StaticKeyLength).ToArray();
            endpointKey = body[^EndpointKeyLength..].ToArray();
        }
        else if (remaining != 0)
        {
            return false;
        }

        value = new ConnectionStringData(peerId, (WireNatHint)hint, candidates, staticKey, endpointKey);
        consumed = body.Length;
        return true;
    }

    public static int Write(in ConnectionStringData value, Span<byte> destination)
    {
        int needed = ValidateAndMeasure(value);
        if (destination.Length < needed)
        {
            ThrowTooSmall();
        }

        byte[]? staticKey = value.StaticKey;
        byte[]? endpointKey = value.EndpointKey;
        destination[0] = (byte)(endpointKey is not null ? BodyVersion3 : staticKey is not null ? BodyVersion2 : BodyVersion1);
        destination[1] = (byte)((staticKey is not null ? FlagsHasStaticKey : 0) | (endpointKey is not null ? FlagsHasEndpointKey : 0));
        WirePrimitives.WriteU64Le(destination.Slice(2, 8), value.PeerId);
        destination[10] = (byte)value.NatHint;
        destination[11] = (byte)value.Candidates!.Length;

        int pos = HeaderLength;
        foreach (CandidateData candidate in value.Candidates)
        {
            WriteCandidate(destination, ref pos, candidate);
        }

        if (staticKey is not null)
        {
            staticKey.AsSpan().CopyTo(destination.Slice(pos, StaticKeyLength));
            pos += StaticKeyLength;
        }

        if (endpointKey is not null)
        {
            endpointKey.AsSpan().CopyTo(destination.Slice(pos, EndpointKeyLength));
        }

        return needed;
    }

    public static bool TryWrite(in ConnectionStringData value, Span<byte> destination, out int written)
    {
        written = 0;
        int needed;
        try
        {
            needed = ValidateAndMeasure(value);
        }
        catch (ArgumentException)
        {
            // value errors are programmer errors surfaced by Write; TryWrite just declines them
            return false;
        }

        if (destination.Length < needed)
        {
            return false;
        }

        written = Write(value, destination);
        return true;
    }

    public static string Encode(in ConnectionStringData value)
    {
        Span<byte> body = stackalloc byte[MaxBodyLength];
        int bodyLength = Write(value, body);
        Span<char> chars = stackalloc char[MaxStringLength];
        Scheme.AsSpan().CopyTo(chars);
        chars[Scheme.Length] = ':';
        if (!TryEncodeBase64Url(body[..bodyLength], chars[(Scheme.Length + 1)..], out int encoded))
        {
            ThrowUnreachable();
        }

        return new string(chars[..(Scheme.Length + 1 + encoded)]);
    }

    public static bool TryEncodeText(in ConnectionStringData value, Span<char> destination, out int charsWritten)
    {
        charsWritten = 0;
        int needed;
        try
        {
            needed = ValidateAndMeasure(value);
        }
        catch (ArgumentException)
        {
            return false;
        }

        Span<byte> body = stackalloc byte[MaxBodyLength];
        int bodyLength = Write(value, body);
        int total = Scheme.Length + 1 + 4 * ((bodyLength + 2) / 3);
        if (destination.Length < total)
        {
            return false;
        }

        Scheme.AsSpan().CopyTo(destination);
        destination[Scheme.Length] = ':';
        if (!TryEncodeBase64Url(body[..bodyLength], destination[(Scheme.Length + 1)..], out int encoded))
        {
            ThrowUnreachable();
        }

        charsWritten = Scheme.Length + 1 + encoded;
        return true;
    }

    public static bool TryParse(ReadOnlySpan<char> text, out ConnectionStringData value)
    {
        value = default;
        if (text.Length < Scheme.Length + 1 + 2 || !text.StartsWith(Scheme) || text[Scheme.Length] != ':')
        {
            return false;
        }

        ReadOnlySpan<char> payload = text[(Scheme.Length + 1)..];
        Span<byte> body = stackalloc byte[MaxBodyLength];
        if (!TryDecodeBase64Url(payload, body, out int bodyLength))
        {
            return false;
        }

        return TryRead(body[..bodyLength], out value, out int consumed) && consumed == bodyLength;
    }

    // Canonical base64url (RFC 4648 section 5): unpadded URL-safe alphabet,
    // strict charset, and the unused trailing bits of a short final quantum
    // must be zero. The reference decoder also accepts '=' padding and
    // non-zero trailing bits; those forms are not canonical and are rejected.
    public static bool TryDecodeBase64Url(ReadOnlySpan<char> text, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        int length = text.Length;
        if (length % 4 == 1)
        {
            return false;
        }

        int full = length / 4 * 3 + (length % 4 == 2 ? 1 : length % 4 == 3 ? 2 : 0);
        if (destination.Length < full)
        {
            return false;
        }

        int pos = 0;
        int written = 0;
        while (pos + 4 <= length)
        {
            int v0 = CharValue(text[pos]);
            int v1 = CharValue(text[pos + 1]);
            int v2 = CharValue(text[pos + 2]);
            int v3 = CharValue(text[pos + 3]);
            if ((v0 | v1 | v2 | v3) < 0)
            {
                return false;
            }

            destination[written++] = (byte)((v0 << 2) | (v1 >> 4));
            destination[written++] = (byte)((v1 << 4) | (v2 >> 2));
            destination[written++] = (byte)((v2 << 6) | v3);
            pos += 4;
        }

        int remainder = length - pos;
        if (remainder == 2)
        {
            int v0 = CharValue(text[pos]);
            int v1 = CharValue(text[pos + 1]);
            if (v0 < 0 || v1 < 0)
            {
                return false;
            }

            if ((v1 & 0x0F) != 0)
            {
                return false;
            }

            destination[written++] = (byte)((v0 << 2) | (v1 >> 4));
        }
        else if (remainder == 3)
        {
            int v0 = CharValue(text[pos]);
            int v1 = CharValue(text[pos + 1]);
            int v2 = CharValue(text[pos + 2]);
            if (v0 < 0 || v1 < 0 || v2 < 0)
            {
                return false;
            }

            if ((v2 & 0x03) != 0)
            {
                return false;
            }

            destination[written++] = (byte)((v0 << 2) | (v1 >> 4));
            destination[written++] = (byte)((v1 << 4) | (v2 >> 2));
        }

        bytesWritten = written;
        return true;
    }

    public static bool TryEncodeBase64Url(ReadOnlySpan<byte> data, Span<char> destination, out int charsWritten)
    {
        charsWritten = 0;
        int full = data.Length / 3 * 4 + (data.Length % 3 == 0 ? 0 : 4);
        if (destination.Length < full)
        {
            return false;
        }

        ReadOnlySpan<byte> alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"u8;
        int pos = 0;
        int written = 0;
        while (pos + 3 <= data.Length)
        {
            uint n = (uint)((data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]);
            destination[written++] = (char)alphabet[(int)(n >> 18) & 63];
            destination[written++] = (char)alphabet[(int)(n >> 12) & 63];
            destination[written++] = (char)alphabet[(int)(n >> 6) & 63];
            destination[written++] = (char)alphabet[(int)n & 63];
            pos += 3;
        }

        int remainder = data.Length - pos;
        if (remainder == 1)
        {
            destination[written++] = (char)alphabet[data[pos] >> 2];
            destination[written++] = (char)alphabet[(data[pos] & 0x03) << 4];
        }
        else if (remainder == 2)
        {
            destination[written++] = (char)alphabet[data[pos] >> 2];
            destination[written++] = (char)alphabet[((data[pos] & 0x03) << 4) | (data[pos + 1] >> 4)];
            destination[written++] = (char)alphabet[(data[pos + 1] & 0x0F) << 2];
        }

        charsWritten = written;
        return true;
    }

    private static bool TryReadCandidate(ReadOnlySpan<byte> body, ref int pos, out CandidateData candidate)
    {
        candidate = default;
        if (!TryReadEndpoint(body, ref pos, out IPEndPoint? address))
        {
            return false;
        }

        if (pos >= body.Length)
        {
            return false;
        }

        byte kindByte = body[pos++];
        if (kindByte is < (byte)WireCandidateKind.Direct or > (byte)WireCandidateKind.DerpRelay)
        {
            return false;
        }

        var kind = (WireCandidateKind)kindByte;
        IPEndPoint? server = null;
        string? username = null;
        string? credential = null;
        string? relayUrl = null;
        byte[]? relayKey = null;
        if (kind == WireCandidateKind.Relay)
        {
            if (!TryReadEndpoint(body, ref pos, out server)
                || !TryReadShortText(body, ref pos, out username)
                || !TryReadShortText(body, ref pos, out credential))
            {
                return false;
            }
        }
        else if (kind is WireCandidateKind.IrohRelay or WireCandidateKind.DerpRelay)
        {
            if (!TryReadShortText(body, ref pos, out relayUrl))
            {
                return false;
            }

            if (!Uri.TryCreate(relayUrl, UriKind.Absolute, out Uri? url) || !IsValidRelayUrl(url))
            {
                return false;
            }

            if (pos + RelayKeyLength > body.Length)
            {
                return false;
            }

            relayKey = body.Slice(pos, RelayKeyLength).ToArray();
            pos += RelayKeyLength;
        }

        candidate = new CandidateData(kind, address, server, username, credential, relayUrl, relayKey);
        return true;
    }

    private static bool TryReadEndpoint(ReadOnlySpan<byte> body, ref int pos, out IPEndPoint? endpoint)
    {
        endpoint = null;
        if (pos >= body.Length)
        {
            return false;
        }

        int family = body[pos++];
        if (family is not (AddressLengthV4 or AddressLengthV6))
        {
            return false;
        }

        if (pos + family + 2 > body.Length)
        {
            return false;
        }

        var address = new IPAddress(body.Slice(pos, family));
        WirePrimitives.TryReadU16Be(body.Slice(pos + family, 2), out ushort port);
        pos += family + 2;
        endpoint = new IPEndPoint(address, port);
        return true;
    }

    private static bool TryReadShortText(ReadOnlySpan<byte> body, ref int pos, out string? text)
    {
        text = null;
        if (pos >= body.Length)
        {
            return false;
        }

        int length = body[pos++];
        if (length > MaxShortTextBytes || pos + length > body.Length)
        {
            return false;
        }

        // the reference Encoding.ASCII decode silently maps >= 0x80 to '?';
        // high bytes are not canonical and are rejected instead
        foreach (byte c in body.Slice(pos, length))
        {
            if (c > 0x7F)
            {
                return false;
            }
        }

        text = Encoding.ASCII.GetString(body.Slice(pos, length));
        pos += length;
        return true;
    }

    private static bool IsValidRelayUrl(Uri url) => url.IsAbsoluteUri
        && (url.Scheme == "https" || (url.Scheme == "http" && url.IsLoopback))
        && url.UserInfo.Length == 0 && url.Query.Length == 0 && url.Fragment.Length == 0;

    private static void WriteCandidate(Span<byte> destination, ref int pos, in CandidateData candidate)
    {
        // fields are non-null and in range: ValidateAndMeasure ran first
        WriteEndpoint(destination, ref pos, candidate.Address!);
        destination[pos++] = (byte)candidate.Kind;
        if (candidate.Kind == WireCandidateKind.Relay)
        {
            WriteEndpoint(destination, ref pos, candidate.RelayServer!);
            WriteShortText(destination, ref pos, candidate.Username!);
            WriteShortText(destination, ref pos, candidate.Credential!);
        }
        else if (candidate.Kind is WireCandidateKind.IrohRelay or WireCandidateKind.DerpRelay)
        {
            WriteShortText(destination, ref pos, candidate.RelayUrl!);
            candidate.RelayKey!.CopyTo(destination.Slice(pos, RelayKeyLength));
            pos += RelayKeyLength;
        }
    }

    private static void WriteEndpoint(Span<byte> destination, ref int pos, IPEndPoint endpoint)
    {
        int family = endpoint.Address.AddressFamily switch
        {
            AddressFamily.InterNetwork => AddressLengthV4,
            AddressFamily.InterNetworkV6 => AddressLengthV6,
            _ => ThrowUnknownAddressFamily(),
        };
        destination[pos++] = (byte)family;
        endpoint.Address.TryWriteBytes(destination.Slice(pos, family), out int written);
        pos += written;
        WirePrimitives.WriteU16Be(destination.Slice(pos, 2), (ushort)endpoint.Port);
        pos += 2;
    }

    private static void WriteShortText(Span<byte> destination, ref int pos, string value)
    {
        // value is validated 7-bit ASCII of length <= 64, so byte count == char count
        destination[pos++] = (byte)value.Length;
        Encoding.ASCII.GetBytes(value, destination.Slice(pos, value.Length));
        pos += value.Length;
    }

    private static int ValidateAndMeasure(in ConnectionStringData value)
    {
        var candidates = value.Candidates ?? throw new ArgumentNullException(nameof(value), "candidates are required");
        if (candidates.Length is < 1 or > MaxCandidates)
        {
            throw new ArgumentOutOfRangeException(nameof(value), $"1..{MaxCandidates} candidates fit a connection string");
        }

        if (value.NatHint is not (WireNatHint.Unknown or WireNatHint.Cone or WireNatHint.Symmetric))
        {
            throw new ArgumentOutOfRangeException(nameof(value), "unknown NAT hint");
        }

        byte[]? staticKey = value.StaticKey;
        byte[]? endpointKey = value.EndpointKey;
        if (staticKey is not null && staticKey.Length != StaticKeyLength)
        {
            throw new ArgumentOutOfRangeException(nameof(value), $"static keys are {StaticKeyLength} bytes");
        }

        if (endpointKey is not null && endpointKey.Length != EndpointKeyLength)
        {
            throw new ArgumentOutOfRangeException(nameof(value), $"endpoint keys are {EndpointKeyLength} bytes");
        }

        if (endpointKey is not null && staticKey is null)
        {
            throw new ArgumentException("an endpoint key requires the static key it is published with", nameof(value));
        }

        int length = HeaderLength + (staticKey is not null ? StaticKeyLength : 0) + (endpointKey is not null ? EndpointKeyLength : 0);
        for (int i = 0; i < candidates.Length; i++)
        {
            length += MeasureCandidate(candidates[i]);
            for (int j = 0; j < i; j++)
            {
                if (CandidatesEqual(candidates[i], candidates[j]))
                {
                    throw new ArgumentException($"candidate {i} duplicates candidate {j}", nameof(value));
                }
            }
        }

        return length;
    }

    private static int MeasureCandidate(in CandidateData candidate)
    {
        int length = MeasureEndpoint(candidate.Address) + 1;
        switch (candidate.Kind)
        {
            case WireCandidateKind.Direct:
            case WireCandidateKind.Reflexive:
                break;
            case WireCandidateKind.Relay:
                if (candidate.RelayServer is null || candidate.Username is null || candidate.Credential is null)
                {
                    throw new ArgumentException("relay candidates require RelayServer, Username and Credential", nameof(candidate));
                }

                length += MeasureEndpoint(candidate.RelayServer) + ShortTextBytes(candidate.Username) + ShortTextBytes(candidate.Credential);
                break;
            case WireCandidateKind.IrohRelay:
            case WireCandidateKind.DerpRelay:
                if (candidate.RelayUrl is null || candidate.RelayKey is not { Length: RelayKeyLength }
                    || !Uri.TryCreate(candidate.RelayUrl, UriKind.Absolute, out Uri? url) || !IsValidRelayUrl(url))
                {
                    throw new ArgumentException("HTTPS relay candidates require a safe relay URL and a 32-byte public key", nameof(candidate));
                }

                length += ShortTextBytes(candidate.RelayUrl) + RelayKeyLength;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(candidate), "unknown candidate kind");
        }

        return length;
    }

    private static int MeasureEndpoint(IPEndPoint? endpoint)
    {
        if (endpoint is null)
        {
            throw new ArgumentNullException(nameof(endpoint), "candidate addresses are required");
        }

        return endpoint.Address.AddressFamily switch
        {
            AddressFamily.InterNetwork => 1 + AddressLengthV4 + 2,
            AddressFamily.InterNetworkV6 => 1 + AddressLengthV6 + 2,
            _ => ThrowUnknownAddressFamily(),
        };
    }

    private static int ShortTextBytes(string value)
    {
        if (value.Length > MaxShortTextBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "candidate strings are limited to 64 ASCII bytes");
        }

        foreach (char c in value)
        {
            if (c > 0x7F)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "candidate strings are limited to 64 ASCII bytes");
            }
        }

        return 1 + value.Length;
    }

    private static bool CandidatesEqual(in CandidateData x, in CandidateData y) =>
        x.Kind == y.Kind
        && EndpointsEqual(x.Address, y.Address)
        && x.Kind switch
        {
            WireCandidateKind.Relay => EndpointsEqual(x.RelayServer, y.RelayServer) && x.Username == y.Username && x.Credential == y.Credential,
            WireCandidateKind.IrohRelay or WireCandidateKind.DerpRelay => x.RelayUrl == y.RelayUrl && BytesEqual(x.RelayKey, y.RelayKey),
            _ => true,
        };

    private static bool EndpointsEqual(IPEndPoint? x, IPEndPoint? y)
    {
        if (x is null || y is null)
        {
            return x is null && y is null;
        }

        return x.Port == y.Port
            && x.Address.AddressFamily == y.Address.AddressFamily
            && x.Address.GetAddressBytes().AsSpan().SequenceEqual(y.Address.GetAddressBytes());
    }

    private static bool BytesEqual(byte[]? x, byte[]? y) =>
        x is null || y is null ? x is null && y is null : x.AsSpan().SequenceEqual(y);

    private static int CharValue(char c) => c switch
    {
        >= 'A' and <= 'Z' => c - 'A',
        >= 'a' and <= 'z' => c - 'a' + 26,
        >= '0' and <= '9' => c - '0' + 52,
        '-' => 62,
        '_' => 63,
        _ => -1,
    };

    private static int ThrowUnknownAddressFamily() => throw new ArgumentException("candidate addresses must be IPv4 or IPv6");

    private static void ThrowTooSmall() => throw new ArgumentException("destination span too small");

    private static void ThrowUnreachable() => throw new InvalidOperationException("unreachable: destination was sized from the measured body");
}
