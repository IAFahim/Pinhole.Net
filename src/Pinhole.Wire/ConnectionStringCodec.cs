using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Pinhole.Wire;

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

public readonly record struct CandidateData(
    WireCandidateKind Kind,
    IPEndPoint? Address,
    IPEndPoint? RelayServer,
    string? Username,
    string? Credential,
    string? RelayUrl,
    byte[]? RelayKey);

public readonly record struct ConnectionStringData(
    ulong PeerId,
    WireNatHint NatHint,
    CandidateData[]? Candidates,
    byte[]? StaticKey,
    byte[]? EndpointKey,
    byte[]? Knock = null)
{
    public byte Version => Knock is not null ? ConnectionStringCodec.BodyVersion4
        : EndpointKey is not null ? ConnectionStringCodec.BodyVersion3
        : StaticKey is not null ? ConnectionStringCodec.BodyVersion2
        : ConnectionStringCodec.BodyVersion1;
}

public static class ConnectionStringCodec
{
    public const string Scheme = "pinhole1";

    public const int MaxCandidates = 32;

    public const int StaticKeyLength = 32;

    public const int EndpointKeyLength = 32;

    public const int RelayKeyLength = 32;

    public const int MaxKnockLength = 64;

    public const int MaxShortTextBytes = 64;

    public const int HeaderLength = 12;

    public const int MaxBodyLength = HeaderLength + MaxCandidates * MaxCandidateLength
        + StaticKeyLength + EndpointKeyLength + 1 + MaxKnockLength;

    public const int MaxEncodedLength = MaxBodyLength;

    public const int MaxStringLength = 9 + 4 * (MaxBodyLength / 3) + (MaxBodyLength % 3 == 0 ? 0 : MaxBodyLength % 3 + 1);

    internal const byte BodyVersion1 = 1;

    internal const byte BodyVersion2 = 2;

    internal const byte BodyVersion3 = 3;

    internal const byte BodyVersion4 = 4;

    private const byte FlagsHasStaticKey = 1;

    private const byte FlagsHasEndpointKey = 2;

    private const byte FlagsHasKnock = 4;

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
        if (version is not (BodyVersion1 or BodyVersion2 or BodyVersion3 or BodyVersion4))
        {
            return false;
        }

        bool hasStaticKey = version >= BodyVersion2;
        bool hasEndpointKey = version == BodyVersion3;
        bool hasKnock = version == BodyVersion4;
        byte wantedFlags = (byte)((hasStaticKey ? FlagsHasStaticKey : 0) | (hasEndpointKey ? FlagsHasEndpointKey : 0)
            | (hasKnock ? FlagsHasKnock : 0));

        if (body[1] != wantedFlags && (version != BodyVersion4
                || (body[1] & ~FlagsHasEndpointKey) != (FlagsHasStaticKey | FlagsHasKnock)))
        {
            return false;
        }

        if (version == BodyVersion4)
        {
            hasEndpointKey = (body[1] & FlagsHasEndpointKey) != 0;
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

                if (body[starts[i]..ends[i]].SequenceEqual(body[starts[j]..ends[j]]))
                {
                    return false;
                }
            }

            candidates[i] = candidate;
        }

        byte[]? staticKey = null;
        byte[]? endpointKey = null;
        byte[]? knock = null;
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
        else if (version == BodyVersion4)
        {

            int keyTail = StaticKeyLength + (hasEndpointKey ? EndpointKeyLength : 0);
            if (remaining < keyTail + 2)
            {
                return false;
            }

            int knockLength = body[pos + keyTail];
            if (knockLength is < 1 or > MaxKnockLength || remaining != keyTail + 1 + knockLength)
            {
                return false;
            }

            staticKey = body.Slice(pos, StaticKeyLength).ToArray();
            if (hasEndpointKey)
            {
                endpointKey = body.Slice(pos + StaticKeyLength, EndpointKeyLength).ToArray();
            }

            knock = body.Slice(pos + keyTail + 1, knockLength).ToArray();
        }
        else if (remaining != 0)
        {
            return false;
        }

        value = new ConnectionStringData(peerId, (WireNatHint)hint, candidates, staticKey, endpointKey, knock);
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
        byte[]? knock = value.Knock;
        destination[0] = (byte)(knock is not null ? BodyVersion4
            : endpointKey is not null ? BodyVersion3 : staticKey is not null ? BodyVersion2 : BodyVersion1);
        destination[1] = (byte)((staticKey is not null ? FlagsHasStaticKey : 0)
            | (endpointKey is not null ? FlagsHasEndpointKey : 0) | (knock is not null ? FlagsHasKnock : 0));
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
            pos += EndpointKeyLength;
        }

        if (knock is not null)
        {
            destination[pos++] = (byte)knock.Length;
            knock.AsSpan().CopyTo(destination.Slice(pos, knock.Length));
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

        int total = Scheme.Length + 1 + 4 * (bodyLength / 3) + (bodyLength % 3 == 0 ? 0 : bodyLength % 3 + 1);
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

        int full = data.Length / 3 * 4 + (data.Length % 3 == 0 ? 0 : data.Length % 3 + 1);
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

        byte[]? knock = value.Knock;
        if (knock is not null && (knock.Length == 0 || knock.Length > MaxKnockLength))
        {
            throw new ArgumentOutOfRangeException(nameof(value), $"knocks are 1..{MaxKnockLength} bytes");
        }

        if (knock is not null && staticKey is null)
        {
            throw new ArgumentException("a knock requires the static key it is published with", nameof(value));
        }

        int length = HeaderLength + (staticKey is not null ? StaticKeyLength : 0)
            + (endpointKey is not null ? EndpointKeyLength : 0) + (knock is not null ? 1 + knock.Length : 0);
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
