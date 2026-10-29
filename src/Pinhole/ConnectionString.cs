using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;

namespace Pinhole;

public enum CandidateKind : byte
{
    Direct = 1,

    Reflexive = 2,

    Relay = 3,

    IrohRelay = 4,

    DerpRelay = 5,
}

public sealed record PinholeCandidate(
    CandidateKind Kind,
    IPEndPoint Address,
    IPEndPoint? RelayServer = null,
    string? Username = null,
    string? Credential = null,
    Uri? RelayUrl = null,
    byte[]? RelayKey = null);

public enum NatHint : byte
{
    Unknown = 0,

    Cone = 1,

    Symmetric = 2,
}

public sealed class ConnectionString
{
    public const string Scheme = "pinhole1";

    public const int MaxCandidates = 32;

    public const int MaxEncodedLength = 8192;

    // The optional per-string secret (the knock): 1..64 raw bytes, format-level. A knock
    // rides the string only when the node is configured with one, and never on v1..v3.
    public const int MaxKnockLength = 64;

    public ulong PeerId { get; }

    public NatHint NatHint { get; }

    public byte[]? StaticKey { get; }

    public byte[]? EndpointKey { get; }

    public byte[]? Knock { get; }

    public IReadOnlyList<PinholeCandidate> Candidates { get; }

    public ConnectionString(ulong peerId, IReadOnlyList<PinholeCandidate> candidates, NatHint natHint = NatHint.Unknown,
        byte[]? staticKey = null, byte[]? endpointKey = null, byte[]? knock = null)
    {
        if (candidates.Count > MaxCandidates)
        {
            throw new ArgumentOutOfRangeException(nameof(candidates), $"at most {MaxCandidates} candidates fit a connection string");
        }

        if (staticKey is not null && staticKey.Length != NodeIdentity.KeyLength)
        {
            throw new ArgumentOutOfRangeException(nameof(staticKey), $"static keys are {NodeIdentity.KeyLength} bytes");
        }

        if (endpointKey is not null && endpointKey.Length != AddressRecord.EndpointKeyLength)
        {
            throw new ArgumentOutOfRangeException(nameof(endpointKey), $"endpoint keys are {AddressRecord.EndpointKeyLength} bytes");
        }

        if (endpointKey is not null && staticKey is null)
        {
            throw new ArgumentOutOfRangeException(nameof(endpointKey), "an endpoint key requires the static key it is published with");
        }

        if (knock is not null && (knock.Length == 0 || knock.Length > MaxKnockLength))
        {
            throw new ArgumentOutOfRangeException(nameof(knock), $"knocks are 1..{MaxKnockLength} bytes");
        }

        if (knock is not null && staticKey is null)
        {
            throw new ArgumentOutOfRangeException(nameof(knock), "a knock requires the static key it is published with");
        }

        PeerId = peerId;
        NatHint = natHint;
        StaticKey = staticKey;
        EndpointKey = endpointKey;
        Knock = knock;
        Candidates = candidates;
    }

    public override string ToString()
    {
        bool keyed = StaticKey is not null;
        bool epKeyed = EndpointKey is not null;
        bool knocked = Knock is not null;
        var payload = new MemoryStream(64 + Candidates.Count * 32 + (keyed ? NodeIdentity.KeyLength : 0)
            + (epKeyed ? AddressRecord.EndpointKeyLength : 0) + (knocked ? 1 + Knock!.Length : 0));
        byte version = knocked ? Version4 : epKeyed ? Version3 : keyed ? Version2 : Version1;
        payload.WriteByte(version);
        payload.WriteByte((byte)((keyed ? FlagsHasStaticKey : 0) | (epKeyed ? FlagsHasEndpointKey : 0) | (knocked ? FlagsHasKnock : 0)));
        WriteU64(payload, PeerId);
        payload.WriteByte((byte)NatHint);
        payload.WriteByte((byte)Candidates.Count);
        foreach (PinholeCandidate candidate in Candidates)
        {
            CandidateCodec.Write(payload, candidate);
        }

        if (keyed)
        {
            payload.Write(StaticKey!);
        }

        if (epKeyed)
        {
            payload.Write(EndpointKey!);
        }

        if (knocked)
        {
            payload.WriteByte((byte)Knock!.Length);
            payload.Write(Knock);
        }

        return Scheme + ":" + Base64Url.Encode(payload.GetBuffer().AsSpan(0, (int)payload.Length));
    }

    public static bool TryParse(string text, [NotNullWhen(true)] out ConnectionString? cs)
    {
        try
        {
            cs = Parse(text);
            return true;
        }
        catch (FormatException)
        {
            cs = null;
            return false;
        }
    }

    public static ConnectionString Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (text.Length > MaxEncodedLength)
        {
            throw new FormatException($"connection string exceeds {MaxEncodedLength} characters");
        }

        int colon = text.IndexOf(':');
        if (colon <= 0 || text[..colon] != Scheme)
        {
            throw new FormatException($"expected a \"{Scheme}:\" connection string");
        }

        byte[] payload = Base64Url.Decode(text[(colon + 1)..]);
        if (payload.Length < 13 || payload[0] is not (Version1 or Version2 or Version3 or Version4))
        {
            throw new FormatException("unsupported connection string version");
        }

        byte flags = payload[1];
        if ((payload[0] == Version2 && flags != FlagsHasStaticKey)
            || (payload[0] == Version3 && flags != (FlagsHasStaticKey | FlagsHasEndpointKey))
            || (payload[0] == Version1 && flags != 0)
            // v4 adds the knock bit and makes the endpoint bit optional: static+knock or
            // static+endpoint+knock are the only two shapes a v4 body may wear.
            || (payload[0] == Version4 && flags != (FlagsHasStaticKey | FlagsHasKnock)
                && flags != (FlagsHasStaticKey | FlagsHasEndpointKey | FlagsHasKnock)))
        {
            throw new FormatException("unknown connection string flags");
        }

        var reader = new CandidateCodec.Reader(payload, 2);
        ulong peerId = reader.ReadU64();
        NatHint hint = (NatHint)reader.ReadByte();
        if (hint > NatHint.Symmetric)
        {
            throw new FormatException("unknown NAT hint");
        }

        int count = reader.ReadByte();
        if (count > MaxCandidates)
        {
            throw new FormatException($"connection string carries more than {MaxCandidates} candidates");
        }

        var candidates = new List<PinholeCandidate>(count);
        for (int i = 0; i < count; i++)
        {
            candidates.Add(CandidateCodec.Read(ref reader));
        }

        byte[]? staticKey = null;
        byte[]? endpointKey = null;
        byte[]? knock = null;
        if (payload[0] == Version2)
        {
            if (payload.Length - reader.Position != NodeIdentity.KeyLength)
            {
                throw new FormatException("v2 connection string must end with a 32-byte static key");
            }

            staticKey = payload[^NodeIdentity.KeyLength..];
        }
        else if (payload[0] == Version3)
        {
            if (payload.Length - reader.Position != NodeIdentity.KeyLength + AddressRecord.EndpointKeyLength)
            {
                throw new FormatException("v3 connection string must end with 32-byte static and endpoint keys");
            }

            staticKey = payload[^(NodeIdentity.KeyLength + AddressRecord.EndpointKeyLength)..^AddressRecord.EndpointKeyLength];
            endpointKey = payload[^AddressRecord.EndpointKeyLength..];
        }
        else if (payload[0] == Version4)
        {
            int keys = NodeIdentity.KeyLength
                + ((flags & FlagsHasEndpointKey) != 0 ? AddressRecord.EndpointKeyLength : 0);
            int knockLength = payload.Length - reader.Position > keys ? payload[reader.Position + keys] : 0;
            if (knockLength is < 1 or > MaxKnockLength
                || payload.Length - reader.Position != keys + 1 + knockLength)
            {
                throw new FormatException("v4 connection string must end with its keys and a 1..64-byte knock");
            }

            staticKey = payload[reader.Position..(reader.Position + NodeIdentity.KeyLength)];
            if ((flags & FlagsHasEndpointKey) != 0)
            {
                endpointKey = payload[(reader.Position + NodeIdentity.KeyLength)..(reader.Position + keys)];
            }

            knock = payload[(reader.Position + keys + 1)..];
        }
        else if (!reader.AtEnd)
        {
            throw new FormatException("trailing bytes in connection string");
        }

        return new ConnectionString(peerId, candidates, hint, staticKey, endpointKey, knock);
    }

    private const byte Version1 = 1;
    private const byte Version2 = 2;
    private const byte Version3 = 3;
    private const byte Version4 = 4;
    private const byte FlagsHasStaticKey = 1;
    private const byte FlagsHasEndpointKey = 2;
    private const byte FlagsHasKnock = 4;

    private static void WriteU64(MemoryStream payload, ulong value)
    {
        Span<byte> tmp = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(tmp, value);
        payload.Write(tmp);
    }
}

internal static class CandidateCodec
{
    private const int MaxText = 64;

    public static void Write(MemoryStream payload, PinholeCandidate candidate)
    {
        WriteEndpoint(payload, candidate.Address);
        payload.WriteByte((byte)candidate.Kind);
        if (candidate.Kind == CandidateKind.Relay)
        {
            if (candidate.RelayServer is null || candidate.Username is null || candidate.Credential is null)
            {
                throw new InvalidOperationException("relay candidates require RelayServer, Username and Credential");
            }

            WriteEndpoint(payload, candidate.RelayServer);
            WriteShortText(payload, candidate.Username);
            WriteShortText(payload, candidate.Credential);
        }
        else if (candidate.Kind is CandidateKind.IrohRelay or CandidateKind.DerpRelay)
        {
            if (candidate.RelayUrl is null || candidate.RelayKey is not { Length: 32 }
                || !ValidRelayUrl(candidate.RelayUrl))
                throw new InvalidOperationException("HTTPS relay candidates require a safe relay URL and a 32-byte public key");
            WriteShortText(payload, candidate.RelayUrl.AbsoluteUri);
            payload.Write(candidate.RelayKey);
        }
    }

    public static PinholeCandidate Read(ref Reader reader)
    {
        IPEndPoint address = reader.ReadEndpoint();
        CandidateKind kind = (CandidateKind)reader.ReadByte();
        if (kind is < CandidateKind.Direct or > CandidateKind.DerpRelay)
        {
            throw new FormatException("unknown candidate kind");
        }

        IPEndPoint? server = null;
        string? username = null;
        string? credential = null;
        if (kind == CandidateKind.Relay)
        {
            server = reader.ReadEndpoint();
            username = reader.ReadShortText();
            credential = reader.ReadShortText();
        }
        else if (kind is CandidateKind.IrohRelay or CandidateKind.DerpRelay)
        {
            if (!Uri.TryCreate(reader.ReadShortText(), UriKind.Absolute, out Uri? url) || !ValidRelayUrl(url))
                throw new FormatException("invalid HTTPS relay URL");
            byte[] key = new byte[32];
            for (int i = 0; i < key.Length; i++) key[i] = reader.ReadByte();
            return new PinholeCandidate(kind, address, RelayUrl: url, RelayKey: key);
        }

        return new PinholeCandidate(kind, address, server, username, credential);
    }

    private static bool ValidRelayUrl(Uri url) => url.IsAbsoluteUri
        && (url.Scheme == "https" || (url.Scheme == "http" && url.IsLoopback))
        && url.UserInfo.Length == 0 && url.Query.Length == 0 && url.Fragment.Length == 0;

    private static void WriteEndpoint(MemoryStream payload, IPEndPoint ep)
    {
        byte[] raw = ep.Address.GetAddressBytes();
        payload.WriteByte((byte)raw.Length);
        payload.Write(raw);
        payload.WriteByte((byte)(ep.Port >> 8));
        payload.WriteByte((byte)ep.Port);
    }

    private static void WriteShortText(MemoryStream payload, string value)
    {
        byte[] raw = Encoding.ASCII.GetBytes(value);
        if (raw.Length > MaxText)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "candidate strings are limited to 64 ASCII bytes");
        }

        payload.WriteByte((byte)raw.Length);
        payload.Write(raw);
    }

    public struct Reader(byte[] data, int pos)
    {
        private readonly byte[] _data = data;
        private int _pos = pos;

        public readonly bool AtEnd => _pos == _data.Length;

        public readonly int Position => _pos;

        public byte ReadByte()
        {
            if (_pos >= _data.Length)
            {
                throw Truncated();
            }

            return _data[_pos++];
        }

        public ulong ReadU64()
        {
            if (_pos + 8 > _data.Length)
            {
                throw Truncated();
            }

            ulong value = BinaryPrimitives.ReadUInt64LittleEndian(_data.AsSpan(_pos, 8));
            _pos += 8;
            return value;
        }

        public IPEndPoint ReadEndpoint()
        {
            int family = ReadByte();
            if (family is not 4 and not 16)
            {
                throw new FormatException("unknown address family");
            }

            if (_pos + family + 2 > _data.Length)
            {
                throw Truncated();
            }

            var ep = new IPEndPoint(new IPAddress(_data.AsSpan(_pos, family)), BinaryPrimitives.ReadUInt16BigEndian(_data.AsSpan(_pos + family)));
            _pos += family + 2;
            return ep;
        }

        public string ReadShortText()
        {
            int len = ReadByte();
            if (len > MaxText || _pos + len > _data.Length)
            {
                throw Truncated();
            }

            string s = Encoding.ASCII.GetString(_data, _pos, len);
            _pos += len;
            return s;
        }

        private static FormatException Truncated() => new("payload is truncated");
    }
}

internal static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Decode(string text)
    {
        // Strict charset: Convert.FromBase64String silently skips whitespace, and a
        // connection string that tolerates "AA BB" is one that round-trips ambiguously.
        foreach (char c in text)
        {
            if (!(c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_' or '='))
            {
                throw new FormatException("payload is not valid base64url");
            }
        }

        int pad = (4 - text.Length % 4) % 4;
        string base64 = text.Replace('-', '+').Replace('_', '/') + new string('=', pad);
        try
        {
            return Convert.FromBase64String(base64);
        }
        catch (FormatException ex)
        {
            throw new FormatException("payload is not valid base64url", ex);
        }
    }
}
