using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;

namespace Pinhole;

/// <summary>Kind of candidate address a connection string can carry.</summary>
public enum CandidateKind : byte
{
    /// <summary>A host address of the peer's own socket (LAN/local machine).</summary>
    Direct = 1,

    /// <summary>The peer's server-reflexive address as observed by a STUN server (its NAT mapping).</summary>
    Reflexive = 2,

    /// <summary>A TURN relayed address of the peer. Carries the TURN server and credentials
    /// needed to reach the peer through that relay when the punch fails.</summary>
    Relay = 3,

    /// <summary>Datagrams tunneled through an iroh HTTPS WebSocket relay.</summary>
    IrohRelay = 4,
}

/// <summary>One address a peer can be reached at. TURN candidates carry credentials; iroh candidates
/// carry a relay URL (at most 64 ASCII characters) and the public relay identity key.
/// Address is unused for iroh candidates.</summary>
public sealed record PinholeCandidate(
    CandidateKind Kind,
    IPEndPoint Address,
    IPEndPoint? RelayServer = null,
    string? Username = null,
    string? Credential = null,
    Uri? RelayUrl = null,
    byte[]? RelayKey = null);

/// <summary>A NAT classification hint a publisher can embed in its connection string so
/// dialers can pace direct probes while racing relay fallback.</summary>
public enum NatHint : byte
{
    /// <summary>The publisher has not classified its NAT; dialers should attempt the punch.</summary>
    Unknown = 0,

    /// <summary>Endpoint-independent mapping: the reflexive candidate is reusable, so a direct punch can land.</summary>
    Cone = 1,

    /// <summary>Per-destination mapping: public direct paths depend on the other peer's
    /// filtering behavior; LAN and explicit router mappings may still be reachable.</summary>
    Symmetric = 2,
}

/// <summary>The single discovery artifact: a stable peer ID plus every candidate address the
/// peer is reachable on. Encoded as "pinhole1:&lt;base64url&gt;". How the string travels
/// between peers — clipboard, lobby, your server — is the application's concern.</summary>
public sealed class ConnectionString
{
    /// <summary>The scheme prefix ("pinhole1") every encoded string starts with; the digit is the format version.</summary>
    public const string Scheme = "pinhole1";

    /// <summary>The most candidates one string may carry; the constructor throws above this.</summary>
    public const int MaxCandidates = 32;

    /// <summary>The hard cap on encoded length accepted by <see cref="Parse"/> — longer strings are rejected as malformed, not parsed.
    /// Sized so the worst legal string (32 fat relay candidates) fits: encoding one may reach ~7.4k characters.</summary>
    public const int MaxEncodedLength = 8192;

    /// <summary>The peer's stable ID — the only part that survives roaming while every candidate address churns.</summary>
    public ulong PeerId { get; }

    /// <summary>The NAT classification the publisher embedded, to steer dialers away from a hopeless punch.</summary>
    public NatHint NatHint { get; }

    /// <summary>The peer's long-term X25519 public key (32 bytes) when the string was
    /// published by an encryption-capable node (v2). Dialers pin the answering handshake to
    /// this key, so no man in the middle can substitute itself. Null on v1 strings, whose
    /// dialers fall back to plaintext when the local policy allows it.</summary>
    public byte[]? StaticKey { get; }

    /// <summary>The peer's Ed25519 endpoint public key (32 bytes, v3): the key its signed
    /// address records are verified against, letting a dialer adopt rediscovered endpoints
    /// from a lookup provider without ever trusting the provider. Requires
    /// <see cref="StaticKey"/>; null on v1/v2 strings, whose dialers never adopt
    /// provider-supplied addresses.</summary>
    public byte[]? EndpointKey { get; }

    /// <summary>Every address the peer is reachable on — direct, reflexive, and relay entries as published.</summary>
    public IReadOnlyList<PinholeCandidate> Candidates { get; }

    /// <summary>Assembles a string from a peer ID, its candidates, a NAT hint, and optionally
    /// the peer's 32-byte static public key (making a v2 string) plus its 32-byte endpoint
    /// public key (making a v3 string). Throws <see cref="ArgumentOutOfRangeException"/>
    /// above <see cref="MaxCandidates"/> candidates or for malformed keys.</summary>
    public ConnectionString(ulong peerId, IReadOnlyList<PinholeCandidate> candidates, NatHint natHint = NatHint.Unknown,
        byte[]? staticKey = null, byte[]? endpointKey = null)
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

        PeerId = peerId;
        NatHint = natHint;
        StaticKey = staticKey;
        EndpointKey = endpointKey;
        Candidates = candidates;
    }

    /// <summary>Encodes as "pinhole1:..." (base64url, no padding). Payloads carrying both a
    /// static and an endpoint key are version 3; static only, version 2; neither, version 1 —
    /// the same envelope either way.</summary>
    public override string ToString()
    {
        bool keyed = StaticKey is not null;
        bool epKeyed = EndpointKey is not null;
        var payload = new MemoryStream(64 + Candidates.Count * 32 + (keyed ? NodeIdentity.KeyLength : 0) + (epKeyed ? AddressRecord.EndpointKeyLength : 0));
        byte version = epKeyed ? Version3 : keyed ? Version2 : Version1;
        payload.WriteByte(version);
        payload.WriteByte((byte)((keyed ? FlagsHasStaticKey : 0) | (epKeyed ? FlagsHasEndpointKey : 0)));
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

        return Scheme + ":" + Base64Url.Encode(payload.GetBuffer().AsSpan(0, (int)payload.Length));
    }

    /// <summary>Attempts a <see cref="Parse"/> without throwing: returns false on any malformed
    /// input (wrong scheme, bad base64url, wrong version, truncated or trailing payload).</summary>
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

    /// <summary>Strict parse: throws <see cref="FormatException"/> on anything but a well-formed
    /// current-version string, and <see cref="ArgumentNullException"/> on null. Accepts at most
    /// <see cref="MaxEncodedLength"/> characters and <see cref="MaxCandidates"/> candidates.</summary>
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
        if (payload.Length < 13 || payload[0] is not (Version1 or Version2 or Version3))
        {
            throw new FormatException("unsupported connection string version");
        }

        byte flags = payload[1];
        if ((payload[0] == Version2 && flags != FlagsHasStaticKey)
            || (payload[0] == Version3 && flags != (FlagsHasStaticKey | FlagsHasEndpointKey))
            || (payload[0] == Version1 && flags != 0))
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
        else if (!reader.AtEnd)
        {
            throw new FormatException("trailing bytes in connection string");
        }

        return new ConnectionString(peerId, candidates, hint, staticKey, endpointKey);
    }

    private const byte Version1 = 1;
    private const byte Version2 = 2;
    private const byte Version3 = 3;
    private const byte FlagsHasStaticKey = 1;
    private const byte FlagsHasEndpointKey = 2;

    private static void WriteU64(MemoryStream payload, ulong value)
    {
        Span<byte> tmp = stackalloc byte[8];
        BitConverter.TryWriteBytes(tmp, value);
        payload.Write(tmp);
    }
}

/// <summary>Candidate TLV codec shared by connection strings and announce frames.</summary>
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
        else if (candidate.Kind == CandidateKind.IrohRelay)
        {
            if (candidate.RelayUrl is null || candidate.RelayKey is not { Length: 32 }
                || !ValidRelayUrl(candidate.RelayUrl))
                throw new InvalidOperationException("iroh candidates require an HTTPS relay URL and a 32-byte public key");
            WriteShortText(payload, candidate.RelayUrl.AbsoluteUri);
            payload.Write(candidate.RelayKey);
        }
    }

    public static PinholeCandidate Read(ref Reader reader)
    {
        IPEndPoint address = reader.ReadEndpoint();
        CandidateKind kind = (CandidateKind)reader.ReadByte();
        if (kind is < CandidateKind.Direct or > CandidateKind.IrohRelay)
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
        else if (kind == CandidateKind.IrohRelay)
        {
            if (!Uri.TryCreate(reader.ReadShortText(), UriKind.Absolute, out Uri? url) || !ValidRelayUrl(url))
                throw new FormatException("invalid iroh relay URL");
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

            ulong value = BitConverter.ToUInt64(_data, _pos);
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
