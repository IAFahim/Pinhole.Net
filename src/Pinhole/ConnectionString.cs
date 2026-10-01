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
}

/// <summary>One address a peer can be reached at. Relay candidates carry the server and
/// credentials needed to send to the relayed address.</summary>
public sealed record PinholeCandidate(
    CandidateKind Kind,
    IPEndPoint Address,
    IPEndPoint? RelayServer = null,
    string? Username = null,
    string? Credential = null);

/// <summary>A NAT classification hint a publisher can embed in its connection string so
/// dialers can skip a hopeless punch (symmetric NAT) and go straight to relay.</summary>
public enum NatHint : byte
{
    /// <summary>The publisher has not classified its NAT; dialers should attempt the punch.</summary>
    Unknown = 0,

    /// <summary>Endpoint-independent mapping: the reflexive candidate is reusable, so a direct punch can land.</summary>
    Cone = 1,

    /// <summary>Per-destination mapping: the observed reflexive address is useless to a dialer — skip the punch, go straight to relay.</summary>
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

    /// <summary>The hard cap on encoded length accepted by <see cref="Parse"/> — longer strings are rejected as malformed, not parsed.</summary>
    public const int MaxEncodedLength = 4096;

    /// <summary>The peer's stable ID — the only part that survives roaming while every candidate address churns.</summary>
    public ulong PeerId { get; }

    /// <summary>The NAT classification the publisher embedded, to steer dialers away from a hopeless punch.</summary>
    public NatHint NatHint { get; }

    /// <summary>Every address the peer is reachable on — direct, reflexive, and relay entries as published.</summary>
    public IReadOnlyList<PinholeCandidate> Candidates { get; }

    /// <summary>Assembles a string from a peer ID, its candidates, and a NAT hint. Throws
    /// <see cref="ArgumentOutOfRangeException"/> above <see cref="MaxCandidates"/> candidates.</summary>
    public ConnectionString(ulong peerId, IReadOnlyList<PinholeCandidate> candidates, NatHint natHint = NatHint.Unknown)
    {
        if (candidates.Count > MaxCandidates)
        {
            throw new ArgumentOutOfRangeException(nameof(candidates), $"at most {MaxCandidates} candidates fit a connection string");
        }

        PeerId = peerId;
        NatHint = natHint;
        Candidates = candidates;
    }

    /// <summary>Encodes as "pinhole1:..." (base64url, no padding).</summary>
    public override string ToString()
    {
        var payload = new MemoryStream(64 + Candidates.Count * 32);
        payload.WriteByte(Version);
        payload.WriteByte(0); // flags, reserved
        WriteU64(payload, PeerId);
        payload.WriteByte((byte)NatHint);
        payload.WriteByte((byte)Candidates.Count);
        foreach (PinholeCandidate candidate in Candidates)
        {
            CandidateCodec.Write(payload, candidate);
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
        if (payload.Length < 13 || payload[0] != Version)
        {
            throw new FormatException("unsupported connection string version");
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

        if (!reader.AtEnd)
        {
            throw new FormatException("trailing bytes in connection string");
        }

        return new ConnectionString(peerId, candidates, hint);
    }

    private const byte Version = 1;

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
    }

    public static PinholeCandidate Read(ref Reader reader)
    {
        IPEndPoint address = reader.ReadEndpoint();
        CandidateKind kind = (CandidateKind)reader.ReadByte();
        if (kind is < CandidateKind.Direct or > CandidateKind.Relay)
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

        return new PinholeCandidate(kind, address, server, username, credential);
    }

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

        public byte ReadByte()
        {
            if (_pos >= _data.Length)
            {
                throw truncated();
            }

            return _data[_pos++];
        }

        public ulong ReadU64()
        {
            if (_pos + 8 > _data.Length)
            {
                throw truncated();
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
                throw truncated();
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
                throw truncated();
            }

            string s = Encoding.ASCII.GetString(_data, _pos, len);
            _pos += len;
            return s;
        }

        private static FormatException truncated() => new("payload is truncated");
    }
}

internal static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Decode(string text)
    {
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
