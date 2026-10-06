using System.Net;
using System.Text;

namespace Pinhole;

/// <summary>An iroh endpoint's Ed25519 identity and IP/relay addresses. Encodes the native
/// iroh 1.x <c>endpoint...</c> ticket, independently of Pinhole's connection strings.</summary>
public sealed class IrohAddress
{
    internal const int MaxAddresses = 64;
    internal byte[] Key { get; }
    private readonly IPEndPoint[] _direct;
    private readonly Uri[] _relays;

    /// <summary>Creates an address from an endpoint ID (hex or unpadded base32) and known paths.</summary>
    public IrohAddress(string endpointId, IReadOnlyList<IPEndPoint>? directAddresses = null,
        IReadOnlyList<Uri>? relayUrls = null)
    {
        Key = IrohEncoding.ParseKey(endpointId);
        EndpointId = Convert.ToHexString(Key).ToLowerInvariant();
        _direct = (directAddresses ?? []).Select(Clone).Distinct().ToArray();
        _relays = (relayUrls ?? []).Select(ValidateRelay).Distinct().ToArray();
        if (_direct.Length + _relays.Length > MaxAddresses)
            throw new ArgumentException($"an iroh address may have at most {MaxAddresses} paths");
    }

    /// <summary>The 32-byte Ed25519 endpoint public key as canonical lowercase hex.</summary>
    public string EndpointId { get; }
    /// <summary>Known direct UDP paths. A snapshot protects the address from caller mutation.</summary>
    public IReadOnlyList<IPEndPoint> DirectAddresses => Array.AsReadOnly(_direct.Select(Clone).ToArray());
    /// <summary>Known home relay URLs.</summary>
    public IReadOnlyList<Uri> RelayUrls => Array.AsReadOnly(_relays);

    /// <summary>Optional application metadata from signed iroh discovery (at most 245 UTF-8
    /// bytes). Native endpoint tickets contain addresses only and do not encode this field.</summary>
    public string? UserData { get; init; }

    /// <summary>Encodes an iroh 1.x EndpointTicket (postcard followed by unpadded base32).</summary>
    public override string ToString()
    {
        using var wire = new MemoryStream();
        wire.WriteByte(0); // EndpointTicket::Variant1
        wire.Write(Key);
        IrohEncoding.WriteVarint(wire, (ulong)(_relays.Length + _direct.Length));
        // Match TransportAddr's BTreeSet order: Relay, Ip; then URL/SocketAddr order.
        foreach (Uri relay in _relays.OrderBy(x => x.AbsoluteUri, StringComparer.Ordinal))
        {
            wire.WriteByte(0);
            byte[] url = Encoding.UTF8.GetBytes(relay.AbsoluteUri);
            IrohEncoding.WriteVarint(wire, (ulong)url.Length);
            wire.Write(url);
        }
        foreach (IPEndPoint direct in _direct.OrderBy(x => x.AddressFamily)
            .ThenBy(x => Convert.ToHexString(x.Address.GetAddressBytes()), StringComparer.Ordinal).ThenBy(x => x.Port))
        {
            wire.WriteByte(1);
            byte[] ip = direct.Address.GetAddressBytes();
            wire.WriteByte(ip.Length == 4 ? (byte)0 : (byte)1);
            wire.Write(ip);
            IrohEncoding.WriteVarint(wire, (ulong)direct.Port);
        }
        return "endpoint" + IrohEncoding.Encode32(wire.ToArray());
    }

    /// <summary>Parses an iroh 1.x endpoint ticket, or an endpoint ID with no addressing information.</summary>
    public static IrohAddress Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        text = text.Trim();
        if (!text.StartsWith("endpoint", StringComparison.Ordinal)) return new IrohAddress(text);
        if (text.Length > 32768) throw new FormatException("iroh ticket exceeds the size limit");
        ReadOnlySpan<byte> wire = IrohEncoding.Decode32(text[8..]);
        if (IrohEncoding.Take(ref wire, 1)[0] != 0) throw new FormatException("unsupported iroh ticket version");
        string id = Convert.ToHexString(IrohEncoding.Take(ref wire, 32));
        ulong count = IrohEncoding.ReadVarint(ref wire);
        if (count > MaxAddresses) throw new FormatException("too many iroh ticket addresses");
        List<IPEndPoint> direct = [];
        List<Uri> relays = [];
        for (ulong i = 0; i < count; i++)
        {
            byte kind = IrohEncoding.Take(ref wire, 1)[0];
            if (kind == 0)
            {
                ulong size = IrohEncoding.ReadVarint(ref wire);
                if (size is 0 or > 2048) throw new FormatException("invalid iroh relay URL length");
                string url = new UTF8Encoding(false, true).GetString(IrohEncoding.Take(ref wire, (int)size));
                if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? relay)) throw new FormatException("invalid iroh relay URL");
                relays.Add(ValidateRelay(relay));
            }
            else if (kind == 1)
            {
                byte family = IrohEncoding.Take(ref wire, 1)[0];
                if (family > 1) throw new FormatException("invalid iroh IP family");
                var ip = new IPAddress(IrohEncoding.Take(ref wire, family == 0 ? 4 : 16));
                ulong port = IrohEncoding.ReadVarint(ref wire);
                if (port is 0 or > 65535) throw new FormatException("invalid iroh UDP port");
                direct.Add(new IPEndPoint(ip, (int)port));
            }
            else throw new FormatException("iroh custom transports require their own transport adapter");
        }
        if (!wire.IsEmpty) throw new FormatException("trailing bytes in iroh ticket");
        try { return new IrohAddress(id, direct, relays); }
        catch (ArgumentException ex) { throw new FormatException("invalid iroh address", ex); }
    }

    internal static Uri ValidateRelay(Uri url)
    {
        ArgumentNullException.ThrowIfNull(url);
        if (!url.IsAbsoluteUri || url.Scheme is not ("https" or "http")
            || (url.Scheme == "http" && !url.IsLoopback) || url.UserInfo.Length != 0
            || url.Query.Length != 0 || url.Fragment.Length != 0 || url.AbsoluteUri.Length > 2048)
            throw new ArgumentException("iroh URL must use HTTPS (HTTP is allowed on loopback)", nameof(url));
        return url;
    }

    private static IPEndPoint Clone(IPEndPoint endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (endpoint.Port is < 1 or > 65535) throw new ArgumentException("invalid iroh UDP port", nameof(endpoint));
        IPAddress ip = endpoint.Address.IsIPv4MappedToIPv6 ? endpoint.Address.MapToIPv4() : endpoint.Address;
        return new IPEndPoint(new IPAddress(ip.GetAddressBytes()), endpoint.Port);
    }
}

internal static class IrohEncoding
{
    private const string Base32 = "abcdefghijklmnopqrstuvwxyz234567";
    private const string ZBase32 = "ybndrfg8ejkmcpqxot1uwisza345h769";

    internal static byte[] ParseKey(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        text = text.Trim();
        byte[] key = text.Length == 64 ? Convert.FromHexString(text) : Decode32(text);
        if (key.Length != 32) throw new FormatException("an iroh endpoint ID must be a 32-byte Ed25519 public key");
        if (!Org.BouncyCastle.Math.EC.Rfc8032.Ed25519.ValidatePublicKeyFull(key, 0))
            throw new FormatException("invalid iroh Ed25519 public key");
        return key;
    }

    internal static string Encode32(ReadOnlySpan<byte> data, bool zbase = false)
    {
        string alphabet = zbase ? ZBase32 : Base32;
        var result = new StringBuilder((data.Length * 8 + 4) / 5);
        int bits = 0, buffer = 0;
        foreach (byte value in data)
        {
            buffer = (buffer << 8) | value;
            bits += 8;
            while (bits >= 5) { bits -= 5; result.Append(alphabet[(buffer >> bits) & 31]); }
        }
        if (bits > 0) result.Append(alphabet[(buffer << (5 - bits)) & 31]);
        return result.ToString();
    }

    internal static byte[] Decode32(string text)
    {
        if (text.Length > 32768) throw new FormatException("base32 value exceeds the size limit");
        byte[] result = new byte[text.Length * 5 / 8];
        int bits = 0, buffer = 0, offset = 0;
        foreach (char c in text)
        {
            int value = Base32.IndexOf(char.ToLowerInvariant(c));
            if (value < 0) throw new FormatException("invalid unpadded base32");
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) { bits -= 8; result[offset++] = (byte)(buffer >> bits); }
        }
        if (bits >= 5 || (buffer & ((1 << bits) - 1)) != 0) throw new FormatException("noncanonical base32 padding");
        return result;
    }

    internal static void WriteVarint(Stream stream, ulong value)
    {
        while (value >= 128) { stream.WriteByte((byte)(value | 128)); value >>= 7; }
        stream.WriteByte((byte)value);
    }

    internal static ulong ReadVarint(ref ReadOnlySpan<byte> wire)
    {
        ulong value = 0;
        for (int shift = 0; shift <= 63; shift += 7)
        {
            byte next = Take(ref wire, 1)[0];
            if (shift == 63 && next > 1) throw new FormatException("iroh varint overflow");
            value |= (ulong)(next & 127) << shift;
            if (next < 128)
            {
                if (shift > 0 && next == 0) throw new FormatException("noncanonical iroh varint");
                return value;
            }
        }
        throw new FormatException("iroh varint overflow");
    }

    internal static ReadOnlySpan<byte> Take(ref ReadOnlySpan<byte> wire, int length)
    {
        if (length > wire.Length) throw new FormatException("truncated iroh ticket");
        ReadOnlySpan<byte> result = wire[..length];
        wire = wire[length..];
        return result;
    }
}
