using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Pinhole;

// iroh-dns 1.x / BEP 44: the HTTP payload is signature || timestampBE || DNS.
// The pinned key comes from the URL, not from an untrusted response body.
internal sealed class IrohDiscovery
{
    internal const int MaxPayloadSize = 1072;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private readonly HttpClient _http;
    private readonly Uri _relay;
    private readonly Dictionary<string, ulong> _sequences = new(StringComparer.Ordinal);
    private long _timestamp;

    internal IrohDiscovery(HttpClient http, Uri relay)
    {
        _http = http;
        _relay = IrohAddress.ValidateRelay(relay);
    }

    private Uri Url(byte[] key) => new(_relay.AbsoluteUri.TrimEnd('/') + "/" + IrohEncoding.Encode32(key, zbase: true));

    internal async Task<IrohAddress> ResolveAsync(string endpointId, CancellationToken ct)
    {
        byte[] key = IrohEncoding.ParseKey(endpointId);
        using HttpResponseMessage response = await _http.GetAsync(Url(key), HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        using Stream input = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        byte[] buffer = new byte[MaxPayloadSize + 1];
        int used = 0;
        while (used < buffer.Length)
        {
            int read = await input.ReadAsync(buffer.AsMemory(used), ct).ConfigureAwait(false);
            if (read == 0) break;
            used += read;
        }
        IrohAddress address = ParsePayload(key, buffer.AsSpan(0, used), out ulong sequence);
        lock (_sequences)
        {
            if (_sequences.TryGetValue(address.EndpointId, out ulong previous) && sequence < previous)
                throw new InvalidDataException("the iroh discovery record is a rollback");
            if (_sequences.Count < 1024 || _sequences.ContainsKey(address.EndpointId))
                _sequences[address.EndpointId] = sequence;
        }
        return address;
    }

    internal async Task PublishAsync(IrohAddress address, RelayIdentity identity, CancellationToken ct)
    {
        long previous, next;
        do
        {
            previous = Volatile.Read(ref _timestamp);
            next = Math.Max(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1000, previous + 1);
        } while (Interlocked.CompareExchange(ref _timestamp, next, previous) != previous);
        byte[] payload = CreatePayload(address, identity, (ulong)next);
        using var content = new ByteArrayContent(payload);
        content.Headers.ContentType = new("application/octet-stream");
        using HttpResponseMessage response = await _http.PutAsync(Url(address.Key), content, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
    }

    internal static byte[] CreatePayload(IrohAddress address, RelayIdentity identity, ulong timestamp)
    {
        if (!address.Key.AsSpan().SequenceEqual(identity.PublicKey)) throw new ArgumentException("the publishing key does not match the endpoint ID");
        List<string> values = address.RelayUrls.Select(x => "relay=" + x.AbsoluteUri).ToList();
        // Native EndpointInfo parses one TransportAddr per TXT value. A grouped
        // space-separated value verifies cryptographically but loses every address.
        values.AddRange(address.DirectAddresses.Select(x => "addr=" + x));
        using var dns = new MemoryStream();
        byte[] header = new byte[12];
        header[2] = 0x80; // DNS reply
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6), (ushort)values.Count);
        dns.Write(header);
        string owner = "_iroh." + IrohEncoding.Encode32(address.Key, zbase: true);
        foreach (string value in values)
        {
            if (dns.Position > 12)
            {
                dns.WriteByte(0xc0);
                dns.WriteByte(12); // owner of the first answer
            }
            else
            {
                foreach (string label in owner.Split('.'))
                {
                    byte[] bytes = Encoding.ASCII.GetBytes(label);
                    dns.WriteByte((byte)bytes.Length);
                    dns.Write(bytes);
                }
                dns.WriteByte(0);
            }
            byte[] rr = new byte[10];
            BinaryPrimitives.WriteUInt16BigEndian(rr, 16); // TXT
            BinaryPrimitives.WriteUInt16BigEndian(rr.AsSpan(2), 1); // IN
            BinaryPrimitives.WriteUInt32BigEndian(rr.AsSpan(4), 60);
            byte[] text = Utf8.GetBytes(value);
            int chunks = (text.Length + 254) / 255;
            BinaryPrimitives.WriteUInt16BigEndian(rr.AsSpan(8), checked((ushort)(text.Length + chunks)));
            dns.Write(rr);
            for (int offset = 0; offset < text.Length; offset += 255)
            {
                int size = Math.Min(255, text.Length - offset);
                dns.WriteByte((byte)size);
                dns.Write(text, offset, size);
            }
        }
        byte[] packet = dns.ToArray();
        if (packet.Length > 1000) throw new InvalidDataException("iroh discovery DNS records exceed the 1000-byte pkarr limit");
        byte[] payload = new byte[72 + packet.Length];
        identity.SignBody(Signable(timestamp, packet)).CopyTo(payload, 0);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(64), timestamp);
        packet.CopyTo(payload, 72);
        return payload;
    }

    private static byte[] Signable(ulong timestamp, ReadOnlySpan<byte> dns)
    {
        byte[] prefix = Encoding.ASCII.GetBytes("3:seqi" + timestamp.ToString(CultureInfo.InvariantCulture)
            + "e1:v" + dns.Length.ToString(CultureInfo.InvariantCulture) + ":");
        byte[] message = new byte[prefix.Length + dns.Length];
        prefix.CopyTo(message, 0);
        dns.CopyTo(message.AsSpan(prefix.Length));
        return message;
    }

    internal static IrohAddress ParsePayload(byte[] key, ReadOnlySpan<byte> payload, out ulong timestamp)
    {
        if (key.Length != 32 || payload.Length is < 84 or > MaxPayloadSize)
            throw new InvalidDataException("invalid pkarr payload size");
        timestamp = BinaryPrimitives.ReadUInt64BigEndian(payload[64..]);
        ReadOnlySpan<byte> dns = payload[72..];
        var verifier = new Ed25519Signer();
        verifier.Init(false, new Ed25519PublicKeyParameters(key));
        verifier.BlockUpdate(Signable(timestamp, dns));
        if (!verifier.VerifySignature(payload[..64].ToArray()))
            throw new InvalidDataException("the iroh discovery record failed endpoint-key verification");
        string owner = "_iroh." + IrohEncoding.Encode32(key, zbase: true);
        List<IPEndPoint> direct = [];
        List<Uri> relays = [];
        foreach (string value in ReadTxt(dns, owner))
        {
            if (value.StartsWith("relay=", StringComparison.Ordinal))
            {
                if (!Uri.TryCreate(value[6..], UriKind.Absolute, out Uri? relay)) throw new InvalidDataException("invalid discovered iroh relay URL");
                try { relays.Add(IrohAddress.ValidateRelay(relay)); }
                catch (ArgumentException ex) { throw new InvalidDataException("unsafe discovered iroh relay URL", ex); }
            }
            else if (value.StartsWith("addr=", StringComparison.Ordinal))
            {
                foreach (string address in value[5..].Split(' ', StringSplitOptions.RemoveEmptyEntries))
                {
                    if (IPEndPoint.TryParse(address, out IPEndPoint? endpoint) && endpoint.Port > 0) direct.Add(endpoint);
                    // Custom transport addresses need a corresponding custom transport;
                    // IP/relay consumers may still use the other records in the packet.
                }
            }
            if (direct.Count + relays.Count > IrohAddress.MaxAddresses) throw new InvalidDataException("too many discovered iroh paths");
        }
        return new IrohAddress(Convert.ToHexString(key), direct, relays);
    }

    private static List<string> ReadTxt(ReadOnlySpan<byte> dns, string expectedOwner)
    {
        List<string> values = [];
        int offset = 12;
        int questions = BinaryPrimitives.ReadUInt16BigEndian(dns[4..]);
        int answers = BinaryPrimitives.ReadUInt16BigEndian(dns[6..]);
        int remaining = BinaryPrimitives.ReadUInt16BigEndian(dns[8..]) + BinaryPrimitives.ReadUInt16BigEndian(dns[10..]);
        if (questions > 64 || answers + remaining > 128) throw new InvalidDataException("too many DNS records");
        for (int i = 0; i < questions; i++) { ReadName(dns, ref offset); Check(dns, offset, 4); offset += 4; }
        for (int i = 0; i < answers + remaining; i++)
        {
            string name = ReadName(dns, ref offset);
            Check(dns, offset, 10);
            int type = BinaryPrimitives.ReadUInt16BigEndian(dns[offset..]);
            int rrClass = BinaryPrimitives.ReadUInt16BigEndian(dns[(offset + 2)..]) & 0x7fff;
            int size = BinaryPrimitives.ReadUInt16BigEndian(dns[(offset + 8)..]);
            offset += 10;
            Check(dns, offset, size);
            if (i < answers && type == 16 && rrClass == 1 && name.Equals(expectedOwner, StringComparison.OrdinalIgnoreCase))
            {
                using var text = new MemoryStream();
                int end = offset + size;
                for (int cursor = offset; cursor < end;)
                {
                    int length = dns[cursor++];
                    if (length > end - cursor) throw new InvalidDataException("truncated DNS TXT string");
                    text.Write(dns.Slice(cursor, length));
                    cursor += length;
                }
                values.Add(Utf8.GetString(text.ToArray()));
            }
            offset += size;
        }
        if (offset != dns.Length) throw new InvalidDataException("trailing bytes in DNS packet");
        return values;
    }

    private static string ReadName(ReadOnlySpan<byte> dns, ref int offset)
    {
        int cursor = offset, end = -1;
        var labels = new List<string>();
        for (int steps = 0; steps < 128; steps++)
        {
            Check(dns, cursor, 1);
            byte length = dns[cursor++];
            if (length == 0) { offset = end < 0 ? cursor : end; return string.Join('.', labels); }
            if ((length & 0xc0) == 0xc0)
            {
                Check(dns, cursor, 1);
                int target = ((length & 63) << 8) | dns[cursor++];
                if (target >= cursor - 2) throw new InvalidDataException("invalid DNS compression pointer");
                if (end < 0) end = cursor;
                cursor = target;
            }
            else
            {
                if (length > 63) throw new InvalidDataException("invalid DNS label");
                Check(dns, cursor, length);
                labels.Add(Utf8.GetString(dns.Slice(cursor, length)));
                if (labels.Sum(x => x.Length + 1) > 255) throw new InvalidDataException("DNS name exceeds size limit");
                cursor += length;
            }
        }
        throw new InvalidDataException("DNS compression loop");
    }

    private static void Check(ReadOnlySpan<byte> packet, int offset, int length)
    {
        if (offset < 0 || length > packet.Length - offset) throw new InvalidDataException("truncated DNS packet");
    }
}
