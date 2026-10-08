using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Pinhole;

/// <summary>One peer found on the local link, already assembled into a dialable form.</summary>
public sealed record LanPeer(ulong PeerId, IReadOnlyList<IPEndPoint> Endpoints, NatHint NatHint, byte[]? StaticKey)
{
    /// <summary>The discovered peer as a dialable connection string — v2 (with the static
    /// key) when the announcer runs encryption, v1 otherwise.</summary>
    public ConnectionString ToConnectionString() => new(
        PeerId,
        Endpoints.Select(e => new PinholeCandidate(CandidateKind.Direct, e)).ToList(),
        NatHint,
        StaticKey);
}

/// <summary>Announces this node as <c>&lt;peer-id-hex&gt;._pinhole._udp.local</c> on the
/// link (RFC 6762/6763 subset) and browses for peers doing the same — how two machines on
/// one LAN find each other with no server at all. The announcement carries the peer ID,
/// the static public key, the NAT hint, and the local addresses: everything a dialer needs
/// to build a v2 connection string, authenticated by the same key pinning as any other.
/// Production traffic rides the mDNS multicast group; tests inject a direct channel.</summary>
internal sealed class LanDiscovery : IDisposable
{
    public const string Service = "_pinhole._udp.local";
    private const string HostSuffix = ".pinhole.local";
    private const uint RecordTtl = 120;              // seconds; a gone announcer ages out fast
    private const int MaxAddresses = 4;              // announcements must stay under one datagram
    private const long HeartbeatMs = 120_000;

    private readonly ILanChannel _channel;
    private readonly ulong _peerId;
    private readonly byte[]? _staticKey;
    private readonly Func<IReadOnlyList<IPAddress>> _addresses;
    private readonly int _port;
    private readonly NatHint _hint;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _loop;

    public LanDiscovery(ILanChannel channel, ulong peerId, byte[]? staticKey, Func<IReadOnlyList<IPAddress>> addresses, int port, NatHint hint)
    {
        _channel = channel;
        _peerId = peerId;
        _staticKey = staticKey is null ? null : (byte[])staticKey.Clone();
        _addresses = addresses;
        _port = port;
        _hint = hint;
        _loop = Task.Run(() => RunAsync(_shutdown.Token));
    }

    private async Task RunAsync(CancellationToken ct)
    {
        // The RFC's three startup announcements, then a slow heartbeat keeping neighbors'
        // caches warm, answering queries in between.
        for (int i = 0; i < 3 && !ct.IsCancellationRequested; i++)
        {
            try { SendAnnouncement(RecordTtl); }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException) { return; }
            if (i < 2)
            {
                await SafeDelay(150, ct).ConfigureAwait(false);
            }
        }

        long nextHeartbeat = Environment.TickCount64 + HeartbeatMs;
        byte[] buf = new byte[1500];
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (_channel.TryReceive(buf, out int len, out IPEndPoint from, 500))
                {
                    if (DnsCodec.AsksForOurService(buf.AsSpan(0, len)))
                    {
                        SendAnnouncement(RecordTtl, from);
                    }
                }

                if (Environment.TickCount64 >= nextHeartbeat)
                {
                    nextHeartbeat = Environment.TickCount64 + HeartbeatMs;
                    SendAnnouncement(RecordTtl);
                }
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                break; // the channel died; nothing left to announce on
            }
        }
    }

    /// <summary>The full record set — PTR, SRV, TXT, and one address record per local
    /// address — as one mDNS response. TTL 0 makes the same packet the goodbye.</summary>
    private void SendAnnouncement(uint ttl, IPEndPoint? unicastTo = null)
    {
        IReadOnlyList<IPAddress> addresses = _addresses();
        string instance = IdText(_peerId);
        string host = instance + HostSuffix;

        var w = new DnsCodec.Writer();
        w.Header(flags: 0x8400, questions: 0, answers: 3 + Math.Min(addresses.Count, MaxAddresses), 0, 0);
        w.WritePtr(Service, instance, ttl);
        w.WriteSrv(Service, instance, host, (ushort)_port, ttl);
        w.WriteTxt(Service, instance, TxtEntries(), ttl);
        foreach (IPAddress address in addresses.Take(MaxAddresses))
        {
            w.WriteAddress(host, address, ttl);
        }

        _channel.Send(w.ToArray(), unicastTo);
    }

    private (string Key, string Value)[] TxtEntries()
    {
        var entries = new List<(string, string)>
        {
            ("id", IdText(_peerId)),
            ("hint", ((int)_hint).ToString()),
        };
        if (_staticKey is { } key)
        {
            entries.Add(("key", Convert.ToHexString(key).ToLowerInvariant()));
        }
        return entries.ToArray();
    }

    public void Dispose()
    {
        _shutdown.Cancel();
        try
        {
            SendAnnouncement(ttl: 0); // goodbye: cache-flush the records out of neighbors
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
        }
        _channel.Dispose();
    }

    // ------------------------------------------------------------------ browsing

    /// <summary>Asks the link who else is a pinhole node and collects answers for one
    /// window — both responses to the query and unsolicited announcements count. Two
    /// queries a second apart cover ordinary loss.</summary>
    public static async Task<IReadOnlyList<LanPeer>> BrowseAsync(ILanChannel channel, TimeSpan window, CancellationToken ct)
    {
        byte[] query = BuildQuery();
        _ = Task.Run(() =>
        {
            channel.Send(query, null);
            Thread.Sleep(1000);
            try { channel.Send(query, null); } catch (Exception ex) when (ex is SocketException or ObjectDisposedException) { }
        }, CancellationToken.None);

        var peers = new Dictionary<ulong, LanPeer>();
        byte[] buf = new byte[1500];
        long deadline = Environment.TickCount64 + (long)window.TotalMilliseconds;
        while (Environment.TickCount64 < deadline && !ct.IsCancellationRequested)
        {
            long remaining = deadline - Environment.TickCount64;
            try
            {
                if (channel.TryReceive(buf, out int len, out _, (int)Math.Clamp(remaining, 1, 500))
                    && DnsCodec.TryParsePeers(buf.AsSpan(0, len), out IReadOnlyList<LanPeer> found))
                {
                    foreach (LanPeer peer in found)
                    {
                        peers.TryAdd(peer.PeerId, peer);
                    }
                }
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                break;
            }
        }

        return peers.Values.ToArray();
    }

    private static byte[] BuildQuery()
    {
        var w = new DnsCodec.Writer();
        w.Header(flags: 0x0000, questions: 1, answers: 0, 0, 0);
        w.WritePtrQuestion(Service);
        return w.ToArray();
    }

    private static async Task SafeDelay(int ms, CancellationToken ct)
    {
        try { await Task.Delay(ms, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { }
    }

    internal static string IdText(ulong peerId) => peerId.ToString("x16");
    internal static string HostOf(ulong peerId) => IdText(peerId) + HostSuffix;

    /// <summary>Exactly 16 hex digits — strictly digits (TryParse with HexNumber would
    /// accept signs and whitespace, which hex decoding later rejects).</summary>
    internal static bool IsHex16(string text) => text.Length == 16 && text.All(Uri.IsHexDigit);
}

/// <summary>Where announcements and queries travel. Production rides the mDNS multicast
/// group; tests inject a direct channel so no OS multicast runs in CI.</summary>
internal interface ILanChannel : IDisposable
{
    /// <summary>Sends one packet — to the group, or to one querier answering a legacy
    /// unicast query. Null means "the group".</summary>
    void Send(ReadOnlySpan<byte> packet, IPEndPoint? unicastTo);

    /// <summary>Receives one datagram if any arrives within the timeout.</summary>
    bool TryReceive(byte[] buffer, out int length, out IPEndPoint from, int timeoutMs);
}

/// <summary>The production channel: one UDP socket on the mDNS port joined to the
/// link-scope multicast group. Multiple processes share the port (SO_REUSEADDR), as the
/// RFC requires; 224.0.0.251 is never forwarded by routers, so announcements stay on the
/// local link by construction.</summary>
internal sealed class MulticastLanChannel : ILanChannel
{
    public static readonly IPEndPoint GroupV4 = new(IPAddress.Parse("224.0.0.251"), 5353);

    private readonly Socket _socket;

    public MulticastLanChannel()
    {
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            _socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _socket.MulticastLoopback = true; // hearing ourselves is harmless — peers dedupe by id
            _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 255);
            _socket.Bind(new IPEndPoint(IPAddress.Any, 5353));
            _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(GroupV4.Address));
        }
        catch
        {
            _socket.Dispose();
            throw;
        }
    }

    public void Send(ReadOnlySpan<byte> packet, IPEndPoint? unicastTo)
    {
        _socket.SendTo(packet, SocketFlags.None, unicastTo ?? GroupV4);
    }

    public bool TryReceive(byte[] buffer, out int length, out IPEndPoint from, int timeoutMs)
    {
        if (!_socket.Poll(timeoutMs * 1000, SelectMode.SelectRead))
        {
            length = 0;
            from = new IPEndPoint(IPAddress.Any, 0);
            return false;
        }

        EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
        length = _socket.ReceiveFrom(buffer, ref remote);
        from = (IPEndPoint)remote;
        return true;
    }

    public void Dispose() => _socket.Dispose();
}

/// <summary>Strict, minimal DNS wire codec: one PTR question out, the pinhole record set
/// in. Anything hostile — pointer loops, oversized labels, truncated sections, absurd
/// counts — costs the packet, never the process.</summary>
internal static class DnsCodec
{
    private const ushort TypeA = 1, TypePtr = 12, TypeTxt = 16, TypeAaaa = 28, TypeSrv = 33;
    private const ushort ClassIn = 1, ClassAny = 255;
    private const int MaxNameBytes = 255;
    private const int MaxNameJumps = 128;
    private const int MaxRecords = 256;

    /// <summary>A record worth keeping, flattened: what it was and where its rdata lives
    /// in the packet (names stay packet-relative — compression survives that way).</summary>
    private readonly record struct WireRecord(ushort Type, int RdataStart, int RdataLength);

    public sealed class Writer
    {
        private readonly List<byte> _buf = new(512);

        public void Header(ushort flags, int questions, int answers, int authority, int additional)
        {
            AppendU16(0); // mDNS: transaction id zero
            AppendU16(flags);
            AppendU16((ushort)questions);
            AppendU16((ushort)answers);
            AppendU16((ushort)authority);
            AppendU16((ushort)additional);
        }

        public void WritePtrQuestion(string service)
        {
            WriteName(service);
            AppendU16(TypePtr);
            AppendU16(ClassIn);
        }

        public void WritePtr(string service, string instance, uint ttl)
        {
            WriteName(service);
            AppendU16(TypePtr);
            AppendU16(ClassIn);
            AppendU32(ttl);
            int lengthAt = StartRdata();
            WriteName(instance + "." + service);
            FinishRdata(lengthAt);
        }

        public void WriteSrv(string service, string instance, string target, ushort port, uint ttl)
        {
            WriteName(instance + "." + service);
            AppendU16(TypeSrv);
            AppendU16((ushort)(ClassIn | CacheFlushBit));
            AppendU32(ttl);
            int lengthAt = StartRdata();
            AppendU16(0); // priority
            AppendU16(0); // weight
            AppendU16(port);
            WriteName(target);
            FinishRdata(lengthAt);
        }

        public void WriteTxt(string service, string instance, (string Key, string Value)[] entries, uint ttl)
        {
            WriteName(instance + "." + service);
            AppendU16(TypeTxt);
            AppendU16((ushort)(ClassIn | CacheFlushBit));
            AppendU32(ttl);
            int lengthAt = StartRdata();
            foreach ((string key, string value) in entries)
            {
                string entry = key + "=" + value;
                if (entry.Length > 255)
                {
                    throw new InvalidOperationException("TXT entries are one DNS string each");
                }
                AppendU8((byte)entry.Length);
                _buf.AddRange(Encoding.ASCII.GetBytes(entry));
            }
            FinishRdata(lengthAt);
        }

        public void WriteAddress(string host, IPAddress address, uint ttl)
        {
            WriteName(host);
            AppendU16((ushort)(address.AddressFamily == AddressFamily.InterNetworkV6 ? TypeAaaa : TypeA));
            AppendU16((ushort)(ClassIn | CacheFlushBit));
            AppendU32(ttl);
            byte[] raw = address.GetAddressBytes();
            AppendU16((ushort)raw.Length);
            _buf.AddRange(raw);
        }

        public byte[] ToArray() => _buf.ToArray();

        private const ushort CacheFlushBit = 0x8000;

        private int StartRdata()
        {
            AppendU16(0); // length placeholder
            return _buf.Count - 2;
        }

        private void FinishRdata(int lengthAt)
        {
            int length = _buf.Count - lengthAt - 2;
            _buf[lengthAt] = (byte)(length >> 8);
            _buf[lengthAt + 1] = (byte)length;
        }

        private void WriteName(string name)
        {
            foreach (string label in name.Split('.'))
            {
                if (label.Length is < 1 or > 63)
                {
                    throw new InvalidOperationException("DNS labels are 1-63 bytes");
                }
                AppendU8((byte)label.Length);
                _buf.AddRange(Encoding.ASCII.GetBytes(label));
            }
            AppendU8(0);
        }

        private void AppendU8(byte b) => _buf.Add(b);
        private void AppendU16(ushort v) { _buf.Add((byte)(v >> 8)); _buf.Add((byte)v); }
        private void AppendU32(uint v) { _buf.Add((byte)(v >> 24)); _buf.Add((byte)(v >> 16)); _buf.Add((byte)(v >> 8)); _buf.Add((byte)v); }
    }

    /// <summary>True when the packet carries a PTR question for the pinhole service — the
    /// trigger to answer. Questions from any source port count (legacy queries).</summary>
    public static bool AsksForOurService(ReadOnlySpan<byte> packet)
    {
        var reader = new Reader(packet);
        if (!reader.TryHeader(out int questions))
        {
            return false;
        }

        for (int i = 0; i < questions; i++)
        {
            if (!reader.TryName(out string name) || !reader.TryU16(out ushort qtype) || !reader.TryU16(out ushort qclass))
            {
                return false;
            }

            if (qtype == TypePtr && (qclass & 0x7FFF) is ClassIn or ClassAny
                && name.Equals(LanDiscovery.Service, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Parses one mDNS response into peers. A peer counts only with SRV, TXT, and
    /// at least one address record under the same instance name — the dialable minimum;
    /// a v2 announcer additionally yields the static key for key-pinned dialing.</summary>
    public static bool TryParsePeers(ReadOnlySpan<byte> packet, out IReadOnlyList<LanPeer> peers)
    {
        peers = Array.Empty<LanPeer>();
        var reader = new Reader(packet);
        if (!reader.TryHeader(out int questions, out int answers, out int authority, out int additional))
        {
            return false;
        }

        int recordCount = answers + authority + additional;
        if (recordCount > MaxRecords)
        {
            return false;
        }

        for (int i = 0; i < questions; i++)
        {
            if (!reader.TryName(out _) || !reader.TryU16(out _) || !reader.TryU16(out _))
            {
                return false;
            }
        }

        var records = new List<WireRecord>(recordCount);
        var owners = new List<string>(recordCount);
        for (int i = 0; i < recordCount; i++)
        {
            if (!reader.TryName(out string owner)
                || !reader.TryU16(out ushort type) || !reader.TryU16(out _)
                || !reader.TryU32(out _) || !reader.TryU16(out ushort rdLength)
                || !reader.TrySkip(rdLength))
            {
                return false;
            }

            records.Add(new WireRecord(type, reader.Position - rdLength, rdLength));
            owners.Add(owner);
        }

        string suffix = "." + LanDiscovery.Service;
        var found = new List<LanPeer>();
        for (int i = 0; i < records.Count; i++)
        {
            if (records[i].Type != TypePtr || !owners[i].Equals(LanDiscovery.Service, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var ptrReader = new Reader(packet);
            string instanceName = "";
            if (!ptrReader.TrySeek(records[i].RdataStart) || !ptrReader.TryName(out instanceName)
                || !instanceName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            LanPeer? peer = BuildPeer(packet, records, owners, instanceName[..^suffix.Length]);
            if (peer is not null)
            {
                found.Add(peer);
            }
        }

        peers = found;
        return found.Count > 0;
    }

    /// <summary>Collects the SRV/TXT/address records under one instance and assembles the
    /// peer — null when the dialable minimum is missing.</summary>
    private static LanPeer? BuildPeer(ReadOnlySpan<byte> packet, List<WireRecord> records, List<string> owners, string instance)
    {
        if (!LanDiscovery.IsHex16(instance))
        {
            return null;
        }

        string serviceInstance = instance + "." + LanDiscovery.Service;
        string? target = null;
        ushort port = 0;
        byte[]? txt = null;
        for (int i = 0; i < records.Count; i++)
        {
            if (!owners[i].Equals(serviceInstance, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            WireRecord r = records[i];
            switch (r.Type)
            {
                case TypeSrv when r.RdataLength >= 8:
                    port = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(r.RdataStart + 4, 2));
                    var nameReader = new Reader(packet);
                    target = nameReader.TrySeek(r.RdataStart + 6) && nameReader.TryName(out string t) ? t : null;
                    break;
                case TypeTxt:
                    txt = packet.Slice(r.RdataStart, r.RdataLength).ToArray();
                    break;
            }
        }

        if (target is null || port == 0 || txt is null)
        {
            return null;
        }

        // The address records live under the SRV target host name, not the service instance.
        var hostAddresses = new List<byte[]>();
        for (int i = 0; i < records.Count; i++)
        {
            if (owners[i].Equals(target, StringComparison.OrdinalIgnoreCase)
                && records[i].Type is TypeA or TypeAaaa)
            {
                hostAddresses.Add(packet.Slice(records[i].RdataStart, records[i].RdataLength).ToArray());
            }
        }

        if (hostAddresses.Count == 0)
        {
            return null;
        }

        NatHint hint = NatHint.Unknown;
        string? keyHex = null;
        if (txt is not null)
        {
            foreach ((string key, string value) in ParseTxt(txt))
            {
                if (key == "hint" && byte.TryParse(value, out byte h) && h <= 2)
                {
                    hint = (NatHint)h;
                }
                else if (key == "key")
                {
                    keyHex = value;
                }
            }
        }

        byte[]? staticKey = null;
        if (keyHex is { Length: 64 }
            && LanDiscovery.IsHex16(keyHex[..16]) && LanDiscovery.IsHex16(keyHex[16..32])
            && LanDiscovery.IsHex16(keyHex[32..48]) && LanDiscovery.IsHex16(keyHex[48..]))
        {
            staticKey = Convert.FromHexString(keyHex);
        }

        var endpoints = hostAddresses.Select(a => new IPEndPoint(new IPAddress(a), port)).ToList();
        return endpoints.Count == 0 ? null : new LanPeer(ulong.Parse(instance, System.Globalization.NumberStyles.HexNumber), endpoints, hint, staticKey);
    }

    private static IEnumerable<(string, string)> ParseTxt(byte[] rdata)
    {
        int pos = 0;
        while (pos < rdata.Length)
        {
            int len = rdata[pos++];
            if (pos + len > rdata.Length)
            {
                yield break; // malformed TXT tail: keep what parsed, drop the rest
            }

            string entry = Encoding.ASCII.GetString(rdata, pos, len);
            pos += len;
            int eq = entry.IndexOf('=');
            if (eq > 0)
            {
                yield return (entry[..eq], entry[(eq + 1)..]);
            }
        }
    }

    private ref struct Reader
    {
        private readonly ReadOnlySpan<byte> _packet;
        public int Position;

        public Reader(ReadOnlySpan<byte> packet) => _packet = packet;

        public bool TrySeek(int offset)
        {
            if (offset < 0 || offset >= _packet.Length)
            {
                return false;
            }
            Position = offset;
            return true;
        }

        public bool TrySkip(int bytes)
        {
            if (bytes < 0 || Position > _packet.Length - bytes)
            {
                return false;
            }
            Position += bytes;
            return true;
        }

        public bool TryHeader(out int questions) => TryHeader(out questions, out _, out _, out _);

        public bool TryHeader(out int questions, out int answers, out int authority, out int additional)
        {
            questions = answers = authority = additional = 0;
            if (_packet.Length < 12 || _packet[0] != 0 || _packet[1] != 0 || !TrySkip(4))
            {
                return false; // mDNS: transaction id zero
            }

            if (!TryU16(out ushort q) || !TryU16(out ushort a) || !TryU16(out ushort n) || !TryU16(out ushort d))
            {
                return false;
            }

            questions = q;
            answers = a;
            authority = n;
            additional = d;
            return true;
        }

        public bool TryU16(out ushort value)
        {
            value = 0;
            if (!TrySkip(2))
            {
                return false;
            }
            value = BinaryPrimitives.ReadUInt16BigEndian(_packet.Slice(Position - 2, 2));
            return true;
        }

        public bool TryU32(out uint value)
        {
            value = 0;
            if (!TrySkip(4))
            {
                return false;
            }
            value = BinaryPrimitives.ReadUInt32BigEndian(_packet.Slice(Position - 4, 4));
            return true;
        }

        /// <summary>Reads one domain name, chasing compression pointers. A pointer must
        /// point strictly backwards — forward pointers are how loops hide — and every hop
        /// lands on a smaller offset, so the jump cap is belt-and-braces.</summary>
        public bool TryName(out string name)
        {
            name = "";
            var labels = new List<string>();
            int pos = Position, jumps = 0, end = -1, totalLength = 0;
            while (true)
            {
                if (pos >= _packet.Length)
                {
                    return false;
                }

                byte first = _packet[pos];
                if (first == 0)
                {
                    pos++;
                    if (end < 0)
                    {
                        end = pos;
                    }
                    break;
                }

                if ((first & 0xC0) == 0xC0)
                {
                    if (pos + 1 >= _packet.Length || ++jumps > MaxNameJumps)
                    {
                        return false;
                    }

                    int target = ((first & 0x3F) << 8) | _packet[pos + 1];
                    if (target >= pos)
                    {
                        return false;
                    }

                    if (end < 0)
                    {
                        end = pos + 2;
                    }
                    pos = target;
                    continue;
                }

                if (first > 63 || pos + 1 + first > _packet.Length)
                {
                    return false;
                }

                labels.Add(Encoding.ASCII.GetString(_packet.Slice(pos + 1, first)));
                totalLength += first + 1;
                if (totalLength > MaxNameBytes)
                {
                    return false;
                }

                pos += 1 + first;
            }

            Position = end;
            name = string.Join('.', labels);
            return true;
        }
    }
}
