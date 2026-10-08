using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
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
/// to build a v2 connection string. The handshake proves possession of the advertised
/// key; the announcement itself is untrusted discovery, not a verified device identity.
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
    private int _disposed;

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
        long nextAddressCheck = Environment.TickCount64 + 2_000;
        string addressSet = AddressSet();
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

                bool changed = false;
                if (Environment.TickCount64 >= nextAddressCheck)
                {
                    nextAddressCheck = Environment.TickCount64 + 2_000;
                    string current = AddressSet();
                    changed = current != addressSet;
                    addressSet = current;
                }
                if (changed || Environment.TickCount64 >= nextHeartbeat)
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
        IReadOnlyList<IPAddress> addresses = AnnouncementAddresses(_addresses());
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
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
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

    private string AddressSet() => string.Join(",", _addresses().Select(a => a.ToString()).Order(StringComparer.Ordinal));

    /// <summary>Reserve room for both families and link-local fallback before filling
    /// the remaining slots. A machine with many IPv4/VPN addresses must not lose IPv6.</summary>
    internal static IReadOnlyList<IPAddress> AnnouncementAddresses(IReadOnlyList<IPAddress> addresses)
    {
        var all = addresses.Distinct().ToArray();
        var selected = new List<IPAddress>(MaxAddresses);
        foreach (IPAddress? ip in new[]
        {
            all.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork),
            all.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6 && !a.IsIPv6LinkLocal),
            all.FirstOrDefault(a => a.IsIPv6LinkLocal),
        })
        {
            if (ip is not null && !selected.Contains(ip)) selected.Add(ip);
        }
        foreach (IPAddress ip in all)
            if (selected.Count < MaxAddresses && !selected.Contains(ip)) selected.Add(ip);
        return selected;
    }

    // ------------------------------------------------------------------ browsing

    /// <summary>Asks the link who else is a pinhole node and collects answers for one
    /// window — both responses to the query and unsolicited announcements count. Two
    /// queries a second apart cover ordinary loss.</summary>
    public static async Task<IReadOnlyList<LanPeer>> BrowseAsync(ILanChannel channel, TimeSpan window, CancellationToken ct)
    {
        byte[] query = BuildQuery();
        using var queriesStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        Task queries = Task.Run(async () =>
        {
            try
            {
                channel.Send(query, null);
                await Task.Delay(1000, queriesStop.Token).ConfigureAwait(false);
                channel.Send(query, null);
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException or OperationCanceledException) { }
        }, CancellationToken.None);

        var peers = new Dictionary<ulong, LanPeer>();
        byte[] buf = new byte[1500];
        long deadline = Environment.TickCount64 + (long)window.TotalMilliseconds;
        while (Environment.TickCount64 < deadline && !ct.IsCancellationRequested)
        {
            long remaining = deadline - Environment.TickCount64;
            try
            {
                if (channel.TryReceive(buf, out int len, out IPEndPoint from, (int)Math.Clamp(remaining, 1, 500))
                    && DnsCodec.TryParsePeers(buf.AsSpan(0, len), out IReadOnlyList<LanPeer> found))
                {
                    foreach (LanPeer peer in found)
                    {
                        LanPeer scoped = ScopePeer(peer, channel.LastReceiveIpv6Scope > 0
                            ? channel.LastReceiveIpv6Scope
                            : from.Address.AddressFamily == AddressFamily.InterNetworkV6 ? from.Address.ScopeId : 0);
                        if (!peers.TryGetValue(peer.PeerId, out LanPeer? existing))
                        {
                            if (peers.Count < 256) peers.Add(peer.PeerId, scoped);
                        }
                        else if (KeysEqual(existing.StaticKey, scoped.StaticKey))
                            peers[peer.PeerId] = existing with { Endpoints = existing.Endpoints.Concat(scoped.Endpoints).Distinct().Take(16).ToArray() };
                    }
                }
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
            {
                break;
            }
        }

        queriesStop.Cancel();
        await queries.ConfigureAwait(false);
        return peers.Values.ToArray();
    }

    internal static LanPeer ScopePeer(LanPeer peer, long scope) => scope <= 0 ? peer : peer with
    {
        Endpoints = peer.Endpoints.Select(ep => ep.Address.IsIPv6LinkLocal && ep.Address.ScopeId == 0
            ? new IPEndPoint(new IPAddress(ep.Address.GetAddressBytes(), scope), ep.Port) : ep).ToArray(),
    };

    private static bool KeysEqual(byte[]? left, byte[]? right) => left is null ? right is null : right is not null && left.AsSpan().SequenceEqual(right);

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

    /// <summary>The local IPv6 interface index for the last received packet, including
    /// IPv4 packets carrying AAAA records. Zero when the channel cannot determine it.</summary>
    long LastReceiveIpv6Scope => 0;
}

/// <summary>Shared-port IPv4 and IPv6 mDNS sockets, joined on each active multicast
/// interface. An unavailable family or membership does not disable the others.</summary>
internal sealed class MulticastLanChannel : ILanChannel
{
    public static readonly IPEndPoint GroupV4 = new(IPAddress.Parse("224.0.0.251"), 5353);
    public static readonly IPEndPoint GroupV6 = new(IPAddress.Parse("ff02::fb"), 5353);
    internal sealed record Interface(IPAddress? V4, int V4Index, int V6Index);
    private readonly object _gate = new();
    private readonly Socket? _v4, _v6;
    private readonly Func<IReadOnlyList<Interface>> _interfaces;
    private readonly IPEndPoint _groupV4, _groupV6;
    private readonly HashSet<IPAddress> _joinedV4 = [];
    private readonly HashSet<int> _joinedV6 = [];
    private IReadOnlyList<Interface> _current = [];
    private long _nextRefresh;
    private int _dirty = 1, _disposed;
    public long LastReceiveIpv6Scope { get; private set; }

    public MulticastLanChannel() : this(ReadInterfaces, GroupV4, GroupV6) { }

    // Alternate endpoints/port let tests exercise the production dual-socket receive
    // path using actual loopback UDP, without multicast availability in hosted runners.
    internal MulticastLanChannel(Func<IReadOnlyList<Interface>> interfaces, IPEndPoint groupV4, IPEndPoint groupV6, int? bindPort = null)
    {
        _interfaces = interfaces;
        _groupV4 = groupV4;
        _groupV6 = groupV6;
        _v4 = Bind(AddressFamily.InterNetwork, bindPort ?? groupV4.Port);
        _v6 = Bind(AddressFamily.InterNetworkV6, bindPort ?? groupV6.Port);
        if (_v4 is null && _v6 is null) throw new SocketException((int)SocketError.NetworkUnreachable);
        RefreshInterfaces();
        NetworkChange.NetworkAddressChanged += OnAddressChanged;
    }

    internal IPEndPoint? LocalV4 => (IPEndPoint?)_v4?.LocalEndPoint;
    internal IPEndPoint? LocalV6 => (IPEndPoint?)_v6?.LocalEndPoint;

    private static Socket? Bind(AddressFamily family, int port)
    {
        Socket? socket = null;
        try
        {
            socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
            if (family == AddressFamily.InterNetworkV6) socket.DualMode = false;
            var level = family == AddressFamily.InterNetwork ? SocketOptionLevel.IP : SocketOptionLevel.IPv6;
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            socket.MulticastLoopback = true;
            socket.SetSocketOption(level, SocketOptionName.MulticastTimeToLive, 255);
            socket.SetSocketOption(level, SocketOptionName.PacketInformation, true);
            socket.Bind(new IPEndPoint(family == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, port));
            return socket;
        }
        catch (Exception ex) when (ex is SocketException or NotSupportedException)
        {
            socket?.Dispose();
            return null;
        }
    }

    private void OnAddressChanged(object? sender, EventArgs e) => Interlocked.Exchange(ref _dirty, 1);

    internal void RefreshInterfaces(bool force = false)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            if (Interlocked.Exchange(ref _dirty, 0) == 0 && !force && Environment.TickCount64 < _nextRefresh) return;
            _nextRefresh = Environment.TickCount64 + 5_000;
            try { _current = _interfaces().Distinct().Take(32).ToArray(); }
            catch (NetworkInformationException) { return; }
            var v4 = _current.Where(i => i.V4 is not null).Select(i => i.V4!).ToHashSet();
            var v6 = _current.Where(i => i.V6Index > 0).Select(i => i.V6Index).ToHashSet();
            if (_v4 is not null)
            {
                foreach (IPAddress ip in _joinedV4.Except(v4).ToArray())
                {
                    try { _v4.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.DropMembership, new MulticastOption(GroupV4.Address, ip)); } catch (SocketException) { }
                    _joinedV4.Remove(ip);
                }
                foreach (IPAddress ip in v4.Except(_joinedV4))
                {
                    try { _v4.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, new MulticastOption(GroupV4.Address, ip)); _joinedV4.Add(ip); } catch (SocketException) { }
                }
            }
            if (_v6 is not null)
            {
                foreach (int index in _joinedV6.Except(v6).ToArray())
                {
                    try { _v6.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.DropMembership, new IPv6MulticastOption(GroupV6.Address, index)); } catch (SocketException) { }
                    _joinedV6.Remove(index);
                }
                foreach (int index in v6.Except(_joinedV6))
                {
                    try { _v6.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership, new IPv6MulticastOption(GroupV6.Address, index)); _joinedV6.Add(index); } catch (SocketException) { }
                }
            }
        }
    }

    public void Send(ReadOnlySpan<byte> packet, IPEndPoint? unicastTo)
    {
        RefreshInterfaces();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed != 0, this);
            if (unicastTo is not null)
            {
                Socket? target = unicastTo.AddressFamily == AddressFamily.InterNetwork ? _v4 : _v6;
                target?.SendTo(packet, SocketFlags.None, unicastTo);
                return;
            }
            foreach (IPAddress ip in _joinedV4)
            {
                try
                {
                    _v4!.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, ip.GetAddressBytes());
                    _v4.SendTo(packet, SocketFlags.None, _groupV4);
                }
                catch (SocketException) { } // one failed route cannot suppress other links
            }
            foreach (int index in _joinedV6)
            {
                try
                {
                    _v6!.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, index);
                    _v6.SendTo(packet, SocketFlags.None, new IPEndPoint(new IPAddress(_groupV6.Address.GetAddressBytes(), index), _groupV6.Port));
                }
                catch (SocketException) { }
            }
        }
    }

    public bool TryReceive(byte[] buffer, out int length, out IPEndPoint from, int timeoutMs)
    {
        RefreshInterfaces();
        var readable = new List<Socket>(2);
        if (_v4 is not null) readable.Add(_v4);
        if (_v6 is not null) readable.Add(_v6);
        Socket.Select(readable, null, null, (int)Math.Clamp((long)timeoutMs * 1000, 0, int.MaxValue));
        length = 0;
        from = new IPEndPoint(IPAddress.Any, 0);
        LastReceiveIpv6Scope = 0;
        if (readable.Count == 0) return false;
        Socket socket = readable[0];
        EndPoint remote = new IPEndPoint(socket.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
        SocketFlags flags = SocketFlags.None;
        length = socket.ReceiveMessageFrom(buffer, 0, buffer.Length, ref flags, ref remote, out IPPacketInformation info);
        from = (IPEndPoint)remote;
        if (socket.AddressFamily == AddressFamily.InterNetworkV6) LastReceiveIpv6Scope = info.Interface;
        else
        {
            lock (_gate) LastReceiveIpv6Scope = _current.FirstOrDefault(i => i.V4Index == info.Interface)?.V6Index ?? 0;
        }
        if (from.Address.IsIPv6LinkLocal && from.Address.ScopeId == 0 && LastReceiveIpv6Scope > 0)
            from = new IPEndPoint(new IPAddress(from.Address.GetAddressBytes(), LastReceiveIpv6Scope), from.Port);
        if ((flags & SocketFlags.Truncated) != 0) { length = 0; return false; }
        return true;
    }

    internal static IReadOnlyList<Interface> ReadInterfaces()
    {
        var interfaces = new List<Interface>();
        try
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || !nic.SupportsMulticast || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                try
                {
                    IPInterfaceProperties properties = nic.GetIPProperties();
                    int v4 = nic.Supports(NetworkInterfaceComponent.IPv4) ? properties.GetIPv4Properties()?.Index ?? 0 : 0;
                    int v6 = nic.Supports(NetworkInterfaceComponent.IPv6) ? properties.GetIPv6Properties()?.Index ?? 0 : 0;
                    var addresses = properties.UnicastAddresses.Select(a => a.Address)
                        .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a) && !a.Equals(IPAddress.Any)).ToArray();
                    if (addresses.Length == 0 && v6 > 0) interfaces.Add(new Interface(null, v4, v6));
                    foreach (IPAddress address in addresses) interfaces.Add(new Interface(address, v4, v6));
                }
                catch (NetworkInformationException) { }
            }
        }
        catch (NetworkInformationException) { }
        return interfaces;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            NetworkChange.NetworkAddressChanged -= OnAddressChanged;
            _v4?.Dispose();
            _v6?.Dispose();
        }
    }
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
                && (records[i].Type == TypeA && records[i].RdataLength == 4
                    || records[i].Type == TypeAaaa && records[i].RdataLength == 16))
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

        var endpoints = hostAddresses.Select(a => new IPAddress(a))
            .Where(a => !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any) && !a.IsIPv6Multicast
                && !(a.AddressFamily == AddressFamily.InterNetwork && a.GetAddressBytes()[0] is >= 224))
            .Distinct().Take(16).Select(a => new IPEndPoint(a, port)).ToList();
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
