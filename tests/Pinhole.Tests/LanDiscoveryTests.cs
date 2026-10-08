using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Pinhole;
using Xunit;

namespace Pinhole.Tests;

/// <summary>mDNS LAN discovery: announcements, queries, browsing, and a parser that
/// survives hostile bytes. All traffic rides an in-process channel — no OS multicast in CI.</summary>
public sealed class LanDiscoveryTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    /// <summary>The test channel: a loopback UDP socket whose "group" is the other side's
    /// endpoint, recording everything sent so goodbye/query behavior is observable.</summary>
    private sealed class DirectChannel : ILanChannel
    {
        public readonly Socket Sock;
        public readonly List<(byte[] Packet, IPEndPoint? To)> Sent = new();
        public IPEndPoint Group = new(IPAddress.Loopback, 1);

        public long LastReceiveIpv6Scope { get; set; }
        public DirectChannel(AddressFamily family = AddressFamily.InterNetwork)
        {
            Sock = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
            Sock.Bind(new IPEndPoint(family == AddressFamily.InterNetwork ? IPAddress.Loopback : IPAddress.IPv6Loopback, 0));
            Group = new IPEndPoint(family == AddressFamily.InterNetwork ? IPAddress.Loopback : IPAddress.IPv6Loopback, 1);
        }

        public IPEndPoint Local => (IPEndPoint)Sock.LocalEndPoint!;

        public void Send(ReadOnlySpan<byte> packet, IPEndPoint? unicastTo)
        {
            lock (Sent)
            {
                Sent.Add((packet.ToArray(), unicastTo));
            }
            Sock.SendTo(packet, SocketFlags.None, unicastTo ?? Group);
        }

        public bool TryReceive(byte[] buffer, out int length, out IPEndPoint from, int timeoutMs)
        {
            if (!Sock.Poll(timeoutMs * 1000, SelectMode.SelectRead))
            {
                length = 0;
                from = new IPEndPoint(IPAddress.Any, 0);
                return false;
            }

            EndPoint remote = new IPEndPoint(Sock.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, 0);
            length = Sock.ReceiveFrom(buffer, ref remote);
            from = (IPEndPoint)remote;
            return true;
        }

        public void Dispose() => Sock.Dispose();
    }

    [Fact]
    public async Task Announcer_IsDiscoverable_QueryAndUnsolicited()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        ulong peerId = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8)) | 1;
        var announcedAddress = new IPAddress(new byte[] { 192, 168, 1, 42 });
        using var announcerSide = new DirectChannel();
        using var browserSide = new DirectChannel();
        announcerSide.Group = browserSide.Local; // "the group" is wherever the other side listens
        browserSide.Group = announcerSide.Local;

        using var announcer = new LanDiscovery(
            announcerSide, peerId, key, () => [announcedAddress], port: 7777, NatHint.Cone);

        // The browser's window covers both paths: its query provoking a unicast answer,
        // and the startup announcements that arrive unsolicited.
        IReadOnlyList<LanPeer> found = await LanDiscovery.BrowseAsync(browserSide, TimeSpan.FromSeconds(2), CancellationToken.None);
        LanPeer peer = Assert.Single(found);
        Assert.Equal(peerId, peer.PeerId);
        Assert.Equal(NatHint.Cone, peer.NatHint);
        Assert.Equal(key, peer.StaticKey);
        IPEndPoint ep = Assert.Single(peer.Endpoints);
        Assert.Equal(new IPEndPoint(announcedAddress, 7777), ep);

        // The discovered string is a fully dialable v2 string: same key pin, same endpoint.
        ConnectionString cs = peer.ToConnectionString();
        Assert.Equal(peerId, cs.PeerId);
        Assert.Equal(key, cs.StaticKey);
        PinholeCandidate candidate = Assert.Single(cs.Candidates);
        Assert.Equal(new IPEndPoint(announcedAddress, 7777), candidate.Address);
    }

    [Fact]
    public void Query_ForTheService_IsRecognized_GarbageIsNot()
    {
        var w = new DnsCodec.Writer();
        w.Header(flags: 0x0000, questions: 1, answers: 0, 0, 0);
        w.WritePtrQuestion(LanDiscovery.Service);
        byte[] query = w.ToArray();
        Assert.True(DnsCodec.AsksForOurService(query));

        // A query for some other service, or random bytes, must not trigger answers.
        var other = new DnsCodec.Writer();
        other.Header(flags: 0x0000, questions: 1, answers: 0, 0, 0);
        other.WritePtrQuestion("_http._tcp.local");
        Assert.False(DnsCodec.AsksForOurService(other.ToArray()));
        Assert.False(DnsCodec.AsksForOurService(RandomNumberGenerator.GetBytes(64)));
    }

    [Fact]
    public async Task Dispose_SendsTheGoodbye()
    {
        using var side = new DirectChannel();
        using var announcer = new LanDiscovery(
            side, 0x1122334455667788, RandomNumberGenerator.GetBytes(32), () => [IPAddress.Parse("192.168.1.5")], 1, NatHint.Unknown);
        await TestPoll.UntilAsync(Timeout, () =>
        {
            lock (side.Sent) { return side.Sent.Count >= 3; }
        }); // all three startup announcements are out; nothing else sends until the heartbeat

        int before;
        lock (side.Sent) { before = side.Sent.Count; }
        announcer.Dispose();
        int after;
        lock (side.Sent) { after = side.Sent.Count; }

        Assert.Equal(before + 1, after); // exactly the goodbye went out
        byte[] goodbye;
        lock (side.Sent) { goodbye = side.Sent[^1].Packet; }
        Assert.True(DnsCodec.TryParsePeers(goodbye, out IReadOnlyList<LanPeer> peers));
        Assert.Equal(0x1122334455667788UL, Assert.Single(peers).PeerId);
    }

    [Fact]
    public async Task Parser_EveryTruncationAndCorruption_NeverThrows()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        using var side = new DirectChannel();
        using var announcer = new LanDiscovery(
            side, 0xaabbccddeeff0011, key, () => [new IPAddress(new byte[] { 10, 1, 2, 3 })], 4242, NatHint.Symmetric);
        await Task.Delay(200);

        byte[] real;
        lock (side.Sent) { real = side.Sent[0].Packet; }
        Assert.True(DnsCodec.TryParsePeers(real, out _));

        for (int cut = 0; cut <= real.Length; cut++)
        {
            DnsCodec.TryParsePeers(real.AsSpan(0, cut), out _); // any outcome, no exception
        }

        var rng = new Random(20261005);
        byte[] mutant = new byte[real.Length];
        for (int round = 0; round < 2_000; round++)
        {
            real.AsSpan().CopyTo(mutant);
            int hits = 1 + rng.Next(4);
            for (int i = 0; i < hits; i++)
            {
                mutant[rng.Next(mutant.Length)] = (byte)rng.Next(256);
            }
            DnsCodec.TryParsePeers(mutant, out _);
            DnsCodec.AsksForOurService(mutant);
        }
    }

    [Fact]
    public void Parser_ForwardAndLoopingPointers_AreRefused()
    {
        var w = new DnsCodec.Writer();
        w.Header(flags: 0x8400, questions: 0, answers: 1, 0, 0);
        w.WritePtr(LanDiscovery.Service, "0123456789abcdef", 120);
        byte[] packet = w.ToArray();

        // A self-pointing compression pointer (offset 0xC0 | 0) where a name starts: the
        // canonical infinite loop. The parser must refuse, not spin.
        byte[] loop = (byte[])packet.Clone();
        int rdata = FindPtrRdata(loop);
        loop[rdata] = 0xC0;
        loop[rdata + 1] = (byte)rdata;
        Assert.False(DnsCodec.TryParsePeers(loop, out _));

        // Pointer chasing backwards forever (two mutually-referencing names) is bounded too.
        byte[] zigzag = (byte[])packet.Clone();
        zigzag[rdata] = 0xC0;
        zigzag[rdata + 1] = 0x0D; // points near the header; the walk must terminate
        DnsCodec.TryParsePeers(zigzag, out _);
    }

    private static int FindPtrRdata(byte[] packet)
    {
        // Walk past the header and the PTR owner name to the rdata start: first byte after
        // the fixed 10-byte record tail (type+class+ttl+rdlength) whose rdlength equals
        // the remaining instance-name bytes. Simpler: hunt for the record's rdlength slot
        // by re-deriving it — the owner is "_pinhole._udp.local", 22 wire bytes + header 12.
        int owner = 12;
        int pos = owner;
        while (packet[pos] != 0) pos += 1 + packet[pos];
        return pos + 1 + 10; // root label + type/class/ttl/rdlength, rdata starts here
    }

    [Fact]
    public async Task Ipv6OnlyAnnouncement_BrowsesAndDialsEncryptedOverIpv6()
    {
        Assert.True(Socket.OSSupportsIPv6);
        using var side = new DirectChannel(AddressFamily.InterNetworkV6);
        using var browser = new DirectChannel(AddressFamily.InterNetworkV6);
        side.Group = browser.Local;
        browser.Group = side.Local;
        var options = new PinholeOptions
        {
            Bind = new IPEndPoint(IPAddress.IPv6Loopback, 0),
            StunServers = [], IrohRelayUrls = [], EnableNetworkWatch = false,
            EnablePortMapping = false, PublishIrohAddress = false, EnableLanDiscovery = false,
            ReceiveBufferCapacity = 4,
        };
        await using var listener = await PinholeNode.BindAsync(options);
        await using var dialer = await PinholeNode.BindAsync(options);
        using var announcer = new LanDiscovery(side, listener.PeerId, listener.StaticPublicKey,
            () => [IPAddress.IPv6Loopback], listener.LocalPort, NatHint.Unknown);
        LanPeer peer = Assert.Single(await LanDiscovery.BrowseAsync(browser, TimeSpan.FromSeconds(1.2), CancellationToken.None));
        Assert.Equal(IPAddress.IPv6Loopback, Assert.Single(peer.Endpoints).Address);
        Task<PinholeConnection> accept = listener.AcceptAsync();
        await using var outgoing = await dialer.ConnectAsync(peer.ToConnectionString().ToString()).WaitAsync(Timeout);
        await using var incoming = await accept.WaitAsync(Timeout);
        Assert.True(outgoing.IsEncrypted);
        Assert.Equal(PathKind.Direct, outgoing.Path.Kind);
        Assert.NotNull(outgoing.Path.Remote);
        Assert.Equal(AddressFamily.InterNetworkV6, outgoing.Path.Remote.AddressFamily);
        outgoing.Send([42, 73]);
        ReadOnlyMemory<byte>? received = await incoming.ReceiveAsync().AsTask().WaitAsync(Timeout);
        Assert.NotNull(received);
        Assert.Equal(new byte[] { 42, 73 }, received.Value.ToArray());
    }

    [Fact]
    public async Task Browse_MergesBothFamiliesAndScopesLinkLocal_WithoutReplacingTheKey()
    {
        using var sender = new DirectChannel();
        using var browser = new DirectChannel { LastReceiveIpv6Scope = 42 };
        sender.Group = browser.Local;
        browser.Group = sender.Local;
        byte[] key = RandomNumberGenerator.GetBytes(32);
        const ulong id = 0x1234567812345678;
        sender.Send(Announcement(id, key, IPAddress.Parse("192.168.4.2")), null);
        sender.Send(Announcement(id, key, IPAddress.Parse("fe80::beef")), null);
        sender.Send(Announcement(id, key, IPAddress.Parse("2001:db8::4")), null);
        sender.Send(Announcement(id, RandomNumberGenerator.GetBytes(32), IPAddress.Parse("192.168.4.99")), null);
        LanPeer found = Assert.Single(await LanDiscovery.BrowseAsync(browser, TimeSpan.FromMilliseconds(250), CancellationToken.None));
        Assert.Equal(key, found.StaticKey);
        Assert.Equal(3, found.Endpoints.Count);
        Assert.Contains(found.Endpoints, ep => ep.Address.IsIPv6LinkLocal && ep.Address.ScopeId == 42);
        Assert.DoesNotContain(found.Endpoints, ep => ep.Address.Equals(IPAddress.Parse("192.168.4.99")));
        Assert.All(ConnectionString.Parse(found.ToConnectionString().ToString()).Candidates.Where(c => c.Address.Address.IsIPv6LinkLocal),
            c => Assert.Equal(0, c.Address.Address.ScopeId)); // local scope never goes in a ticket
    }

    private static byte[] Announcement(ulong id, byte[] key, IPAddress address)
    {
        var w = new DnsCodec.Writer();
        string instance = LanDiscovery.IdText(id);
        w.Header(0x8400, 0, 4, 0, 0);
        w.WritePtr(LanDiscovery.Service, instance, 120);
        w.WriteSrv(LanDiscovery.Service, instance, LanDiscovery.HostOf(id), 7777, 120);
        w.WriteTxt(LanDiscovery.Service, instance, [("key", Convert.ToHexString(key))], 120);
        w.WriteAddress(LanDiscovery.HostOf(id), address, 120);
        return w.ToArray();
    }

    [Fact]
    public void AnnouncementLimit_KeepsIpv6AndLinkLocalDespiteManyIpv4Addresses()
    {
        IPAddress[] input = Enumerable.Range(1, 8).Select(i => IPAddress.Parse($"10.0.0.{i}"))
            .Concat([IPAddress.Parse("2001:db8::1"), IPAddress.Parse("fe80::2%7")]).ToArray();
        IReadOnlyList<IPAddress> selected = LanDiscovery.AnnouncementAddresses(input);
        Assert.Equal(4, selected.Count);
        Assert.Contains(IPAddress.Parse("2001:db8::1"), selected);
        Assert.Contains(IPAddress.Parse("fe80::2%7"), selected);
        Assert.Contains(selected, a => a.AddressFamily == AddressFamily.InterNetwork);
    }

    [Fact]
    public async Task AddressChanges_AnnouncePromptlyRatherThanWaitingForHeartbeat()
    {
        using var side = new DirectChannel();
        using var sink = new DirectChannel();
        side.Group = sink.Local;
        IPAddress[] addresses = [IPAddress.Parse("10.1.0.2")];
        using var announcer = new LanDiscovery(side, 123, null, () => Volatile.Read(ref addresses), 7070, NatHint.Unknown);
        await TestPoll.UntilAsync(Timeout, () => { lock (side.Sent) return side.Sent.Count >= 3; });
        Volatile.Write(ref addresses, [IPAddress.Parse("2001:db8::9")]);
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(6), () =>
        {
            lock (side.Sent)
                return side.Sent.Any(p => DnsCodec.TryParsePeers(p.Packet, out var peers)
                    && peers.Any(peer => peer.Endpoints.Any(ep => ep.Address.Equals(IPAddress.Parse("2001:db8::9")))));
        });
    }

    [Fact]
    public void Parser_InvalidAddressRecordSizesAndNonUnicast_DoNotYieldDialablePeers()
    {
        foreach (IPAddress address in new[] { IPAddress.Any, IPAddress.IPv6Any, IPAddress.Parse("ff02::1"), IPAddress.Parse("224.1.2.3") })
            Assert.False(DnsCodec.TryParsePeers(Announcement(99, new byte[32], address), out _));
        byte[] packet = Announcement(99, new byte[32], IPAddress.Parse("2001:db8::1"));
        // The last AAAA record advertises 15 bytes and supplies exactly that amount.
        packet[^18] = 0;
        packet[^17] = 15;
        Assert.False(DnsCodec.TryParsePeers(packet.AsSpan(0, packet.Length - 1), out _));
    }

    [Fact]
    public async Task DefaultNode_AnnouncesItsAuthenticatedLanTicket()
    {
        using var announcerSide = new DirectChannel();
        using var browserSide = new DirectChannel();
        announcerSide.Group = browserSide.Local;
        browserSide.Group = announcerSide.Local;
        await using var node = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [], IrohRelayUrls = [], EnableNetworkWatch = false,
            EnablePortMapping = false, PublishIrohAddress = false,
            LanChannelFactory = () => announcerSide,
        });
        IReadOnlyList<LanPeer> found = await LanDiscovery.BrowseAsync(browserSide, TimeSpan.FromSeconds(2), CancellationToken.None);
        LanPeer peer = Assert.Single(found);
        Assert.Equal(node.PeerId, peer.PeerId);
        Assert.Equal(node.StaticPublicKey, peer.StaticKey);
        Assert.Equal(node.NatHint, peer.NatHint);
        Assert.All(peer.Endpoints, ep => Assert.Equal(node.LocalPort, ep.Port));

        await using var dialer = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [], IrohRelayUrls = [], EnableNetworkWatch = false,
            EnablePortMapping = false, PublishIrohAddress = false, EnableLanDiscovery = false,
        });
        Task<PinholeConnection> incoming = node.AcceptAsync();
        await using PinholeConnection outgoing = await dialer.ConnectAsync(peer.ToConnectionString().ToString()).WaitAsync(Timeout);
        await using PinholeConnection accepted = await incoming.WaitAsync(Timeout);
        Assert.True(outgoing.IsEncrypted);
        Assert.True(accepted.IsEncrypted);
        Assert.Equal(PathKind.Direct, outgoing.Path.Kind);
    }

    [Fact]
    public async Task LanOptOut_DoesNotCreateAnAnnouncementChannel()
    {
        int created = 0;
        await using var node = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [], IrohRelayUrls = [], EnableNetworkWatch = false,
            EnablePortMapping = false, PublishIrohAddress = false, EnableLanDiscovery = false,
            LanChannelFactory = () => { Interlocked.Increment(ref created); return new DirectChannel(); },
        });
        Assert.Equal(0, created);
        Assert.NotNull(node.StaticPublicKey);
    }

    [Fact]
    public async Task DefaultLanDiscovery_BindsAndDialsWhenMulticastIsUnavailable()
    {
        // Inject the OS failure so every runner exercises best-effort default discovery.
        await using PinholeNode announcing = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [],
            Relays = [],
            IrohRelayUrls = [],
            EnableNetworkWatch = false,
            EnablePortMapping = false,
            PublishIrohAddress = false,
            LanChannelFactory = () => throw new SocketException((int)SocketError.NetworkUnreachable),
        });
        await using PinholeNode other = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [],
            Relays = [],
            IrohRelayUrls = [],
            EnableNetworkWatch = false,
            EnablePortMapping = false,
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
        });
        Assert.NotNull(announcing.StaticPublicKey);

        _ = other.AcceptAsync();
        PinholeConnection conn = await announcing.ConnectAsync(other.ConnectionString).WaitAsync(Timeout);
        Assert.True(conn.IsEncrypted);
    }
}
