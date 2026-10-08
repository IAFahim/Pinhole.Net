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
        public readonly Socket Sock = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        public readonly List<(byte[] Packet, IPEndPoint? To)> Sent = new();
        public IPEndPoint Group = new(IPAddress.Loopback, 1);

        public DirectChannel() => Sock.Bind(new IPEndPoint(IPAddress.Loopback, 0));

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

            EndPoint remote = new IPEndPoint(IPAddress.Any, 0);
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
            side, 0x1122334455667788, RandomNumberGenerator.GetBytes(32), () => [IPAddress.Any], 1, NatHint.Unknown);
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
