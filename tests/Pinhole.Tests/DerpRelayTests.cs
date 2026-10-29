using System.Buffers.Binary;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Pinhole.Tests;

public sealed class DerpRelayTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(12);
    private static PinholeOptions Options(InMemoryDerpRelay relay) => new()
    {
        StunServers = [], Relays = [], IrohRelayUrls = [], DerpRelayUrls = [relay.Url],
        DerpWebSocketFactory = relay.ConnectAsync, PublishIrohAddress = false,
        EnableDirectUdp = false, EnableTcpTransport = false, EnableInterfaceCandidates = false,
        EnableNetworkWatch = false, EnablePortMapping = false, EnableLanDiscovery = false,
        ConnectTimeout = Timeout, BindProbeBudget = TimeSpan.FromSeconds(1), ReceiveBufferCapacity = 32,
    };

    private static string RelayOnly(PinholeNode node)
    {
        var ticket = ConnectionString.Parse(node.ConnectionString);
        return new ConnectionString(ticket.PeerId,
            ticket.Candidates.Where(c => c.Kind is CandidateKind.IrohRelay or CandidateKind.DerpRelay).ToArray(),
            staticKey: ticket.StaticKey, endpointKey: ticket.EndpointKey).ToString();
    }

    private static async Task Exchange(PinholeConnection from, PinholeConnection to, string message)
    {
        from.Send(Encoding.UTF8.GetBytes(message));
        Assert.Equal(message, Encoding.UTF8.GetString((await to.ReceiveAsync().AsTask().WaitAsync(Timeout))!.Value.Span));
    }

    [Fact]
    public void AuthenticationBox_MatchesIndependentLibsodiumVector_AndRejectsTampering()
    {

        byte[] secret = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] peer = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        byte[] nonce = Convert.FromHexString("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");
        byte[] message = Convert.FromHexString(
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a" +
            "1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057" +
            "e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040" +
            "e082f937763848645e0705");
        byte[] expected = Convert.FromHexString(
            "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4" +
            "476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738" +
            "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de" +
            "56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5");
        byte[] key = DerpBox.SharedKey(secret, peer);
        byte[] box = DerpBox.Seal(key, message, nonce);
        Assert.Equal(expected, box[24..]);
        Assert.Equal(message, DerpBox.Open(key, box));
        box[24] ^= 1;
        Assert.Throws<InvalidDataException>(() => DerpBox.Open(key, box));
        Assert.Throws<CryptographicException>(() => DerpBox.SharedKey(secret, new byte[32]));
    }

    [Fact]
    public void ConnectionString_DistinguishesDerpFromIroh_AndRejectsUnsafeUrls()
    {
        var key = new NodeIdentity().PublicKey;
        var candidate = new PinholeCandidate(CandidateKind.DerpRelay, new(IPAddress.None, 0),
            RelayUrl: new("https://tc304a.ipn.dev/"), RelayKey: key);
        string ticket = new ConnectionString(42, [candidate], staticKey: key).ToString();
        var decoded = ConnectionString.Parse(ticket).Candidates.Single();
        Assert.Equal(CandidateKind.DerpRelay, decoded.Kind);
        Assert.Equal(candidate.RelayUrl, decoded.RelayUrl);
        Assert.Equal(key, decoded.RelayKey);
        Assert.Throws<InvalidOperationException>(() => new ConnectionString(42,
            [candidate with { RelayUrl = new("http://example.com/") }]).ToString());
        Assert.Throws<InvalidOperationException>(() => new ConnectionString(42,
            [candidate with { RelayKey = new byte[31] }]).ToString());
        for (int i = 0; i < ticket.Length; i++) Assert.False(ConnectionString.TryParse(ticket[..i], out _));
    }

    [Fact]
    public async Task Protocol_StreamsAcrossWebSocketMessages_AnswersPings_AndHonorsRateLimits()
    {
        using var relay = new InMemoryDerpRelay { BytesPerSecond = 1, Burst = 64 };
        var identity = new NodeIdentity();
        using var client = new DerpRelay(relay.Url, identity, relay.ConnectAsync);
        await client.StartAsync().WaitAsync(Timeout);
        await TestPoll.UntilAsync(Timeout, () => relay.Pongs == 1);
        Assert.True(client.IsAlive);
        Assert.True(client.Send(new byte[32], new byte[27]));
        Assert.True(client.Send(new byte[32], new byte[1]));
        relay.Inject(identity.PublicKey, [0x12, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
        await TestPoll.UntilAsync(Timeout, () => relay.Pongs == 2);
        Assert.Equal(27, Assert.Single(relay.Traffic).Payload.Length);
        Assert.False(client.Send(new byte[32], new byte[DerpRelay.MaxDatagramSize + 1]));
    }

    [Fact]
    public async Task CorruptServerAuthentication_NeverMakesRelayReady()
    {
        using var relay = new InMemoryDerpRelay { CorruptServerInfo = true };
        using var client = new DerpRelay(relay.Url, new NodeIdentity(), relay.ConnectAsync);
        using var ct = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.StartAsync(ct.Token));
        Assert.False(client.IsAlive);
        Assert.Contains("verification", client.LastError);
    }

    [Fact]
    public async Task OversizedFrame_IsRejectedBeforeBodyAllocation_AndReconnects()
    {
        using var relay = new InMemoryDerpRelay();
        var identity = new NodeIdentity();
        using var client = new DerpRelay(relay.Url, identity, relay.ConnectAsync);
        await client.StartAsync().WaitAsync(Timeout);
        byte[] header = new byte[5];
        header[0] = 0x05;
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(1), DerpRelay.MaxFrameSize + 1);
        relay.Inject(identity.PublicKey, header);
        await TestPoll.UntilAsync(Timeout, () => relay.Authentications >= 2 && client.IsAlive);
        Assert.True(client.IsAlive);
    }

    [Fact]
    public async Task RelayOnly_EncryptedDatagramsFlowBothWays_WithDifferentHomeRelays()
    {
        using var relayA = new InMemoryDerpRelay("derp-a.example.test");
        using var relayB = new InMemoryDerpRelay("derp-b.example.test");
        Task<WebSocket> Connect(Uri uri, CancellationToken ct) => uri.Host == relayA.Url.Host
            ? relayA.ConnectAsync(uri, ct) : relayB.ConnectAsync(uri, ct);
        await using var a = await PinholeNode.BindAsync(Options(relayA) with { DerpWebSocketFactory = Connect });
        await using var b = await PinholeNode.BindAsync(Options(relayB) with { DerpWebSocketFactory = Connect });
        Task<PinholeConnection> accept = a.AcceptAsync();
        await using var atB = await b.ConnectAsync(RelayOnly(a));
        await using var atA = await accept.WaitAsync(Timeout);
        Assert.Equal(PathKind.Relay, atA.Path.Kind);
        Assert.Equal(PathKind.Relay, atB.Path.Kind);
        await Exchange(atA, atB, "DERP keeps Pinhole payloads encrypted A to B");
        await Exchange(atB, atA, "DERP keeps Pinhole payloads encrypted B to A");
        Assert.True(relayA.Authentications >= 2);
        byte[] plaintext = Encoding.UTF8.GetBytes("DERP keeps Pinhole payloads encrypted A to B");
        Assert.Contains(relayA.Traffic, p => p.Payload[0] == (byte)FrameType.Data);
        Assert.All(relayA.Traffic, p => Assert.True(p.Payload.AsSpan().IndexOf(plaintext) < 0));
    }

    [Fact]
    public async Task DerpIntroduction_UpgradesToDirectUdp_WhenThePeersCanReachEachOther()
    {
        using var lab = new VirtualLab();
        using var relay = new InMemoryDerpRelay();
        Task<PinholeNode> Node(string address) => lab.BindNodeAsync(hostAddress: new(IPAddress.Parse(address), 0),
            tweak: options => options with
            {
                DerpRelayUrls = [relay.Url], DerpWebSocketFactory = relay.ConnectAsync,
                ReceiveBufferCapacity = 32,
            });
        await using var a = await Node("192.0.2.10");
        await using var b = await Node("192.0.2.20");
        Task<PinholeConnection> accepting = a.AcceptAsync();
        await using var atB = await b.ConnectAsync(RelayOnly(a));
        await using var atA = await accepting.WaitAsync(Timeout);
        await TestPoll.UntilAsync(Timeout, () => atA.Path.Kind == PathKind.Direct && atB.Path.Kind == PathKind.Direct);
        Assert.True(atA.IsEncrypted);
        Assert.True(atB.IsEncrypted);
        Assert.Contains(relay.Traffic, p => p.Payload[0] == (byte)FrameType.Punc);
        await Exchange(atA, atB, "DERP introduction, direct UDP data");
        await Exchange(atB, atA, "direct UDP reply");
    }

    [Fact]
    public async Task SignalingOnly_DerpExchangesCandidates_ButCannotDeliverApplicationData()
    {
        using var relay = new InMemoryDerpRelay();
        await using var listener = await PinholeNode.BindAsync(Options(relay) with { RelaySignalingOnly = true });
        await using var dialer = await PinholeNode.BindAsync(Options(relay));
        using var stopAccept = new CancellationTokenSource();
        Task<PinholeConnection> accepting = listener.AcceptAsync(stopAccept.Token);
        await using var outgoing = await dialer.ConnectAsync(RelayOnly(listener));
        await TestPoll.UntilAsync(Timeout, () => listener.Connections.Count == 1
            && listener.Connections[0].RelaySignalingReady && listener.Engine.Lookup(dialer.PeerId)!.PeerCandidatesReceived);
        PinholeConnection pending = Assert.Single(listener.Connections);
        Assert.False(accepting.IsCompleted);
        Assert.Throws<InvalidOperationException>(() => pending.Send([1]));
        outgoing.Send("must not become application data"u8);
        await TestPoll.UntilAsync(Timeout, () => pending.RelayedDatagramsBlocked == 1);
        Assert.Equal(0, pending.Stats.DatagramsReceived);
        Assert.Equal(PathKind.None, pending.Path.Kind);
        Assert.False(accepting.IsCompleted);
        stopAccept.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => accepting);
    }

    [Fact]
    public async Task AuthenticatedDerpStranger_CannotSpoofAnEstablishedPeerId()
    {
        using var relay = new InMemoryDerpRelay();
        await using var a = await PinholeNode.BindAsync(Options(relay));
        await using var b = await PinholeNode.BindAsync(Options(relay));
        Task<PinholeConnection> accept = a.AcceptAsync();
        await using var atB = await b.ConnectAsync(RelayOnly(a));
        await using var atA = await accept.WaitAsync(Timeout);

        await Exchange(atA, atB, "prime the listener's authenticated relay lane");
        await Exchange(atB, atA, "prime the dialer's authenticated relay lane");
        var stranger = new NodeIdentity();
        using var attacker = new DerpRelay(relay.Url, stranger, relay.ConnectAsync);
        await attacker.StartAsync().WaitAsync(Timeout);
        var conn = b.Engine.Lookup(a.PeerId)!;
        long before = Interlocked.Read(ref conn.PuncsReceived);
        Assert.True(attacker.Send(b.StaticPublicKey!, a.Engine.Lookup(b.PeerId)!.PuncFrame));
        await TestPoll.UntilAsync(Timeout, () => relay.Traffic.Any(p => p.Source.AsSpan().SequenceEqual(stranger.PublicKey)));
        await Task.Delay(100);
        Assert.Equal(before, Interlocked.Read(ref conn.PuncsReceived));
        Assert.DoesNotContain(relay.Traffic, p => p.Destination.AsSpan().SequenceEqual(stranger.PublicKey));
        await Exchange(atA, atB, "honest peer still works after spoof attempt");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RelayOutage_SwitchesBetweenIrohAndDerp_OnTheSameEncryptedConnection(bool startWithDerp)
    {
        using var derp = new InMemoryDerpRelay { Paused = !startWithDerp };
        using var iroh = new InMemoryIrohRelay();
        bool blockIroh = startWithDerp;
        Task<WebSocket> IrohConnect(Uri uri, CancellationToken ct) => blockIroh
            ? Task.FromException<WebSocket>(new WebSocketException("iroh unavailable")) : iroh.ConnectAsync(uri, ct);
        PinholeOptions options = Options(derp) with { IrohRelayUrls = [InMemoryIrohRelay.Url], IrohWebSocketFactory = IrohConnect };
        await using var a = await PinholeNode.BindAsync(options);
        await using var b = await PinholeNode.BindAsync(options);
        Task<PinholeConnection> accept = a.AcceptAsync();
        await using var atB = await b.ConnectAsync(RelayOnly(a));
        await using var atA = await accept.WaitAsync(Timeout);
        CandidateKind initial = startWithDerp ? CandidateKind.DerpRelay : CandidateKind.IrohRelay;
        Assert.Equal(initial, a.Engine.Lookup(b.PeerId)!.PacketRelay!.Kind);
        await Exchange(atA, atB, "before provider outage");

        blockIroh = false; derp.Paused = false;
        await TestPoll.UntilAsync(Timeout, () => ConnectionString.Parse(a.ConnectionString).Candidates.Any(c => c.Kind != initial && c.Kind is CandidateKind.IrohRelay or CandidateKind.DerpRelay)
            && ConnectionString.Parse(b.ConnectionString).Candidates.Any(c => c.Kind != initial && c.Kind is CandidateKind.IrohRelay or CandidateKind.DerpRelay));
        if (startWithDerp) { derp.Paused = true; derp.DisconnectClients(); }
        else { blockIroh = true; iroh.Dispose(); }
        CandidateKind alternate = startWithDerp ? CandidateKind.IrohRelay : CandidateKind.DerpRelay;
        await TestPoll.UntilAsync(Timeout, () => a.Engine.Lookup(b.PeerId)?.PacketRelay is { IsAlive: true } r && r.Kind == alternate
            && b.Engine.Lookup(a.PeerId)?.PacketRelay is { IsAlive: true } s && s.Kind == alternate);
        await Exchange(atA, atB, "after provider outage A to B");
        await Exchange(atB, atA, "after provider outage B to A");
    }
}
