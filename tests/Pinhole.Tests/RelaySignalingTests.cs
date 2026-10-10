using System.Net;
using System.Buffers.Binary;
using Xunit;

namespace Pinhole.Tests;

public sealed class RelaySignalingTests
{
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(6);
    private static Task Until(Func<bool> condition) => TestPoll.UntilAsync(Budget, condition);
    private static Task<PinholeNode> Node(VirtualLab lab, InMemoryIrohRelay relay, string address, bool signalingOnly = true, double timeout = 8) =>
        lab.BindNodeAsync(hostAddress: new(IPAddress.Parse(address), 0), tweak: o => o with
        {
            IrohRelayUrls = [InMemoryIrohRelay.Url], IrohWebSocketFactory = relay.ConnectAsync,
            RelaySignalingOnly = signalingOnly, ReceiveBufferCapacity = 16,
            ConnectTimeout = TimeSpan.FromSeconds(timeout),
            PathValidationIdle = TimeSpan.FromMilliseconds(150), PathValidationProbeInterval = TimeSpan.FromMilliseconds(80),
            PathValidationMaxUnansweredProbes = 2,
        });
    private static string RelayTicket(PinholeNode node)
    {
        var cs = ConnectionString.Parse(node.ConnectionString);
        return new ConnectionString(cs.PeerId, cs.Candidates.Where(c => c.Kind == CandidateKind.IrohRelay).ToArray(),
            cs.NatHint, cs.StaticKey, cs.EndpointKey).ToString();
    }
    private static LinkRule BlockPeers(PinholeNode a, PinholeNode b) => new()
    {
        DropAll = true,
        Match = (source, destination) => source.Port == a.LocalPort && destination.Port == b.LocalPort
            || source.Port == b.LocalPort && destination.Port == a.LocalPort,
    };
    private static async Task Exchange(PinholeConnection from, PinholeConnection to, byte marker)
    {
        from.Send([marker, 2, 3]);
        Assert.Equal(new[] { marker, (byte)2, (byte)3 }, (await to.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
    }

    [Fact]
    public async Task RelayIntroduction_ExchangesBothCandidatesBeforeExposingADirectApplicationPath()
    {
        using var lab = new VirtualLab(); using var relay = new InMemoryIrohRelay();
        await using var a = await Node(lab, relay, "192.0.2.10");
        await using var b = await Node(lab, relay, "192.0.2.20");
        LinkRule blocked = BlockPeers(a, b); lab.Net.AddRule(blocked);
        using var stopAccept = new CancellationTokenSource();
        Task<PinholeConnection> accept = b.AcceptAsync(stopAccept.Token);
        Task<PinholeConnection> dial = a.ConnectAsync(RelayTicket(b));
        await Until(() => a.Engine.Lookup(b.PeerId) is { PeerCandidatesReceived: true } ac
            && b.Engine.Lookup(a.PeerId) is { PeerCandidatesReceived: true } bc
            && ac.Public!.RelaySignalingReady && bc.Public!.RelaySignalingReady);
        Assert.False(dial.IsCompleted); Assert.False(accept.IsCompleted);
        Assert.Equal(PathKind.None, Assert.Single(a.Connections).Path.Kind);
        Assert.Equal(PinholeConnectionState.Punching, Assert.Single(b.Connections).State);
        Assert.False(b.Engine.Lookup(a.PeerId)!.IncomingQueued);
        Assert.Equal(2, relay.Authentications);
        Assert.Contains(a.Engine.Lookup(b.PeerId)!.PeerCandidates, c => c.Address.Port == b.LocalPort && c.Kind == CandidateKind.Reflexive);
        Assert.Contains(b.Engine.Lookup(a.PeerId)!.PeerCandidates, c => c.Address.Port == a.LocalPort && c.Kind == CandidateKind.Reflexive);
        lab.Net.RemoveRule(blocked);
        await using var outgoing = await dial.WaitAsync(Budget);
        await using var incoming = await accept.WaitAsync(Budget);
        Assert.Equal(PathKind.Direct, outgoing.Path.Kind); Assert.Equal(PathKind.Direct, incoming.Path.Kind);
        Assert.True(outgoing.IsEncrypted); Assert.True(incoming.IsEncrypted);
        await Exchange(outgoing, incoming, 7); await Exchange(incoming, outgoing, 8);
        Assert.DoesNotContain(relay.Traffic, d => d.Payload[0] == 0x52); // application Data was never relayed
    }

    [Fact]
    public async Task ForbiddenRelayedApplicationData_IsAuthenticatedThenDroppedAndNeverCompletesAccept()
    {
        using var lab = new VirtualLab(); using var relay = new InMemoryIrohRelay();
        await using var signalOnly = await Node(lab, relay, "192.0.2.10");
        await using var ordinary = await Node(lab, relay, "192.0.2.20", signalingOnly: false);
        LinkRule blocked = BlockPeers(signalOnly, ordinary); lab.Net.AddRule(blocked);
        using var cancelAccept = new CancellationTokenSource();
        Task<PinholeConnection> pendingAccept = signalOnly.AcceptAsync(cancelAccept.Token);
        await using var sender = await ordinary.ConnectAsync(RelayTicket(signalOnly)).WaitAsync(Budget);
        await Until(() => signalOnly.Connections.Count == 1 && signalOnly.Connections[0].RelaySignalingReady);
        PinholeConnection waiting = Assert.Single(signalOnly.Connections);
        Assert.False(pendingAccept.IsCompleted);
        Assert.Throws<InvalidOperationException>(() => waiting.Send([1]));
        sender.Send([99, 98, 97]);
        await Until(() => waiting.RelayedDatagramsBlocked == 1);
        Assert.Equal(0, waiting.Stats.DatagramsReceived); Assert.Equal(0, waiting.Stats.BytesReceived);
        Assert.Equal(PathKind.None, waiting.Path.Kind); Assert.False(pendingAccept.IsCompleted);
        lab.Net.RemoveRule(blocked);
        await using var accepted = await pendingAccept.WaitAsync(Budget);
        await Until(() => sender.Path.Kind == PathKind.Direct);
        Assert.Same(waiting, accepted);
        await Exchange(sender, accepted, 11); await Exchange(accepted, sender, 12);
        Assert.Equal(1, accepted.RelayedDatagramsBlocked);
    }

    [Fact]
    public async Task DirectFailure_UsesControlSignalingAndRecoversTheSameConnectionWithoutRelayingData()
    {
        using var lab = new VirtualLab(); using var relay = new InMemoryIrohRelay();
        await using var a = await Node(lab, relay, "192.0.2.10");
        await using var b = await Node(lab, relay, "192.0.2.20");
        Task<PinholeConnection> accepting = b.AcceptAsync();
        await using var outgoing = await a.ConnectAsync(RelayTicket(b)).WaitAsync(Budget);
        await using var incoming = await accepting.WaitAsync(Budget);
        await Exchange(outgoing, incoming, 21);
        LinkRule blocked = BlockPeers(a, b); lab.Net.AddRule(blocked);
        await Until(() => outgoing.State == PinholeConnectionState.Punching && incoming.State == PinholeConnectionState.Punching);
        Assert.Equal(PathKind.None, outgoing.Path.Kind); Assert.True(outgoing.RelaySignalingReady);
        Assert.Throws<InvalidOperationException>(() => outgoing.Send([1]));
        lab.Net.RemoveRule(blocked);
        await Until(() => outgoing.State == PinholeConnectionState.Open && incoming.State == PinholeConnectionState.Open);
        Assert.Same(outgoing, Assert.Single(a.Connections)); Assert.Same(incoming, Assert.Single(b.Connections));
        await Exchange(outgoing, incoming, 22); await Exchange(incoming, outgoing, 23);
        Assert.DoesNotContain(relay.Traffic, d => d.Payload[0] == 0x52);
    }

    [Fact]
    public async Task LostAnnouncements_AreRetriedWithoutApplicationDataOrBudgetExtension()
    {
        using var lab = new VirtualLab(); using var relay = new InMemoryIrohRelay();
        relay.DropNext(0x55, 4);
        await using var a = await Node(lab, relay, "192.0.2.10");
        await using var b = await Node(lab, relay, "192.0.2.20");
        Task<PinholeConnection> accepting = b.AcceptAsync();
        await using var outgoing = await a.ConnectAsync(RelayTicket(b)).WaitAsync(Budget);
        await using var incoming = await accepting.WaitAsync(Budget);
        Assert.True(relay.Traffic.Count(t => t.Payload[0] == 0x55) > 4);
        await Exchange(outgoing, incoming, 31);
        Assert.DoesNotContain(relay.Traffic, d => d.Payload[0] == 0x52);
    }

    [Fact]
    public async Task BlockedDirectPath_TimesOutHonestlyAndClearsTheDialInsteadOfReturningARelay()
    {
        using var lab = new VirtualLab(); using var relay = new InMemoryIrohRelay();
        await using var a = await Node(lab, relay, "192.0.2.10", timeout: 0.8);
        await using var b = await Node(lab, relay, "192.0.2.20");
        lab.Net.AddRule(BlockPeers(a, b));
        PinholeConnectResult result = await a.TryConnectAsync(RelayTicket(b)).WaitAsync(Budget);
        Assert.False(result.IsSuccess); Assert.Equal(PinholeConnectFailure.TimedOut, result.Failure);
        Assert.Contains("signaling", result.ErrorMessage!);
        // Husk cleanup is asynchronous on BOTH sides: the timed-out dial's local entry is
        // closed in the background, so poll it down like the peer's instead of asserting
        // a single instant (a loaded runner once caught the husk mid-retirement).
        await Until(() => a.Connections.Count == 0 && b.Connections.Count == 0);
        Assert.DoesNotContain(relay.Traffic, d => d.Payload[0] == 0x52);
    }

    [Fact]
    public async Task CancellationAfterIntroduction_SendsControlCloseAndDoesNotAcceptAnUnusableSession()
    {
        using var lab = new VirtualLab(); using var relay = new InMemoryIrohRelay();
        await using var a = await Node(lab, relay, "192.0.2.10");
        await using var b = await Node(lab, relay, "192.0.2.20");
        lab.Net.AddRule(BlockPeers(a, b));
        using var cancel = new CancellationTokenSource();
        Task<PinholeConnection> dial = a.ConnectAsync(RelayTicket(b), cancel.Token);
        await Until(() => a.Connections.Count == 1 && a.Connections[0].RelaySignalingReady);
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => dial);
        await Until(() => a.Connections.Count == 0 && b.Connections.Count == 0);
        Assert.Contains(relay.Traffic, d => d.Payload[0] == 0x56);
    }

    [Fact]
    public async Task DefaultPolicy_StillConnectsAndCarriesEncryptedRelayData()
    {
        using var lab = new VirtualLab(); using var relay = new InMemoryIrohRelay();
        await using var a = await Node(lab, relay, "192.0.2.10", signalingOnly: false);
        await using var b = await Node(lab, relay, "192.0.2.20", signalingOnly: false);
        lab.Net.AddRule(BlockPeers(a, b));
        Task<PinholeConnection> accepting = b.AcceptAsync();
        await using var outgoing = await a.ConnectAsync(RelayTicket(b)).WaitAsync(Budget);
        await using var incoming = await accepting.WaitAsync(Budget);
        await Until(() => outgoing.IsEncrypted && incoming.IsEncrypted);
        Assert.Equal(PathKind.Relay, outgoing.Path.Kind); Assert.Equal(PathKind.Relay, incoming.Path.Kind);
        await Exchange(outgoing, incoming, 41); await Exchange(incoming, outgoing, 42);
        Assert.Contains(relay.Traffic, d => d.Payload[0] == 0x52);
    }

    [Theory]
    [InlineData(PinholeEncryption.Optional)]
    [InlineData(PinholeEncryption.Disabled)]
    public async Task SignalingOnly_RefusesPoliciesThatPermitUnauthenticatedCandidates(PinholeEncryption policy)
    {
        await Assert.ThrowsAsync<ArgumentException>(() => PinholeOptions.ResolveAsync(new()
        { RelaySignalingOnly = true, Encryption = policy, PublishIrohAddress = false, StunServers = [], IrohRelayUrls = [] }));
    }

    [Fact]
    public async Task NoRelayTicket_StillEstablishesAnAuthenticatedDirectConnection()
    {
        using var lab = new VirtualLab();
        await using var a = await lab.BindNodeAsync(hostAddress: new(IPAddress.Parse("192.0.2.10"), 0), tweak: o => o with { RelaySignalingOnly = true, ReceiveBufferCapacity = 8 });
        await using var b = await lab.BindNodeAsync(hostAddress: new(IPAddress.Parse("192.0.2.20"), 0), tweak: o => o with { RelaySignalingOnly = true, ReceiveBufferCapacity = 8 });
        Task<PinholeConnection> accepting = b.AcceptAsync();
        await using var outgoing = await a.ConnectAsync(b.ConnectionString).WaitAsync(Budget);
        await using var incoming = await accepting.WaitAsync(Budget);
        Assert.Equal(PathKind.Direct, outgoing.Path.Kind); Assert.True(outgoing.IsEncrypted);
        Assert.False(outgoing.RelaySignalingReady); await Exchange(outgoing, incoming, 51);
    }

    [Fact]
    public async Task ReplayedUnsealedHandshakeAtAnotherUdpSource_CannotCompleteADirectApplicationConnection()
    {
        using var lab = new VirtualLab(); using var relay = new InMemoryIrohRelay();
        await using var a = await Node(lab, relay, "192.0.2.10");
        await using var b = await Node(lab, relay, "192.0.2.20");
        LinkRule blocked = BlockPeers(a, b); lab.Net.AddRule(blocked);
        Task<PinholeConnection> dial = a.ConnectAsync(RelayTicket(b));
        using var cancelAccept = new CancellationTokenSource();
        Task<PinholeConnection> accept = b.AcceptAsync(cancelAccept.Token);
        await Until(() => a.Connections.Count == 1 && a.Connections[0].RelaySignalingReady
            && b.Connections.Count == 1 && b.Connections[0].RelaySignalingReady);
        byte[] original = relay.Traffic.First(d => d.Payload[0] == 0x50 && d.Source.SequenceEqual(a.EndpointPublicKey!)).Payload;
        using var attacker = lab.Net.CreateHost(new(IPAddress.Parse("192.0.2.66"), 60666));
        long deliveredBefore = Interlocked.Read(ref lab.Net.Delivered);
        attacker.SendTo(original, new IPEndPoint(IPAddress.Parse("192.0.2.20").MapToIPv6(), b.LocalPort).Serialize());
        var ack = new byte[8192];
        var from = new System.Net.SocketAddress(System.Net.Sockets.AddressFamily.InterNetworkV6);
        // Receiving the reply proves that the replay was processed, rather than dropped
        // by the virtual network. The attacker cannot produce an encrypted response.
        int count = await Task.Run(() => attacker.ReceiveFrom(ack, from)).WaitAsync(Budget);
        Assert.Equal(0x51, ack[0]); Assert.Equal(97, count);
        Assert.True(Interlocked.Read(ref lab.Net.Delivered) > deliveredBefore);
        Assert.Equal(PathKind.None, b.Connections[0].Path.Kind);
        Assert.False(dial.IsCompleted); Assert.False(accept.IsCompleted);
        lab.Net.RemoveRule(blocked);
        await using var outgoing = await dial.WaitAsync(Budget);
        await using var incoming = await accept.WaitAsync(Budget);
        await Exchange(outgoing, incoming, 61);
    }

    [Fact]
    public async Task ReversePuncWithASubstitutedStaticKey_CannotPoisonThePinnedDial()
    {
        using var lab = new VirtualLab(); using var relay = new InMemoryIrohRelay();
        relay.DropNext(0x50, 1000);
        await using var a = await Node(lab, relay, "192.0.2.10");
        await using var b = await Node(lab, relay, "192.0.2.20");
        ConnState state = a.Engine.ConnectAsync(ConnectionString.Parse(RelayTicket(b)), default);
        var impostor = new NodeIdentity(); var ephemeral = NodeIdentity.NewEphemeral();
        byte[] forged = new byte[77]; forged[0] = 0x50;
        BinaryPrimitives.WriteUInt64LittleEndian(forged.AsSpan(1), b.PeerId);
        BinaryPrimitives.WriteUInt32LittleEndian(forged.AsSpan(9), 123456);
        ephemeral.Public.CopyTo(forged, 13); impostor.PublicKey.CopyTo(forged, 45);
        using var attacker = lab.Net.CreateHost(new(IPAddress.Parse("192.0.2.66"), 60666));
        attacker.SendTo(forged, new IPEndPoint(IPAddress.Parse("192.0.2.10").MapToIPv6(), a.LocalPort).Serialize());
        await Until(() => state.Public!.FramesRejected > 0);
        Assert.False(state.RemoteTokenKnown); Assert.False(state.Crypto!.Established);
        Assert.False(state.Connected.Task.IsCompleted); Assert.Null(state.Crypto.PeerStaticPublic);
        await a.Engine.CloseAsync(state);
    }

    [Fact]
    public async Task ReplayedOrTamperedCandidateAnnouncements_CannotChangeThePeerTargets()
    {
        using var lab = new VirtualLab(); using var relay = new InMemoryIrohRelay();
        await using var a = await Node(lab, relay, "192.0.2.10");
        await using var b = await Node(lab, relay, "192.0.2.20");
        lab.Net.AddRule(BlockPeers(a, b));
        using var stop = new CancellationTokenSource();
        Task<PinholeConnection> dial = a.ConnectAsync(RelayTicket(b), stop.Token);
        await Until(() => a.Engine.Lookup(b.PeerId) is { PeerCandidatesReceived: true });
        ConnState state = a.Engine.Lookup(b.PeerId)!;
        // Honest retries parse the same relay identity into a new byte array.
        // Compare every candidate field by value, including its key bytes, so that
        // reference identity cannot turn an unchanged target into a false failure.
        var before = CandidateValues();
        byte[] original = relay.Traffic.First(d => d.Payload[0] == 0x55 && d.Source.SequenceEqual(b.EndpointPublicKey!)).Payload;
        long rejected = state.Public!.FramesRejected;
        relay.Deliver(b.EndpointPublicKey!, a.EndpointPublicKey!, original);
        byte[] corrupted = (byte[])original.Clone(); corrupted[^1] ^= 1;
        relay.Deliver(b.EndpointPublicKey!, a.EndpointPublicKey!, corrupted);
        await Until(() => state.Public.FramesRejected >= rejected + 2);
        Assert.Equal(before, CandidateValues()); Assert.False(dial.IsCompleted);
        stop.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => dial);

        (CandidateKind, IPEndPoint, IPEndPoint?, string?, string?, Uri?, string?)[] CandidateValues() =>
            state.PeerCandidates.Select(c => (c.Kind, c.Address, c.RelayServer, c.Username, c.Credential,
                c.RelayUrl, c.RelayKey is { } key ? Convert.ToHexString(key) : null)).ToArray();
    }

    [Fact]
    public async Task ASignalingOnlyStrangerWithNoDirectPath_DoesNotBlockAcceptanceOfAWorkingPeer()
    {
        using var lab = new VirtualLab(); using var relay = new InMemoryIrohRelay();
        await using var stalled = await Node(lab, relay, "192.0.2.10");
        await using var listener = await Node(lab, relay, "192.0.2.20");
        await using var working = await Node(lab, relay, "192.0.2.30");
        lab.Net.AddRule(BlockPeers(stalled, listener));
        using var cancel = new CancellationTokenSource();
        Task<PinholeConnection> blocked = stalled.ConnectAsync(RelayTicket(listener), cancel.Token);
        await Until(() => listener.Connections.Count == 1 && listener.Connections[0].RelaySignalingReady);
        Task<PinholeConnection> accepting = listener.AcceptAsync();
        await using var outgoing = await working.ConnectAsync(listener.ConnectionString).WaitAsync(Budget);
        await using var incoming = await accepting.WaitAsync(Budget);
        Assert.Equal(working.PeerId, incoming.PeerId); await Exchange(outgoing, incoming, 71);
        cancel.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => blocked);
    }

    [Fact]
    public async Task AdvertisedRelayIntroduction_HoldsInitialDirectProbesUntilCurrentCandidatesArrive()
    {
        using var lab = new VirtualLab(); using var relay = new InMemoryIrohRelay();
        relay.DropNext(0x55, 1000);
        await using var a = await Node(lab, relay, "192.0.2.10");
        await using var b = await Node(lab, relay, "192.0.2.20");
        long initialDatagrams = Interlocked.Read(ref lab.Net.Delivered);
        Task<PinholeConnection> accepting = b.AcceptAsync();
        Task<PinholeConnection> dial = a.ConnectAsync(b.ConnectionString); // reachable direct tuples and a relay
        await Until(() => a.Connections.Count == 1 && a.Connections[0].RelaySignalingReady
            && b.Connections.Count == 1 && b.Connections[0].RelaySignalingReady);
        Assert.False(dial.IsCompleted); Assert.False(accepting.IsCompleted);
        Assert.False(a.Engine.Lookup(b.PeerId)!.PeerCandidatesReceived);
        Assert.False(b.Engine.Lookup(a.PeerId)!.PeerCandidatesReceived);
        Assert.Equal(initialDatagrams, Interlocked.Read(ref lab.Net.Delivered));
        relay.DropNext(0x55, 0);
        await using var outgoing = await dial.WaitAsync(Budget);
        await using var incoming = await accepting.WaitAsync(Budget);
        Assert.True(a.Engine.Lookup(b.PeerId)!.PeerCandidatesReceived);
        Assert.True(b.Engine.Lookup(a.PeerId)!.PeerCandidatesReceived);
        Assert.Equal(PathKind.Direct, outgoing.Path.Kind); await Exchange(outgoing, incoming, 81);
    }
}
