using System.Net;
using Xunit;

namespace Pinhole.Tests;

public sealed class PortPredictionTests
{
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(12);
    private static IPEndPoint Endpoint(int port, string address = "203.0.113.20") => new(IPAddress.Parse(address), port);
    private static Task Until(Func<bool> condition) => TestPoll.UntilAsync(Budget, condition);

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(16)]
    public void StableFreshObservations_ProduceExactlyEightBoundedTargets(int step)
    {
        IPEndPoint[] targets = PortPrediction.Predict(Enumerable.Range(0, 4).Select(i => Endpoint(41000 + i * step)).ToArray());
        Assert.Equal(8, targets.Length);
        Assert.Equal(Enumerable.Range(4, 8).Select(i => 41000 + i * step), targets.Select(t => t.Port));
        byte[] offer = PortPrediction.Offer(42, targets);
        Assert.Equal(targets, PortPrediction.ReadOffer(offer, [targets[0].Address]));
        Assert.Null(PortPrediction.ReadOffer(offer, [IPAddress.Parse("203.0.113.21")]));
    }

    [Theory]
    [InlineData(0)] // constant observed mapping: no allocation sequence
    [InlineData(1)] // random/inconsistent steps
    [InlineData(2)] // decreasing sequence
    [InlineData(3)] // large jump
    [InlineData(4)] // port wrapping
    [InlineData(5)] // different public IPs
    [InlineData(6)] // unresolved private mapped IP
    [InlineData(7)] // unresolved shared carrier address
    [InlineData(8)] // insufficient sample count
    public void UnreliableOrInapplicableEvidence_IsRefused(int variant)
    {
        IPEndPoint[] observations = [Endpoint(41000), Endpoint(41001), Endpoint(41002), Endpoint(41003)];
        switch (variant)
        {
            case 0: observations = Enumerable.Repeat(Endpoint(41000), 4).ToArray(); break;
            case 1: observations[2] = Endpoint(41017); break;
            case 2: observations = [Endpoint(41004), Endpoint(41003), Endpoint(41002), Endpoint(41001)]; break;
            case 3: observations = [Endpoint(41000), Endpoint(41017), Endpoint(41034), Endpoint(41051)]; break;
            case 4: observations = [Endpoint(65531), Endpoint(65532), Endpoint(65533), Endpoint(65534)]; break;
            case 5: observations[3] = Endpoint(41003, "203.0.113.21"); break;
            case 6: observations = observations.Select(e => Endpoint(e.Port, "192.168.1.2")).ToArray(); break;
            case 7: observations = observations.Select(e => Endpoint(e.Port, "100.64.1.2")).ToArray(); break;
            case 8: observations = observations[..3]; break;
        }
        Assert.Empty(PortPrediction.Predict(observations));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void NegotiatedOffers_RejectTruncationDuplicatesUnboundedListsAndArbitraryPorts(int variant)
    {
        IPEndPoint[] targets = Enumerable.Range(0, 8).Select(i => Endpoint(41000 + i)).ToArray();
        byte[] wire = PortPrediction.Offer(42, targets);
        switch (variant)
        {
            case 0: wire = wire[..^1]; break;
            case 1: wire.AsSpan(11, 6).CopyTo(wire.AsSpan(17, 6)); break;
            case 2: wire[10] = 255; break;
            case 3: wire[^1] ^= 64; break;
        }
        Assert.Null(PortPrediction.ReadOffer(wire, [targets[0].Address]));
    }

    private sealed class Servers(VirtualLab lab) : IDisposable
    {
        private readonly List<VirtualStunServer> _servers = [];
        internal IReadOnlyList<IPEndPoint> All()
        {
            if (_servers.Count == 0)
                for (int i = 60; i < 64; i++) _servers.Add(new VirtualStunServer(lab.Net, new(IPAddress.Parse($"192.0.2.{i}"), 3478)));
            return [.. lab.StunServers, .. _servers.Select(s => s.LocalEndPoint)];
        }
        public void Dispose() { foreach (var server in _servers) server.Dispose(); }
    }

    private static Task<PinholeNode> Node(VirtualLab lab, VirtualNat nat, InMemoryIrohRelay relay, IReadOnlyList<IPEndPoint> stun, bool enabled = true, bool signalingOnly = false) =>
        lab.BindNodeAsync(nat, tweak: o => o with
        {
            StunServers = stun, IrohRelayUrls = [InMemoryIrohRelay.Url], IrohWebSocketFactory = relay.ConnectAsync,
            EnablePortPrediction = enabled, RelaySignalingOnly = signalingOnly, ReceiveBufferCapacity = 8, EnablePathValidation = false,
            EnablePmtud = false, StunRefreshInterval = TimeSpan.Zero, ConnectTimeout = TimeSpan.FromSeconds(12),
        });

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    public async Task TwoPredictableSymmetricNats_UpgradeThroughNegotiatedFreshSocketMeasurements(int lostControlFrames)
    {
        using var lab = new VirtualLab(); using var servers = new Servers(lab); using var relay = new InMemoryIrohRelay();
        relay.DropNext(0x58, lostControlFrames);
        using var an = lab.Nat(VirtualNatKind.Symmetric, "203.0.113.10", "172.31.10.0/24");
        using var bn = lab.Nat(VirtualNatKind.Symmetric, "203.0.113.20", "172.31.20.0/24");
        await using var a = await Node(lab, an, relay, servers.All()); await using var b = await Node(lab, bn, relay, servers.All());
        Assert.Equal(2, an.MappingsCreated); Assert.Equal(2, bn.MappingsCreated); // four destinations remain uncontacted
        Task<PinholeConnection> accepting = b.AcceptAsync();
        await using var outgoing = await a.ConnectAsync(b.ConnectionString).WaitAsync(Budget);
        await using var incoming = await accepting.WaitAsync(Budget);
        try { await Until(() => outgoing.Path.Kind == PathKind.Direct && incoming.Path.Kind == PathKind.Direct); }
        catch
        {
            foreach ((PinholeNode node, PinholeNode peer) in new[] { (a, b), (b, a) })
            {
                ConnState state = node.Engine.Lookup(peer.PeerId)!;
                Console.WriteLine($"prediction peer={node.PeerId:x} capable={state.Prediction?.PeerCapable} started={state.Prediction?.Started} finished={state.Prediction?.Finished} probes={state.PortPredictionProbesSent} local={string.Join(',', state.Prediction?.LocalTargets?.Select(t => t.ToString()) ?? [])} remote={string.Join(',', state.Prediction?.PeerTargets?.Select(t => t.ToString()) ?? [])}");
            }
            Console.WriteLine(an.Counters()); Console.WriteLine(bn.Counters());
            throw;
        }
        Assert.InRange(outgoing.PortPredictionProbesSent, 1, 48); Assert.InRange(incoming.PortPredictionProbesSent, 1, 48);
        Assert.True(outgoing.IsEncrypted); Assert.True(incoming.IsEncrypted);
        outgoing.Send([7, 8]); Assert.Equal(new byte[] { 7, 8 }, (await incoming.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
        incoming.Send([9]); Assert.Equal(new byte[] { 9 }, (await outgoing.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
        Assert.Equal(8, a.Engine.Lookup(b.PeerId)!.Prediction!.LocalTargets!.Length);
        // Guesses never become public reflexive candidates, even after one proves usable.
        Assert.DoesNotContain(ConnectionString.Parse(a.ConnectionString).Candidates,
            c => a.Engine.Lookup(b.PeerId)!.Prediction!.LocalTargets!.Contains(c.Address));
    }

    [Fact]
    public async Task RandomAllocation_RefusesPredictionAndRetainsTheLabeledRelayPath()
    {
        using var lab = new VirtualLab(); using var servers = new Servers(lab); using var relay = new InMemoryIrohRelay();
        using var an = lab.Nat(VirtualNatKind.Symmetric, "203.0.113.10", "172.31.10.0/24");
        using var bn = lab.Nat(VirtualNatKind.Symmetric, "203.0.113.20", "172.31.20.0/24");
        an.PortAllocator = i => 20000 + (int)((long)i * 7919 % 40000);
        bn.PortAllocator = i => 20000 + (int)((long)i * 6151 % 40000);
        await using var a = await Node(lab, an, relay, servers.All()); await using var b = await Node(lab, bn, relay, servers.All());
        Task<PinholeConnection> accepting = b.AcceptAsync();
        await using var outgoing = await a.ConnectAsync(b.ConnectionString).WaitAsync(Budget);
        await using var incoming = await accepting.WaitAsync(Budget);
        await Until(() => a.Engine.Lookup(b.PeerId)!.Prediction is { Finished: true } && b.Engine.Lookup(a.PeerId)!.Prediction is { Finished: true });
        Assert.True(a.Engine.Lookup(b.PeerId)!.Prediction!.PeerCapable);
        Assert.True(b.Engine.Lookup(a.PeerId)!.Prediction!.PeerCapable);
        Assert.True(an.MappingsCreated >= 6); Assert.True(bn.MappingsCreated >= 6);
        Assert.Equal(0, outgoing.PortPredictionProbesSent); Assert.Equal(0, incoming.PortPredictionProbesSent);
        Assert.Equal(PathKind.Relay, outgoing.Path.Kind); Assert.Equal(PathKind.Relay, incoming.Path.Kind);
        outgoing.Send([99]); Assert.Equal(new byte[] { 99 }, (await incoming.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
    }

    [Fact]
    public async Task PeerOptOutOrOldPeer_DoesNotAuthorizeSamplingOrSpeculativePunches()
    {
        using var lab = new VirtualLab(); using var servers = new Servers(lab); using var relay = new InMemoryIrohRelay();
        using var an = lab.Nat(VirtualNatKind.Symmetric, "203.0.113.10", "172.31.10.0/24");
        using var bn = lab.Nat(VirtualNatKind.Symmetric, "203.0.113.20", "172.31.20.0/24");
        await using var a = await Node(lab, an, relay, servers.All()); await using var b = await Node(lab, bn, relay, servers.All(), enabled: false);
        Task<PinholeConnection> accepting = b.AcceptAsync();
        await using var outgoing = await a.ConnectAsync(b.ConnectionString).WaitAsync(Budget);
        await using var incoming = await accepting.WaitAsync(Budget);
        await Until(() => a.Engine.Lookup(b.PeerId)!.Prediction is { Finished: true });
        Assert.Null(b.Engine.Lookup(a.PeerId)!.Prediction);
        Assert.Equal(0, outgoing.PortPredictionProbesSent); Assert.Equal(0, incoming.PortPredictionProbesSent);
        Assert.Equal(PathKind.Relay, outgoing.Path.Kind);
    }

    [Fact]
    public async Task PreviouslyContactedSampleDestination_IsRefusedInsteadOfPretendingItIsFresh()
    {
        using var lab = new VirtualLab(); using var servers = new Servers(lab); using var relay = new InMemoryIrohRelay();
        using var an = lab.Nat(VirtualNatKind.Symmetric, "203.0.113.10", "172.31.10.0/24");
        using var bn = lab.Nat(VirtualNatKind.Symmetric, "203.0.113.20", "172.31.20.0/24");
        var configured = servers.All();
        await using var a = await Node(lab, an, relay, configured); await using var b = await Node(lab, bn, relay, configured);
        await a.Engine.ProbeStunAsync(configured[^1]); // consumes a reserved mapping before the negotiated round
        Task<PinholeConnection> accepting = b.AcceptAsync();
        await using var outgoing = await a.ConnectAsync(b.ConnectionString).WaitAsync(Budget);
        await using var incoming = await accepting.WaitAsync(Budget);
        await Until(() => a.Engine.Lookup(b.PeerId)!.Prediction is { Finished: true });
        Assert.True(a.Engine.Lookup(b.PeerId)!.Prediction!.PeerCapable);
        Assert.Null(a.Engine.Lookup(b.PeerId)!.Prediction!.LocalTargets);
        Assert.Equal(0, outgoing.PortPredictionProbesSent);
        Assert.Equal(PathKind.Relay, outgoing.Path.Kind);
    }

    [Fact]
    public async Task SignalingOnly_PredictionCompletesDirectWithoutSendingApplicationDataThroughRelay()
    {
        using var lab = new VirtualLab(); using var servers = new Servers(lab); using var relay = new InMemoryIrohRelay();
        using var an = lab.Nat(VirtualNatKind.Symmetric, "203.0.113.10", "172.31.10.0/24");
        using var bn = lab.Nat(VirtualNatKind.Symmetric, "203.0.113.20", "172.31.20.0/24");
        await using var a = await Node(lab, an, relay, servers.All(), signalingOnly: true);
        await using var b = await Node(lab, bn, relay, servers.All(), signalingOnly: true);
        Task<PinholeConnection> accepting = b.AcceptAsync();
        await using var outgoing = await a.ConnectAsync(b.ConnectionString).WaitAsync(Budget);
        await using var incoming = await accepting.WaitAsync(Budget);
        Assert.Equal(PathKind.Direct, outgoing.Path.Kind); Assert.Equal(PathKind.Direct, incoming.Path.Kind);
        Assert.InRange(outgoing.PortPredictionProbesSent, 1, 48); Assert.InRange(incoming.PortPredictionProbesSent, 1, 48);
        outgoing.Send([11]); Assert.Equal(new byte[] { 11 }, (await incoming.ReceiveAsync().AsTask().WaitAsync(Budget))!.Value.ToArray());
        Assert.DoesNotContain(relay.Traffic, d => d.Payload[0] == 0x52);
    }
}
