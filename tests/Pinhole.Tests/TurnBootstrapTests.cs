using System.Net;
using Xunit;

namespace Pinhole.Tests;

public sealed class TurnBootstrapTests
{
    [Fact]
    public async Task SeparateRelayDataAddress_AllowsEncryptedIncomingHandshake()
    {
        using var server = new FakeTurnServer(relayedAddresses: [IPAddress.Parse("192.0.2.41")]);
        using var deadline = new CancellationTokenSource(TestBudget.Scenario);
        var options = Options(server);
        await using var listener = await PinholeNode.BindAsync(options, deadline.Token);
        await using var dialer = await PinholeNode.BindAsync(options, deadline.Token);
        var parsed = ConnectionString.Parse(listener.ConnectionString);
        var candidates = parsed.Candidates.Where(c => c.Kind == CandidateKind.Relay).ToArray();
        Assert.Single(candidates);
        Assert.NotEqual(server.Control.Address, candidates[0].Address.Address);
        string ticket = new ConnectionString(parsed.PeerId, candidates, parsed.NatHint,
            parsed.StaticKey, parsed.EndpointKey).ToString();

        var accepting = listener.AcceptAsync(deadline.Token);
        await using var outgoing = await dialer.ConnectAsync(ticket, deadline.Token);
        await using var incoming = await accepting;
        Assert.True(outgoing.IsEncrypted);
        Assert.True(incoming.IsEncrypted);
        Assert.Equal(PathKind.Relay, outgoing.Path.Kind);
        Assert.Equal(PathKind.Relay, incoming.Path.Kind);

        await ExchangeAsync(outgoing, incoming, deadline.Token);
        Assert.Equal(2, server.Allocations);
    }

    [Fact]
    public async Task DifferentRelayDataAddresses_MutualTicketsEstablishOneEncryptedSession()
    {
        using var server = new FakeTurnServer(relayedAddresses:
            [IPAddress.Parse("192.0.2.41"), IPAddress.Parse("192.0.2.42")]);
        using var deadline = new CancellationTokenSource(TestBudget.Scenario);
        await using var a = await PinholeNode.BindAsync(Options(server), deadline.Token);
        await using var b = await PinholeNode.BindAsync(Options(server), deadline.Token);
        var aTicket = ConnectionString.Parse(a.ConnectionString);
        var bTicket = ConnectionString.Parse(b.ConnectionString);
        var aRelays = aTicket.Candidates.Where(c => c.Kind == CandidateKind.Relay).ToArray();
        var bRelays = bTicket.Candidates.Where(c => c.Kind == CandidateKind.Relay).ToArray();
        Assert.Single(aRelays);
        Assert.Single(bRelays);
        Assert.NotEqual(aRelays[0].Address.Address, bRelays[0].Address.Address);
        string aString = new ConnectionString(aTicket.PeerId, aRelays, aTicket.NatHint,
            aTicket.StaticKey, aTicket.EndpointKey).ToString();
        string bString = new ConnectionString(bTicket.PeerId, bRelays, bTicket.NatHint,
            bTicket.StaticKey, bTicket.EndpointKey).ToString();
        var connected = await Task.WhenAll(a.ConnectAsync(bString, deadline.Token),
            b.ConnectAsync(aString, deadline.Token));
        await using var atA = connected[0];
        await using var atB = connected[1];
        Assert.True(atA.IsEncrypted);
        Assert.True(atB.IsEncrypted);
        Assert.Equal(PathKind.Relay, atA.Path.Kind);
        Assert.Equal(PathKind.Relay, atB.Path.Kind);
        Assert.Single(a.Connections);
        Assert.Single(b.Connections);
        await ExchangeAsync(atA, atB, deadline.Token);
        Assert.Equal(2, server.Allocations);
    }

    private static PinholeOptions Options(FakeTurnServer server) => new()
    {
        Bind = new IPEndPoint(IPAddress.Any, 0),
        Relays = [new TurnServerConfig(server.Control, "user", "pass")],
        RelayCatalog = _ => Task.FromResult(Array.Empty<IPEndPoint>()),
        StunServers = [], IrohRelayUrls = [], RendezvousEndpoints = [], LookupProviders = [],
        PublishIrohAddress = false, EnableDirectUdp = false, EnableTcpTransport = false,
        EnableInterfaceCandidates = false, EnablePortMapping = false, EnablePortPrediction = false,
        AdvertiseLinkLocal = false, EnableNetworkWatch = false, EnableLanDiscovery = false,
        EnablePmtud = false, EnablePathValidation = false, StunRefreshInterval = TimeSpan.Zero,
        Encryption = PinholeEncryption.Required, ReceiveBufferCapacity = 4,
        ConnectTimeout = TestBudget.Io
    };

    private static async Task ExchangeAsync(PinholeConnection outgoing, PinholeConnection incoming, CancellationToken ct)
    {
        byte[] request = [1, 2, 3, 4];
        outgoing.Send(request);
        var received = await incoming.ReceiveAsync(ct);
        Assert.NotNull(received);
        Assert.Equal(request, received.Value.ToArray());
        byte[] response = [4, 3, 2, 1];
        incoming.Send(response);
        var reply = await outgoing.ReceiveAsync(ct);
        Assert.NotNull(reply);
        Assert.Equal(response, reply.Value.ToArray());
    }
}
