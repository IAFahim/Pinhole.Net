using System.Net;
using Pinhole;
using Xunit;

namespace Pinhole.Tests;

/// <summary>The optional heartbeat: pings at a fixed cadence on every live connection,
/// counted in caller stats because the app asked for them — and silence by default.</summary>
public sealed class KeepaliveTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static PinholeOptions Opts(TimeSpan? keepalive = null) => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [],
        PublishIrohAddress = false,
        EnableLanDiscovery = false,
        EnableNetworkWatch = false,
        EnablePortMapping = false,
        EnablePathValidation = false,
        EnablePmtud = false,
        KeepaliveInterval = keepalive ?? TimeSpan.Zero,
        ConnectTimeout = TimeSpan.FromSeconds(8),
    };

    private static string LoopbackString(PinholeNode listener) => new ConnectionString(
        listener.PeerId,
        [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, listener.LocalPort))],
        staticKey: listener.StaticPublicKey).ToString();

    [Fact]
    public async Task Keepalive_PingsOnCadence_AndFeedsRtt()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts(TimeSpan.FromMilliseconds(300)));
        _ = a.AcceptAsync();
        PinholeConnection atB = await b.ConnectAsync(LoopbackString(a)).WaitAsync(Timeout);

        // Three heartbeats at 300 ms — generous CI margins — each answered, each RTT fresh.
        await TestPoll.UntilAsync(Timeout, () => atB.Stats.PingsSent >= 3 && atB.LastRtt is not null);
        await TestPoll.UntilAsync(Timeout, () => atB.Stats.PongsReceived >= 3);
        Assert.Equal(PinholeConnectionState.Open, atB.State);
    }

    [Fact]
    public async Task NoKeepaliveByDefault_NothingSendsItself()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        _ = a.AcceptAsync();
        PinholeConnection atB = await b.ConnectAsync(LoopbackString(a)).WaitAsync(Timeout);

        await Task.Delay(800); // far past one 300 ms-style cadence; validation and PMTUD are off too
        Assert.Equal(0, atB.Stats.PingsSent);
        Assert.Equal(0, atB.Stats.PongsReceived);

        // The floor still rejects absurd cadences — at resolve time, before any socket opens.
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => PinholeNode.BindAsync(Opts(TimeSpan.FromMilliseconds(10))));
    }
}
