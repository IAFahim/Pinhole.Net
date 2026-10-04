using System.Diagnostics;
using System.Text;
using Xunit;

namespace Pinhole.Tests;

public sealed class RoamingTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static PinholeOptions Opts(IReadOnlyList<TurnServerConfig>? relays = null, TimeSpan? connectTimeout = null) => new()
    {
        StunServers = [],
        Relays = relays ?? [],
        IrohRelayUrls = [],
        ConnectTimeout = connectTimeout ?? TimeSpan.FromSeconds(8),
        BindProbeBudget = TimeSpan.FromSeconds(5),
        EnableNetworkWatch = false,
    };

    private static async Task<(PinholeConnection DialerSide, PinholeConnection ListenerSide)> ConnectPairAsync(
        PinholeNode listener, PinholeNode dialer, string? listenerString = null)
    {
        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection dialerSide = await dialer.ConnectAsync(listenerString ?? listener.ConnectionString).WaitAsync(Timeout);
        PinholeConnection listenerSide = await accept.WaitAsync(Timeout);
        return (dialerSide, listenerSide);
    }

    private static async Task AssertExchangeAsync(PinholeConnection from, PinholeConnection to, string marker)
    {
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        to.Received += s => got.TrySetResult(s.ToArray());
        from.Send(Encoding.UTF8.GetBytes(marker));
        byte[] answer = await got.Task.WaitAsync(Timeout);
        Assert.Equal(marker, Encoding.UTF8.GetString(answer));
    }

    private static async Task WaitForStateAsync(PinholeConnection conn, PinholeConnectionState state, TimeSpan budget) =>
        await TestPoll.UntilAsync(budget, () => conn.State == state);

    [Fact]
    public async Task InterfaceLoss_Rebinds_SameConnectionObjectFlowsAgain()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        (PinholeConnection conn, PinholeConnection atA) = await ConnectPairAsync(a, b);
        Assert.Equal(PinholeConnectionState.Open, conn.State);

        var states = new List<PinholeConnectionState>();
        conn.StateChanged += s => { lock (states) { states.Add(s); } };

        // The interface "dies": new socket, new port, same connection objects.
        int portBefore = b.LocalPort;
        var sw = Stopwatch.StartNew();
        await b.Engine.SimulateInterfaceLossAsync().WaitAsync(Timeout);
        Assert.NotEqual(portBefore, b.LocalPort);

        await WaitForStateAsync(conn, PinholeConnectionState.Open, TimeSpan.FromSeconds(5));
        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"recovery took {sw.Elapsed}");

        // Same object, not a replacement: roaming must be invisible to the app.
        Assert.Same(conn, b.Connections.Single(c => c.PeerId == a.PeerId));

        // And datagrams flow in both directions on the rebound path.
        Assert.True(conn.Path.Since > DateTimeOffset.UnixEpoch, "the path snapshot carries its timestamp");
        await AssertExchangeAsync(conn, atA, "after rebind, B -> A");
        await AssertExchangeAsync(atA, conn, "after rebind, A -> B");

        lock (states)
        {
            Assert.Contains(PinholeConnectionState.Punching, states); // the outage was honest
            Assert.Contains(PinholeConnectionState.Open, states);     // and so was the recovery
        }
    }

    [Fact]
    public async Task DirectPathDeath_WithRelayConfigured_DegradesButKeepsFlowing()
    {
        using FakeTurnServer turn = new();
        var relay = new TurnServerConfig(turn.Control, "user", "pass");
        await using PinholeNode a = await PinholeNode.BindAsync(Opts(relays: [relay]));
        await using PinholeNode b = await PinholeNode.BindAsync(Opts(relays: [relay]));

        // Meet on the relay first (direct candidates withheld), then let the engine's
        // upgrade probing move the pair onto a direct path.
        string relayOnly = new ConnectionString(a.PeerId,
            ConnectionString.Parse(a.ConnectionString).Candidates.Where(c => c.Kind == CandidateKind.Relay).ToList()).ToString();
        (PinholeConnection conn, PinholeConnection atA) = await ConnectPairAsync(a, b, relayOnly);
        // On loopback the engine's direct-upgrade probing can land within the dial itself,
        // so the post-dial state is Degraded *or* already Open — the meet was on the relay
        // either way (the string carries no direct candidates).
        await WaitForStateAsync(conn, PinholeConnectionState.Open, Timeout);
        await WaitForStateAsync(atA, PinholeConnectionState.Open, Timeout);
        Assert.Equal(PathKind.Direct, conn.Path.Kind);

        // The direct path dies on both sides; the relay path survives.
        b.Engine.SimulateDirectPathDeath(a.PeerId);
        a.Engine.SimulateDirectPathDeath(b.PeerId);

        await WaitForStateAsync(conn, PinholeConnectionState.Degraded, Timeout);
        await WaitForStateAsync(atA, PinholeConnectionState.Degraded, Timeout);
        Assert.Equal(PathKind.Relay, conn.Path.Kind);
        Assert.Equal(PathKind.Relay, atA.Path.Kind);

        await AssertExchangeAsync(conn, atA, "degraded but alive, B -> A");
        await AssertExchangeAsync(atA, conn, "degraded but alive, A -> B");
    }

    [Fact]
    public async Task DirectPathDeath_WithoutRelay_IsHonestlyDead()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts(connectTimeout: TimeSpan.FromSeconds(3)));
        await using PinholeNode b = await PinholeNode.BindAsync(Opts(connectTimeout: TimeSpan.FromSeconds(3)));
        (PinholeConnection conn, _) = await ConnectPairAsync(a, b);
        Assert.Equal(PinholeConnectionState.Open, conn.State);

        b.Engine.SimulateDirectPathDeath(a.PeerId);
        a.Engine.SimulateDirectPathDeath(b.PeerId);

        // No relay to fall back to: after a bounded re-punch the connection admits it.
        await WaitForStateAsync(conn, PinholeConnectionState.Dead, Timeout);
        PinholeConnection atA = a.Connections.Single(c => c.PeerId == b.PeerId);
        await WaitForStateAsync(atA, PinholeConnectionState.Dead, Timeout);
        Assert.Throws<InvalidOperationException>(() => conn.Send("dead"u8));
    }

    [Fact]
    public async Task RoamNow_OnHealthyNetwork_DoesNotDisturb()
    {
        await using PinholeNode a = await PinholeNode.BindAsync(Opts());
        await using PinholeNode b = await PinholeNode.BindAsync(Opts());
        (PinholeConnection conn, PinholeConnection atA) = await ConnectPairAsync(a, b);

        await b.RoamNowAsync().WaitAsync(Timeout);
        Assert.Equal(PinholeConnectionState.Open, conn.State);
        await AssertExchangeAsync(conn, atA, "right after roam-now");
    }
}

/// <summary>Tiny poll helper so tests can await engine-internal transitions without busy loops.</summary>
internal static class TestPoll
{
    public static async Task UntilAsync(TimeSpan budget, Func<bool> condition)
    {
        var sw = Stopwatch.StartNew();
        while (!condition())
        {
            Assert.True(sw.Elapsed < budget, $"condition not met within {budget}");
            await Task.Delay(50);
        }
    }
}
