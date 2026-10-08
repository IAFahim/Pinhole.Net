using System.Net;
using System.Security.Cryptography;
using System.Text;
using Pinhole.Rendezvous;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

/// <summary>#30 — recovery across independent relay failures and changed allocations. All
/// TURN servers here run with short allocation lifetimes so a killed server is detected by
/// the refresh loop in seconds, not minutes, and all of them enforce the RFC receive-side
/// permission gate (StrictInbound, the FakeTurnServer default): a relayed frame is only
/// delivered to an allocation that permitted the sender's relayed address, exactly like a
/// real coturn. Every relayed scenario in this file therefore also proves the permission
/// bootstrap (own-server permits, announce-learned permits) works under strict rules.</summary>
public sealed class RelayFailoverTests
{
    private readonly ITestOutputHelper _output;
    private const int Lifetime = 12; // seconds: refresh ticks clamp to 5s; expiry leaves two spare ticks, and a dead server is declared after 3 missed ticks (≈15s)

    // A relay-first dial is a chain of TURN round trips (allocation, permission, sealed
    // handshake); under a fully parallel suite its honest duration stretches past the 15 s
    // production default, and the engine would condemn its own dial. This class measures
    // failover behavior, not dial latency — the dials get headroom, and passing runs never
    // wait for it (the awaits complete the moment the handshake lands).
    private static readonly TimeSpan RelayHandshake = TimeSpan.FromSeconds(45);

    public RelayFailoverTests(ITestOutputHelper output) => _output = output;

    private static async Task<(PinholeConnection DialerSide, PinholeConnection ListenerSide)> ConnectAsync(
        PinholeNode listener, PinholeNode dialer, string? listenerString = null)
    {
        Task<PinholeConnection> accept = listener.AcceptAsync();
        PinholeConnection dialerSide = await dialer.ConnectAsync(listenerString ?? listener.ConnectionString).WaitAsync(RelayHandshake);
        PinholeConnection listenerSide = await accept.WaitAsync(RelayHandshake);
        return (dialerSide, listenerSide);
    }

    /// <summary>Non-throwing exchange probe for polling a wounded session: true when the
    /// marker made it across within the local budget.</summary>
    private static async Task<bool> TryExchangeAsync(PinholeConnection from, PinholeConnection to, string marker)
    {
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        void Handler(ReadOnlySpan<byte> payload) => got.TrySetResult(payload.ToArray());
        to.Received += Handler;
        try
        {
            from.Send(Encoding.UTF8.GetBytes(marker));
            var done = await Task.WhenAny(got.Task, Task.Delay(TimeSpan.FromSeconds(3)));
            return done == got.Task && Encoding.UTF8.GetString(got.Task.Result) == marker;
        }
        catch (InvalidOperationException)
        {
            return false; // pathless pending state: sending is refused until a path returns
        }
        finally
        {
            to.Received -= Handler;
        }
    }

    /// <summary>Binds a relay-only node: every direct datagram dies in the virtual internet,
    /// so the session physically cannot exist without the TURN path. The dial budget matches
    /// <see cref="RelayHandshake"/> so the engine does not condemn its own relay-first dial
    /// under suite load.</summary>
    private static Task<PinholeNode> RelayOnlyNodeAsync(VirtualLab lab, VirtualNat nat,
        Func<PinholeOptions, PinholeOptions>? tweak = null)
    {
        nat.BlockAllOutboundDirect = true;
        return lab.BindNodeAsync(nat, tweak: o => (tweak?.Invoke(o) ?? o) with
        {
            ConnectTimeout = RelayHandshake,
        });
    }

    /// <summary>Settle-tolerant exchange: polls the probe until the marker lands or the
    /// budget dies. Use anywhere a freshly connected relay path may still be confirming.</summary>
    private static async Task<bool> ExchangeUntilAsync(PinholeConnection from, PinholeConnection to, string marker, TimeSpan budget)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < budget)
        {
            if (await TryExchangeAsync(from, to, marker))
            {
                return true;
            }

            await Task.Delay(500);
        }

        return false;
    }

    [Fact]
    public async Task TwoRelays_LoseOne_RelayOnlySessionSurvivesOnTheSurvivor()
    {
        using VirtualLab lab = new(withTurn: true, turnLifetimeSeconds: Lifetime);
        FakeTurnServer x = lab.Turn!;
        FakeTurnServer y = lab.AddTurn(lifetimeSeconds: Lifetime);
        VirtualNat natA = lab.Nat(VirtualNatKind.FullCone, "203.0.113.10", "172.31.10.0/24");
        VirtualNat natB = lab.Nat(VirtualNatKind.FullCone, "203.0.113.20", "172.31.20.0/24");

        await using PinholeNode a = await RelayOnlyNodeAsync(lab, natA);
        await using PinholeNode b = await RelayOnlyNodeAsync(lab, natB);
        Assert.Equal(2, a.Engine.RelaysConfiguredCount);
        (PinholeConnection atA, PinholeConnection atB) = await ConnectAsync(b, a);
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(15), () => atA.Path.Kind == PathKind.Relay);
        Assert.True(await ExchangeUntilAsync(atA, atB, "before the failure", TimeSpan.FromSeconds(25)),
            "relay-only session never flowed before the failure");

        // One whole relay dies. The session must keep flowing — same connection objects,
        // no ticket, no application action — on the surviving server.
        x.Dispose();
        bool healed = false;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < TimeSpan.FromSeconds(75) && !healed)
        {
            healed = await TryExchangeAsync(atA, atB, $"after x died {sw.ElapsedMilliseconds}");
            if (!healed)
            {
                await Task.Delay(250);
            }
        }

        Assert.True(healed, $"relay-only session did not survive the loss of one of two relays ({sw.Elapsed}); " +
            $"A={atA.State}/{atA.Path.Kind} leg={a.Engine.PeerRelayLeg(b.PeerId)} B={atB.State}/{atB.Path.Kind} leg={b.Engine.PeerRelayLeg(a.PeerId)}");
        Assert.Equal(PathKind.Relay, atA.Path.Kind);
        Assert.True(y.Allocations >= 2, $"the survivor carried the pair: {y.Allocations} allocations");
        _output.WriteLine($"healed in {sw.Elapsed.TotalMilliseconds:F0} ms on the surviving relay");
    }

    /// <summary>The 1.9.0 known gap, closed: a relay restarting in place changes BOTH peers'
    /// relayed addresses. With no direct path and no fresh ticket, the pair must re-find each
    /// other — reallocation announcements plus the authenticated address records of #29 —
    /// and the same session object must come back to life.</summary>
    [Fact]
    public async Task RelayRestartInPlace_BothAllocationsChange_SessionHealsWithoutFreshTicket()
    {
        await using RendezvousServer rendezvous = RendezvousServer.Start();
        IPEndPoint lookup = new(IPAddress.IPv6Loopback, rendezvous.LocalEndPoint.Port);
        using VirtualLab lab = new(withTurn: true, turnLifetimeSeconds: Lifetime);
        FakeTurnServer x = lab.Turn!;
        byte[] seedA = RandomNumberGenerator.GetBytes(32);
        byte[] seedB = RandomNumberGenerator.GetBytes(32);
        VirtualNat natA = lab.Nat(VirtualNatKind.FullCone, "203.0.113.10", "172.31.10.0/24");
        VirtualNat natB = lab.Nat(VirtualNatKind.FullCone, "203.0.113.20", "172.31.20.0/24");
        await using PinholeNode a = await RelayOnlyNodeAsync(lab, natA,
            o => o with { IdentityKeySeed = seedA, RendezvousEndpoints = [lookup] });
        await using PinholeNode b = await RelayOnlyNodeAsync(lab, natB,
            o => o with { IdentityKeySeed = seedB, RendezvousEndpoints = [lookup] });

        (PinholeConnection atA, PinholeConnection atB) = await ConnectAsync(b, a);
        PinholeConnection wounded = atA;
        string ticket = a.ConnectionString;
        IPEndPoint oldRelayedA = RelayCandidate(a).Address;
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(15), () => wounded.Path.Kind == PathKind.Relay);
        Assert.True(await ExchangeUntilAsync(atA, atB, "before the restart", TimeSpan.FromSeconds(15)));

        // The relay dies and comes back on the same port: every allocation it ever handed
        // out is gone, so both peers' relayed addresses change.
        IPEndPoint where = x.Control;
        x.Dispose();
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(30),
            () => wounded.State is PinholeConnectionState.Punching or PinholeConnectionState.Degraded);
        Assert.False(await TryExchangeAsync(atA, atB, "must be down while the relay is gone"),
            "the session must not flow while its only relay is gone");
        FakeTurnServer revived = new(port: where.Port, lifetimeSeconds: Lifetime, bindAddress: where.Address);

        // Time compression only: the ladder wait before a retry is expedited the way its
        // natural 30 s step would expire; every other mechanism runs at real speed.
        a.Engine.TestExpediteRelayRetry();
        b.Engine.TestExpediteRelayRetry();

        bool healed = false;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < TimeSpan.FromSeconds(75) && !healed)
        {
            healed = await TryExchangeAsync(atA, atB, $"after restart {sw.ElapsedMilliseconds}");
            if (!healed)
            {
                await Task.Delay(250);
            }
        }

        try
        {
            Assert.True(healed, $"the session never healed after the in-place relay restart ({sw.Elapsed})");
            Assert.Same(wounded, atA); // the very same connection object, never redialed
            Assert.Equal(PathKind.Relay, atA.Path.Kind);
            Assert.True(revived.Allocations >= 2, "both peers reallocated on the revived server");
            Assert.NotEqual(oldRelayedA, RelayCandidate(a).Address);
            _output.WriteLine($"healed in {sw.Elapsed.TotalSeconds:F1} s after restart; new relayed address {RelayCandidate(a).Address}");
        }
        finally
        {
            revived.Dispose();
        }
    }

    /// <summary>Peers with different relay preferences (an operator A trusts X and Y, an
    /// operator B trusts Y and Z) still meet through their one common usable relay — the
    /// same-server send routing carries the punch, no shared configuration needed.</summary>
    [Fact]
    public async Task DifferingRelayLists_MeetThroughTheCommonRelay()
    {
        using VirtualLab lab = new(withTurn: true, turnLifetimeSeconds: Lifetime);
        FakeTurnServer y = lab.Turn!;
        FakeTurnServer x = lab.AddTurn(lifetimeSeconds: Lifetime);
        FakeTurnServer z = lab.AddTurn(lifetimeSeconds: Lifetime);

        VirtualNat natA = lab.Nat(VirtualNatKind.FullCone, "203.0.113.10", "172.31.10.0/24");
        VirtualNat natB = lab.Nat(VirtualNatKind.FullCone, "203.0.113.20", "172.31.20.0/24");
        await using PinholeNode a = await RelayOnlyNodeAsync(lab, natA,
            o => o with { Relays = [ConfigFor(x), ConfigFor(y)] });
        await using PinholeNode b = await RelayOnlyNodeAsync(lab, natB,
            o => o with { Relays = [ConfigFor(y), ConfigFor(z)] });

        (PinholeConnection atA, PinholeConnection atB) = await ConnectAsync(b, a);
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(15), () => atA.Path.Kind == PathKind.Relay);
        Assert.True(await ExchangeUntilAsync(atA, atB, "common relay", TimeSpan.FromSeconds(15)));
        Assert.True(await TryExchangeAsync(atB, atA, "common relay, reverse"));
        _output.WriteLine($"met through relay Y ({y.Control.Port}); X and Z carry no session");
    }

    /// <summary>A rate-limiting or quota-refusing relay must cost bounded retries, never a
    /// reconnect storm — and the moment it accepts again, the node recovers its allocation.</summary>
    [Fact]
    public async Task QuotaRefusal_RetriesAreBoundedAndRecoveryIsImmediate()
    {
        using VirtualLab lab = new(withTurn: true, turnLifetimeSeconds: Lifetime);
        FakeTurnServer x = lab.Turn!;
        x.RejectAllocationsWithCode = 429;

        VirtualNat nat = lab.Nat(VirtualNatKind.FullCone, "203.0.113.10", "172.31.10.0/24");
        await using PinholeNode node = await lab.BindNodeAsync(nat);
        Assert.Equal(0, x.Allocations);
        int afterBind = x.AllocateRejections;

        // While the quota stands, forced ensures inside the backoff window attempt NOTHING:
        // the ladder gates every retry, which is precisely the no-storm property.
        await node.Engine.ForceRelayEnsureAsync();
        await node.Engine.ForceRelayEnsureAsync();
        Assert.Equal(0, x.Allocations);
        Assert.Equal(afterBind, x.AllocateRejections);

        // One deliberate attempt per ladder step, not a flood: expedite the (compressed)
        // ladder twice more and each pass costs at most one rejected ALLOCATE.
        node.Engine.TestExpediteRelayRetry();
        await node.Engine.ForceRelayEnsureAsync();
        node.Engine.TestExpediteRelayRetry();
        await node.Engine.ForceRelayEnsureAsync();
        Assert.Equal(0, x.Allocations);
        int rejections = x.AllocateRejections - afterBind;
        Assert.InRange(rejections, 2, 2);

        x.RejectAllocationsWithCode = 0;
        node.Engine.TestExpediteRelayRetry();
        await node.Engine.ForceRelayEnsureAsync();
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(10), () => x.Allocations == 1);
        _output.WriteLine($"quota refusal cost {rejections} rejected attempts across ladder steps; recovery was immediate");
    }

    /// <summary>Every relay down at once: the session enters an explained pending state (it
    /// must NOT close and must NOT silently claim health), and when infrastructure returns
    /// it recovers on its own.</summary>
    [Fact]
    public async Task AllRelaysTemporarilyDown_SessionPendsThenRecoversOnRestoration()
    {
        // When EVERY relay dies, both peers' relayed addresses change on revival — the same
        // both-endpoints-moved situation as the in-place restart, so the same authenticated
        // lookup route (seeds + rendezvous records) is what carries the recovery.
        await using RendezvousServer rendezvous = RendezvousServer.Start();
        IPEndPoint lookup = new(IPAddress.IPv6Loopback, rendezvous.LocalEndPoint.Port);
        using VirtualLab lab = new(withTurn: true, turnLifetimeSeconds: Lifetime);
        FakeTurnServer x = lab.Turn!;
        FakeTurnServer y = lab.AddTurn(lifetimeSeconds: Lifetime);
        byte[] seedA = RandomNumberGenerator.GetBytes(32);
        byte[] seedB = RandomNumberGenerator.GetBytes(32);

        VirtualNat natA = lab.Nat(VirtualNatKind.FullCone, "203.0.113.10", "172.31.10.0/24");
        VirtualNat natB = lab.Nat(VirtualNatKind.FullCone, "203.0.113.20", "172.31.20.0/24");
        await using PinholeNode a = await RelayOnlyNodeAsync(lab, natA,
            o => o with { IdentityKeySeed = seedA, RendezvousEndpoints = [lookup] });
        await using PinholeNode b = await RelayOnlyNodeAsync(lab, natB,
            o => o with { IdentityKeySeed = seedB, RendezvousEndpoints = [lookup] });
        (PinholeConnection atA, PinholeConnection atB) = await ConnectAsync(b, a);
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(15), () => atA.Path.Kind == PathKind.Relay);
        Assert.True(await ExchangeUntilAsync(atA, atB, "before the outage", TimeSpan.FromSeconds(25)));

        IPEndPoint whereX = x.Control, whereY = y.Control;
        x.Dispose();
        y.Dispose();

        // Pending, not closed: the connection objects stay alive in a non-Open state while
        // every route is gone — an honest "waiting for infrastructure" instead of a lie.
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(30),
            () => atA.State is PinholeConnectionState.Punching or PinholeConnectionState.Degraded);
        Assert.False(await TryExchangeAsync(atA, atB, "nothing flows while every relay is down"));

        FakeTurnServer backX = new(port: whereX.Port, lifetimeSeconds: Lifetime, bindAddress: whereX.Address);
        FakeTurnServer backY = new(port: whereY.Port, lifetimeSeconds: Lifetime, bindAddress: whereY.Address);
        a.Engine.TestExpediteRelayRetry(); // ladder expiry compressed; mechanisms at real speed
        b.Engine.TestExpediteRelayRetry();
        try
        {
            bool healed = false;
            var sw = System.Diagnostics.Stopwatch.StartNew();
            while (sw.Elapsed < TimeSpan.FromSeconds(90) && !healed)
            {
                healed = await TryExchangeAsync(atA, atB, $"restored {sw.ElapsedMilliseconds}");
                if (!healed)
                {
                    await Task.Delay(250);
                }
            }

            Assert.True(healed, $"session did not recover after infrastructure returned ({sw.Elapsed})");
            Assert.Equal(PathKind.Relay, atA.Path.Kind);
            _output.WriteLine($"recovered {sw.Elapsed.TotalSeconds:F1} s after both relays returned");
        }
        finally
        {
            backX.Dispose();
            backY.Dispose();
        }
    }

    /// <summary>HTTPS relay DNS failures are contained: a hostname that never resolves costs
    /// that relay candidate and its reconnect backoff — never the bind, never the direct
    /// path. (TURN relays are configured by IP by design, so unreachable DNS applies to the
    /// iroh leg.)</summary>
    [Fact]
    public async Task UnresolvableIrohHostname_DirectPathUnaffected()
    {
        var options = new PinholeOptions
        {
            StunServers = [],
            IrohRelayUrls = [new Uri("https://relay-that-does-not-resolve.invalid/")],
            PublishIrohAddress = false,
            EnableNetworkWatch = false,
            EnablePortMapping = false,
            EnableLanDiscovery = false,
        };

        var sw = System.Diagnostics.Stopwatch.StartNew();
        await using PinholeNode a = await PinholeNode.BindAsync(options);
        await using PinholeNode b = await PinholeNode.BindAsync(options with { });
        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), $"bind hung on DNS for {sw.Elapsed}");
        Assert.False(a.HasRelay);

        Task<PinholeConnection> accept = b.AcceptAsync();
        await using PinholeConnection conn = await a.ConnectAsync(b.ConnectionString).WaitAsync(TestBudget.Handshake);
        await using PinholeConnection accepted = await accept.WaitAsync(TestBudget.Handshake);
        var got = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        accepted.Received += p => got.TrySetResult(p.ToArray());
        conn.Send(Encoding.UTF8.GetBytes("direct, dead relay list"));
        Assert.Equal("direct, dead relay list", Encoding.UTF8.GetString(await got.Task.WaitAsync(TestBudget.Io)));
    }

    private static PinholeCandidate RelayCandidate(PinholeNode node) =>
        Pinhole.ConnectionString.Parse(node.ConnectionString).Candidates.First(c => c.Kind == CandidateKind.Relay);

    private static TurnServerConfig ConfigFor(FakeTurnServer server) =>
        new(server.Control, "user", "pass");
}
