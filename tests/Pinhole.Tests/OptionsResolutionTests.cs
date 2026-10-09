using System.Net;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Issue #11: customizing one PinholeOptions setting must not silently drop the
/// free STUN/relay defaults. Precedence per infrastructure setting: null = defaults,
/// empty list = disabled, explicit entries = replace. All resolution goes through
/// injected catalogs — no public-service dependency anywhere in this suite.</summary>
public sealed class OptionsResolutionTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static int _catalogCalls;

    private static PinholeOptions Partial(PinholeOptions options) => options with
    {
        StunCatalog = _ => { Interlocked.Increment(ref _catalogCalls); return Task.FromResult(Array.Empty<IPEndPoint>()); },
        RelayCatalog = _ => { Interlocked.Increment(ref _catalogCalls); return Task.FromResult(Array.Empty<IPEndPoint>()); },
    };

    [Fact]
    public async Task TimeoutOnlyOptions_GetTheSameInfrastructureAsParameterless()
    {
        var catalog = new[] { new IPEndPoint(IPAddress.Parse("198.51.100.1"), 3478) };
        Task<IPEndPoint[]> Source(CancellationToken _) => Task.FromResult<IPEndPoint[]>(catalog);

        // The parameterless default and a timeout-only customization resolve the exact
        // same infrastructure when they see the same catalog.
        PinholeOptions def = await PinholeOptions.ResolveAsync(new PinholeOptions { StunCatalog = Source });
        PinholeOptions customized = await PinholeOptions.ResolveAsync(
            new PinholeOptions { ConnectTimeout = TimeSpan.FromSeconds(30), StunCatalog = Source });

        Assert.Equal(PinholeOptions.PublicIrohRelays, def.ResolvedIrohRelays);
        Assert.Equal(PinholeOptions.PublicIrohRelays, customized.ResolvedIrohRelays);
        Assert.Equal(catalog, def.ResolvedStun);
        Assert.Equal(catalog, customized.ResolvedStun);
        Assert.Equal(TimeSpan.FromSeconds(30), customized.ConnectTimeout); // scalar kept
        Assert.Empty(customized.ResolvedRelays);                            // no TURN by default
        Assert.True(def.EnableLanDiscovery);
        Assert.True(customized.EnableLanDiscovery);
        Assert.True(def.PublishIrohAddress);
        Assert.True(customized.PublishIrohAddress);
        Assert.True(def.PublishDirectIrohAddresses);
        Assert.True(customized.PublishDirectIrohAddresses);
        Assert.True(def.EnableTcpTransport);
        Assert.True(def.EnableDirectUdp);
        Assert.True(def.EnableIPv6FirewallPinholes);
        Assert.True(customized.EnableIPv6FirewallPinholes);
        Assert.False(def.RelaySignalingOnly);
        Assert.True(def.EnableInterfaceCandidates);
        Assert.True(def.EnablePortPrediction);
        Assert.True(customized.EnablePortPrediction);
    }

    [Fact]
    public async Task DiscoveryOptOuts_SurviveInfrastructureResolution()
    {
        PinholeOptions resolved = await PinholeOptions.ResolveAsync(Partial(new PinholeOptions
        {
            EnableLanDiscovery = false, PublishIrohAddress = false, PublishDirectIrohAddresses = false,
            EnableTcpTransport = false, EnableDirectUdp = false,
            EnableIPv6FirewallPinholes = false,
            RelaySignalingOnly = true,
            EnableInterfaceCandidates = false,
            EnablePortPrediction = false,
        }));
        Assert.Equal(PinholeOptions.PublicIrohRelays, resolved.ResolvedIrohRelays);
        Assert.False(resolved.EnableLanDiscovery);
        Assert.False(resolved.PublishIrohAddress);
        Assert.False(resolved.PublishDirectIrohAddresses);
        Assert.False(resolved.EnableTcpTransport);
        Assert.False(resolved.EnableDirectUdp);
        Assert.False(resolved.EnableIPv6FirewallPinholes);
        Assert.True(resolved.RelaySignalingOnly);
        Assert.False(resolved.EnableInterfaceCandidates);
        Assert.False(resolved.EnablePortPrediction);
    }

    [Fact]
    public async Task PlaintextNodes_MustOptOutOfSignedSessionPublication()
    {
        var options = new PinholeOptions
        {
            StunServers = [], IrohRelayUrls = [], Encryption = PinholeEncryption.Disabled,
            EnableNetworkWatch = false, EnablePortMapping = false, EnableLanDiscovery = false,
        };
        await Assert.ThrowsAsync<ArgumentException>(() => PinholeNode.BindAsync(options));
        await using var node = await PinholeNode.BindAsync(options with { PublishIrohAddress = false });
        Assert.Null(node.StaticPublicKey);
    }

    [Fact]
    public async Task ExplicitEndpoints_ReplaceDefaults_AndProbeTheRightServers()
    {
        using FakeStunServer mine = new();
        int lookedUp = 0;
        await using var node = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [mine.LocalEndPoint],
            Relays = [],
            IrohRelayUrls = [],
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
            StunCatalog = _ => { Interlocked.Increment(ref lookedUp); return Task.FromResult(Array.Empty<IPEndPoint>()); },
        });

        // The caller's server was probed for real (the reflexive candidate landed)…
        await TestPoll.UntilAsync(Timeout, () => node.PublicEndpoints.Count > 0);
        // …and the free catalog was never consulted.
        Assert.Equal(0, lookedUp);
    }

    [Fact]
    public async Task EmptyLists_IndependentlyDisableTheirProviders()
    {
        using FakeStunServer stun = new();
        await using var withStun = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [stun.LocalEndPoint],
            Relays = [],
            IrohRelayUrls = [],
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
        });
        await using var withoutStun = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [],
            Relays = [],
            IrohRelayUrls = [],
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
        });

        await TestPoll.UntilAsync(Timeout, () => withStun.PublicEndpoints.Count > 0);
        await Task.Delay(200); // an empty STUN list is structural: nothing can appear late
        Assert.Empty(withoutStun.PublicEndpoints);
        Assert.False(withoutStun.HasRelay);
    }

    [Fact]
    public async Task AllInfrastructureEmpty_PerformsNoCatalogLookups()
    {
        Interlocked.Exchange(ref _catalogCalls, 0);
        await using var node = await PinholeNode.BindAsync(Partial(new PinholeOptions
        {
            StunServers = [],
            Relays = [],
            IrohRelayUrls = [],
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
            BindProbeBudget = TimeSpan.FromSeconds(1),
        }));

        await Task.Delay(300); // any stray warming would show up here
        Assert.Equal(0, Volatile.Read(ref _catalogCalls));
        Assert.False(node.HasRelay);
        Assert.Empty(node.PublicEndpoints);
    }

    [Fact]
    public async Task Cancellation_HaltsTheBind_BeforeAnyEngineExists()
    {
        using var stopped = new CancellationTokenSource();
        Task<IPEndPoint[]> Hanging(CancellationToken ct) => Task.FromCanceled<IPEndPoint[]>(ct);

        stopped.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => PinholeNode.BindAsync(new PinholeOptions
        {
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
            StunCatalog = Hanging,
        }, stopped.Token));
    }

    [Fact]
    public async Task InvalidKnobs_FailFastAtBind()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [], Relays = [], IrohRelayUrls = [], ReceiveBufferCapacity = -1,
        }));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [], Relays = [], IrohRelayUrls = [], ReceiveBufferCapacity = 65537,
        }));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [], Relays = [], IrohRelayUrls = [], PathValidationIdle = TimeSpan.FromMilliseconds(1),
        }));
    }
}
