using System.Net;
using Xunit;

namespace Pinhole.Tests;

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

        PinholeOptions def = await PinholeOptions.ResolveAsync(new PinholeOptions { StunCatalog = Source });
        PinholeOptions customized = await PinholeOptions.ResolveAsync(
            new PinholeOptions { ConnectTimeout = TimeSpan.FromSeconds(30), StunCatalog = Source });

        Assert.Equal(PinholeOptions.PublicIrohRelays, def.ResolvedIrohRelays);
        Assert.Equal(PinholeOptions.PublicIrohRelays, customized.ResolvedIrohRelays);
        Assert.Equal(PinholeOptions.PublicDerpRelays, def.ResolvedDerpRelays);
        Assert.Equal(PinholeOptions.PublicDerpRelays, customized.ResolvedDerpRelays);
        Assert.Equal(catalog, def.ResolvedStun);
        Assert.Equal(catalog, customized.ResolvedStun);
        Assert.Equal(TimeSpan.FromSeconds(30), customized.ConnectTimeout);
        Assert.Empty(customized.ResolvedRelays);
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
    public async Task DerpDefaults_CanBeDisabledOrReplacedIndependentlyOfIroh()
    {
        PinholeOptions disabled = await PinholeOptions.ResolveAsync(new PinholeOptions { StunServers = [], DerpRelayUrls = [] });
        Assert.Empty(disabled.DerpRelayUrls!);
        Assert.Equal(PinholeOptions.PublicIrohRelays, disabled.ResolvedIrohRelays);
        Uri mine = new("https://my-derp.example.test/");
        PinholeOptions replaced = await PinholeOptions.ResolveAsync(new PinholeOptions { StunServers = [], IrohRelayUrls = [], DerpRelayUrls = [mine] });
        Assert.Equal(mine, Assert.Single(replaced.DerpRelayUrls!));
        Assert.Empty(replaced.ResolvedDerpRelays);
        await Assert.ThrowsAsync<ArgumentException>(() => PinholeOptions.ResolveAsync(new PinholeOptions
            { StunServers = [], DerpRelayUrls = [new("http://public.example.test/")] }));
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
            StunServers = [], IrohRelayUrls = [], DerpRelayUrls = [], Encryption = PinholeEncryption.Disabled,
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
            IrohRelayUrls = [], DerpRelayUrls = [],
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
            StunCatalog = _ => { Interlocked.Increment(ref lookedUp); return Task.FromResult(Array.Empty<IPEndPoint>()); },
        });

        await TestPoll.UntilAsync(Timeout, () => node.PublicEndpoints.Count > 0);

        Assert.Equal(0, lookedUp);
    }

    [Fact]
    public async Task BindTimeProbe_RetransmitsThroughDatagramLoss()
    {

        using FakeStunServer stun = new() { DropFirstRequests = 2 };
        await using var node = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [stun.LocalEndPoint],
            Relays = [],
            IrohRelayUrls = [], DerpRelayUrls = [],
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
        });

        await TestPoll.UntilAsync(Timeout, () => node.PublicEndpoints.Count > 0);
    }

    [Fact]
    public async Task EmptyLists_IndependentlyDisableTheirProviders()
    {
        using FakeStunServer stun = new();
        await using var withStun = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [stun.LocalEndPoint],
            Relays = [],
            IrohRelayUrls = [], DerpRelayUrls = [],
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
        });
        await using var withoutStun = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [],
            Relays = [],
            IrohRelayUrls = [], DerpRelayUrls = [],
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
        });

        await TestPoll.UntilAsync(Timeout, () => withStun.PublicEndpoints.Count > 0);
        await Task.Delay(200);
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
            IrohRelayUrls = [], DerpRelayUrls = [],
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
            BindProbeBudget = TimeSpan.FromSeconds(1),
        }));

        await Task.Delay(300);
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
    public async Task BlackHoledStunCatalog_CannotStallTheBind_BeyondItsBudget()
    {

        var never = new TaskCompletionSource<IPEndPoint[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var options = new PinholeOptions
        {
            Relays = [], IrohRelayUrls = [], DerpRelayUrls = [],
            PublishIrohAddress = false, EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
            BindProbeBudget = TimeSpan.FromSeconds(1),
            StunCatalog = _ => never.Task,
        };

        using var backstop = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await using PinholeNode node = await PinholeNode.BindAsync(options, backstop.Token)
            .WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Empty(node.PublicEndpoints);
    }

    [Fact]
    public async Task CancelledWhileResolutionHangs_HaltsTheBindPromptly()
    {

        var never = new TaskCompletionSource<IPEndPoint[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        var options = new PinholeOptions
        {
            Relays = [], IrohRelayUrls = [], DerpRelayUrls = [],
            PublishIrohAddress = false, EnableLanDiscovery = false,
            EnableNetworkWatch = false, EnablePortMapping = false,
            StunCatalog = _ => never.Task,
        };

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => PinholeNode.BindAsync(options, cts.Token).WaitAsync(TimeSpan.FromSeconds(8)));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(4), $"cancellation took {sw.Elapsed.TotalSeconds:F1}s to halt the bind");
    }

    [Fact]
    public async Task InvalidKnobs_FailFastAtBind()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [], Relays = [], IrohRelayUrls = [], DerpRelayUrls = [], ReceiveBufferCapacity = -1,
        }));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [], Relays = [], IrohRelayUrls = [], DerpRelayUrls = [], ReceiveBufferCapacity = 65537,
        }));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [], Relays = [], IrohRelayUrls = [], DerpRelayUrls = [], PathValidationIdle = TimeSpan.FromMilliseconds(1),
        }));
    }
}
