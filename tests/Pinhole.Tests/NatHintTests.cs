using System.Net;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Automatic NAT classification — the netcheck iroh also performs: probe several
/// STUN servers, and either they all observe the same mapping (cone NAT, the reflexive
/// candidate is punchable) or they observe different ones (symmetric NAT, dialers should
/// skip the punch and go straight to relay).</summary>
public sealed class NatHintTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static IPEndPoint Mapping(int port) => new(IPAddress.Parse("198.51.100.7"), port);

    [Fact]
    public void DualStackObservations_CompareMappingsWithinEachFamily()
    {
        var v4 = Mapping(40000);
        var v6 = new IPEndPoint(IPAddress.Parse("2001:db8::7"), 50000);
        Assert.Equal(NatType.Unknown, NatDetector.Classify([v4, v6]));
        Assert.Equal(NatType.Cone, NatDetector.Classify([v4, v4, v6, v6]));
        Assert.Equal(NatType.Symmetric, NatDetector.Classify([v4, Mapping(41000), v6, v6]));
    }

    [Fact]
    public async Task SeparateFamilies_DoNotAdvertiseASymmetricHint()
    {
        using FakeStunServer v4 = new() { ReportMappedOverride = Mapping(40000) };
        using FakeStunServer v6 = new() { ReportMappedOverride = new IPEndPoint(IPAddress.Parse("2001:db8::7"), 50000) };
        await using var node = await BindAsync([v4.LocalEndPoint, v6.LocalEndPoint]);
        Assert.Equal(NatHint.Unknown, node.NatHint);
    }

    private static Task<PinholeNode> BindAsync(IReadOnlyList<IPEndPoint> stun, TimeSpan? refresh = null) =>
        PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = stun,
            Relays = [],
            IrohRelayUrls = [],
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false,
            EnablePathValidation = false,
            EnablePortMapping = false,
            StunRefreshInterval = refresh ?? TimeSpan.Zero,
        }).WaitAsync(Timeout);

    [Fact]
    public async Task SameMappingFromTwoServers_ClassifiesCone()
    {
        using FakeStunServer s1 = new() { ReportMappedOverride = Mapping(40000) };
        using FakeStunServer s2 = new() { ReportMappedOverride = Mapping(40000) };
        await using PinholeNode node = await BindAsync([s1.LocalEndPoint, s2.LocalEndPoint]);

        Assert.Equal(NatHint.Cone, node.NatHint);
        Assert.Equal(NatHint.Cone, ConnectionString.Parse(node.ConnectionString).NatHint);
    }

    [Fact]
    public async Task DivergentMappings_ClassifySymmetric_AndCarryIntoTheString()
    {
        using FakeStunServer s1 = new() { ReportMappedOverride = Mapping(40000) };
        using FakeStunServer s2 = new() { ReportMappedOverride = Mapping(41000) };
        await using PinholeNode node = await BindAsync([s1.LocalEndPoint, s2.LocalEndPoint]);

        Assert.Equal(NatHint.Symmetric, node.NatHint);
        Assert.Equal(NatHint.Symmetric, ConnectionString.Parse(node.ConnectionString).NatHint);
    }

    [Fact]
    public async Task ManualOverride_BeatsTheObservation()
    {
        using FakeStunServer s1 = new() { ReportMappedOverride = Mapping(40000) };
        using FakeStunServer s2 = new() { ReportMappedOverride = Mapping(41000) };
        await using PinholeNode node = await BindAsync([s1.LocalEndPoint, s2.LocalEndPoint]);
        Assert.Equal(NatHint.Symmetric, node.NatHint);

        node.SetNatHint(NatHint.Cone); // the app knows better than the observations
        Assert.Equal(NatHint.Cone, node.NatHint);
        Assert.Equal(NatHint.Cone, ConnectionString.Parse(node.ConnectionString).NatHint);

        node.SetNatHint(NatHint.Unknown); // back to automatic
        Assert.Equal(NatHint.Symmetric, node.NatHint);
    }

    [Fact]
    public async Task SingleServer_LeavesHintUnknown()
    {
        using FakeStunServer s1 = new();
        await using PinholeNode node = await BindAsync([s1.LocalEndPoint]);

        Assert.Equal(NatHint.Unknown, node.NatHint); // one observation can never distinguish
    }

    [Fact]
    public async Task Refresh_ReclassifiesWhenTheNetworkChanges()
    {
        using FakeStunServer s1 = new() { ReportMappedOverride = Mapping(40000) };
        using FakeStunServer s2 = new() { ReportMappedOverride = Mapping(40000) };
        await using PinholeNode node = await BindAsync([s1.LocalEndPoint, s2.LocalEndPoint],
            refresh: TimeSpan.FromMilliseconds(250));
        Assert.Equal(NatHint.Cone, node.NatHint);

        // The NAT is replaced by a symmetric one mid-session (mapping now per-destination).
        s2.ReportMappedOverride = Mapping(42000);
        await TestPoll.UntilAsync(Timeout, () => node.NatHint == NatHint.Symmetric);
    }
}
