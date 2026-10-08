using System.Net;
using System.Net.NetworkInformation;
using Xunit;

namespace Pinhole.Tests;

public sealed class CandidateAdvertisementTests
{
    private static PinholeOptions Options(bool advertiseLinkLocal) => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [],
        EnableNetworkWatch = false,
        EnablePortMapping = false,
        AdvertiseLinkLocal = advertiseLinkLocal,
    };

    private static bool HostHasRadioOrEthernetLinkLocal() =>
        NetworkInterface.GetAllNetworkInterfaces().Any(nic =>
            nic.OperationalStatus == OperationalStatus.Up
            && nic.NetworkInterfaceType is NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.Ethernet
            && nic.GetIPProperties().UnicastAddresses.Any(a => a.Address.IsIPv6LinkLocal));

    [Fact]
    public async Task DefaultOptions_IncludeLanFallbacks()
    {
        Assert.True(new PinholeOptions().AdvertiseLinkLocal);
        await using var node = await PinholeNode.BindAsync(Options(new PinholeOptions().AdvertiseLinkLocal));
        if (HostHasRadioOrEthernetLinkLocal())
            Assert.Contains(ConnectionString.Parse(node.ConnectionString).Candidates, candidate => candidate.Address.Address.IsIPv6LinkLocal);
    }

    [Fact]
    public void BareLinkLocal_TriesEveryDistinctLocalScope_AndKeepsExplicitScope()
    {
        var bare = new IPEndPoint(IPAddress.Parse("fe80::1234"), 12345);
        var scoped = NodeEngine.ScopeLinkLocal(bare, [0, 3, 5, 3]);
        Assert.Equal(new long[] { 3, 5 }, scoped.Select(ep => ep.Address.ScopeId));
        Assert.All(scoped, ep => Assert.Equal(bare.Port, ep.Port));
        Assert.Empty(NodeEngine.ScopeLinkLocal(bare, []));
        var explicitScope = new IPEndPoint(IPAddress.Parse("fe80::1234%7"), 12345);
        Assert.Same(explicitScope, Assert.Single(NodeEngine.ScopeLinkLocal(explicitScope, [3, 5])));
        var ipv4 = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 12345);
        Assert.Same(ipv4, Assert.Single(NodeEngine.ScopeLinkLocal(ipv4, [3, 5])));
    }

    [Fact]
    public async Task LinkLocalStaysOutOfCandidates_WhenNotOptedIn()
    {
        await using PinholeNode node = await PinholeNode.BindAsync(Options(advertiseLinkLocal: false));
        ConnectionString cs = ConnectionString.Parse(node.ConnectionString);
        Assert.DoesNotContain(cs.Candidates, c => c.Kind == CandidateKind.Direct && c.Address.Address.IsIPv6LinkLocal);
    }

    [Fact]
    public async Task LinkLocalRidesTheTicket_BareAndCappedAtTwo_WhenOptedIn()
    {
        if (!HostHasRadioOrEthernetLinkLocal())
        {
            return; // nothing to advertise on this host; the opt-out case above covers it
        }

        await using PinholeNode node = await PinholeNode.BindAsync(Options(advertiseLinkLocal: true));
        ConnectionString cs = ConnectionString.Parse(node.ConnectionString);
        var linkLocal = cs.Candidates
            .Where(c => c.Kind == CandidateKind.Direct && c.Address.Address.IsIPv6LinkLocal)
            .ToList();
        Assert.InRange(linkLocal.Count, 1, 2);
        Assert.All(linkLocal, c => Assert.Equal(0, c.Address.Address.ScopeId)); // bare: scope is the sender's concern
    }
}
