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
        AdvertiseLinkLocal = advertiseLinkLocal,
    };

    private static bool HostHasRadioOrEthernetLinkLocal() =>
        NetworkInterface.GetAllNetworkInterfaces().Any(nic =>
            nic.OperationalStatus == OperationalStatus.Up
            && nic.NetworkInterfaceType is NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.Ethernet
            && nic.GetIPProperties().UnicastAddresses.Any(a => a.Address.IsIPv6LinkLocal));

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
