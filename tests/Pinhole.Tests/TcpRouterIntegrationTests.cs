using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Independent loopback router fixtures. These require OS socket permission
/// and remain pending in the restricted editing session.</summary>
public sealed class TcpRouterIntegrationTests
{
    // Readiness polling, not a performance floor: PCP discovery alone carries an
    // eight-second budget and mappings serialize per transport, so a busy runner can
    // legitimately need longer than discovery+mapping+polling stacked together.
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(25);
    [Fact]
    public async Task DefaultTcpSidecar_GetsItsOwnMappedCandidateAndReleasesBothProtocols()
    {
        using var gateway = new FakeGateway();
        var node = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [], IrohRelayUrls = [], PublishIrohAddress = false,
            EnableLanDiscovery = false, EnableNetworkWatch = false,
            GatewayOverride = [gateway.Endpoint], PortMappingLease = TimeSpan.FromSeconds(30),
        });
        var udp = new IPEndPoint(IPAddress.Parse("203.0.113.66"), 44444);
        var tcp = new IPEndPoint(IPAddress.Parse("203.0.113.66"), 44445);
        try
        {
            await TestPoll.UntilAsync(Budget, () => node.PortMappedEndpoint is not null
                && ConnectionString.Parse(node.ConnectionString).Candidates.Any(c => c.Kind == CandidateKind.Reflexive && c.Address.Equals(tcp)));
            Assert.Equal(udp, node.PortMappedEndpoint);
            Assert.Equal(node.LocalPort, node.TcpListeningPort);
            Assert.Equal(tcp, node.TcpPortMappedEndpoint);
            Assert.Contains(gateway.PcpRequests, bytes => bytes[36] == 6);
            Assert.Contains(gateway.PcpRequests, bytes => bytes[36] == 17);
        }
        finally { await node.DisposeAsync(); }
        await TestPoll.UntilAsync(Budget, () => gateway.Actions.Any(a => a.StartsWith("pcp-delete") && a.Contains("proto=TCP"))
            && gateway.Actions.Any(a => a.StartsWith("pcp-delete") && a.Contains("proto=UDP")));
    }

    [Fact]
    public async Task NatPmpTcp_RenewsAndDeletesOpcodeTwoMapping()
    {
        using var gateway = new FakeGateway();
        using var timeout = new CancellationTokenSource(Budget);
        using NatPmpClient.PmpMapping? lease = await NatPmpClient.TryMapAsync([gateway.Endpoint], 53317,
            TimeSpan.FromSeconds(30), timeout.Token, ProtocolType.Tcp);
        Assert.NotNull(lease);
        Assert.Equal(44445, lease.External.Port);
        Assert.True(await lease.RenewAsync(timeout.Token));
        await lease.ReleaseAsync(timeout.Token);
        Assert.Contains(gateway.Actions, a => a.StartsWith("pmp-delete") && a.Contains("ext=0") && a.Contains("proto=TCP"));
    }

    [Fact]
    public async Task UpnpTcp_LeaseSurvivesDisposingDiscoveryAndRenewsTheGrantedPort()
    {
        await using var gateway = new FakeUpnpIgd();
        using var timeout = new CancellationTokenSource(Budget);
        UpnpIgdClient.UpnpMapping? mapped;
        using (var discovery = new UpnpIgdClient())
            mapped = await discovery.TryMapAsync(53317, TimeSpan.FromSeconds(30), gateway.SsdpEndpoint, timeout.Token, ProtocolType.Tcp);
        Assert.NotNull(mapped);
        using (mapped)
        {
            Assert.Equal(55556, mapped.External.Port);
            Assert.True(await mapped.RenewAsync(timeout.Token));
            await mapped.ReleaseAsync(timeout.Token);
            Assert.Contains(gateway.Actions, a => a.StartsWith("AddPortMapping external=55556") && a.Contains("proto=TCP"));
            Assert.Contains(gateway.Actions, a => a.StartsWith("DeletePortMapping external=55556") && a.Contains("proto=TCP"));
        }
    }
}
