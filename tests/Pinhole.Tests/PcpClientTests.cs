using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Pinhole.Tests;

public sealed class PcpClientTests
{
    // Hand-encoded from RFC 6887 figures 2, 3, 9 and 10, independently of the
    // production encoder and FakeGateway. Source 192.0.2.10, nonce 00..0b,
    // UDP port 53317, lifetime 30 seconds, assigned 203.0.113.66:44444.
    private static byte[] Request => Convert.FromHexString(
        "020100000000001E" + "00000000000000000000FFFFC000020A" +
        "000102030405060708090A0B" + "11000000D0450000" +
        "00000000000000000000FFFF00000000");

    private static byte[] Response => Convert.FromHexString(
        "028100000000001E00001234000000000000000000000000" +
        "000102030405060708090A0B" + "11000000D045AD9C" +
        "00000000000000000000FFFFCB007142");

    [Fact]
    public void MapRequest_MatchesIndependentRfcLayout()
    {
        byte[] actual = PcpClient.BuildMapRequest(Convert.FromHexString("000102030405060708090A0B"),
            IPAddress.Parse("192.0.2.10"), 53317, TimeSpan.FromSeconds(30));
        Assert.Equal(Request, actual);
    }

    [Fact]
    public void MapResponse_ReadsAssignedEndpointFromIndependentRfcLayout()
    {
        Assert.True(PcpClient.TryParseMapResponse(Response, Request, out IPEndPoint? external, out uint granted));
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.66"), 44444), external);
        Assert.Equal(30u, granted);
    }

    [Fact]
    public void Ipv6Mapping_UsesNativeAddressAndFamilySpecificUnspecifiedSuggestion()
    {
        byte[] expected = Convert.FromHexString(
            "020100000000001E" + "20010DB8000000000000000000000010" +
            "000102030405060708090A0B" + "11000000D0450000" +
            "00000000000000000000000000000000");
        byte[] actual = PcpClient.BuildMapRequest(Convert.FromHexString("000102030405060708090A0B"),
            IPAddress.Parse("2001:db8::10"), 53317, TimeSpan.FromSeconds(30));
        Assert.Equal(expected, actual);

        byte[] response = Convert.FromHexString(
            "028100000000001E00001234000000000000000000000000" +
            "000102030405060708090A0B" + "11000000D045AD9C" +
            "20010DB8000000000000000000000066");
        Assert.True(PcpClient.TryParseMapResponse(response, actual, out IPEndPoint? external, out _));
        Assert.Equal(new IPEndPoint(IPAddress.Parse("2001:db8::66"), 44444), external);
    }

    [Theory]
    [InlineData(0, 1)] // wrong version
    [InlineData(1, 130)] // PEER instead of MAP
    [InlineData(3, 8)] // NO_RESOURCES, at the PCP result-code offset
    [InlineData(24, 255)] // different nonce
    [InlineData(36, 6)] // TCP instead of UDP
    [InlineData(40, 0)] // another internal port
    public void MapResponse_RejectsErrorsAndUnrelatedMappings(int offset, byte value)
    {
        byte[] response = Response;
        response[offset] = value;
        Assert.False(PcpClient.TryParseMapResponse(response, Request, out _, out _));
    }

    [Fact]
    public void MapResponse_RejectsTruncationZeroLeaseAndInvalidEndpoint()
    {
        for (int length = 0; length < 60; length++)
            Assert.False(PcpClient.TryParseMapResponse(Response[..length], Request, out _, out _));
        Assert.False(PcpClient.TryParseMapResponse([.. Response, 0], Request, out _, out _));

        byte[] response = Response;
        response.AsSpan(4, 4).Clear();
        Assert.False(PcpClient.TryParseMapResponse(response, Request, out _, out _));
        response = Response;
        response.AsSpan(42, 2).Clear();
        Assert.False(PcpClient.TryParseMapResponse(response, Request, out _, out _));
        response = Response;
        response.AsSpan(44, 16).Clear();
        Assert.False(PcpClient.TryParseMapResponse(response, Request, out _, out _));
    }

    [Fact]
    public void MapResponse_IgnoresReservedBitsAsRequiredByRfc()
    {
        byte[] response = Response;
        response[2] = 255;
        response.AsSpan(12, 12).Fill(255);
        response.AsSpan(37, 3).Fill(255);
        Assert.True(PcpClient.TryParseMapResponse(response, Request, out _, out _));
    }

    [Fact]
    public async Task MapResponse_RejectsForgedSourceAndKeepsWaitingAfterUnrelatedReply()
    {
        using var gateway = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var attacker = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task<PcpClient.PcpMapping?> pending = PcpClient.TryMapAsync([(IPEndPoint)gateway.Client.LocalEndPoint!],
            53317, TimeSpan.FromSeconds(30), timeout.Token);
        UdpReceiveResult request = await gateway.ReceiveAsync(timeout.Token);
        byte[] response = Response;
        request.Buffer.AsSpan(24, 12).CopyTo(response.AsSpan(24));

        // A correct nonce and body must not make another UDP source authoritative.
        await attacker.SendAsync(response, request.RemoteEndPoint, timeout.Token);
        Assert.NotSame(pending, await Task.WhenAny(pending, Task.Delay(100, timeout.Token)));
        byte[] unrelated = (byte[])response.Clone();
        unrelated[24] ^= 255;
        await gateway.SendAsync(unrelated, request.RemoteEndPoint, timeout.Token);
        await gateway.SendAsync(response, request.RemoteEndPoint, timeout.Token);
        using PcpClient.PcpMapping? mapping = await pending;
        Assert.NotNull(mapping);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.66"), 44444), mapping.External);
    }

    [Fact]
    public async Task Mapping_RetriesDroppedRequestOnTheSameSocketWithTheSameNonce()
    {
        using var gateway = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task<PcpClient.PcpMapping?> pending = PcpClient.TryMapAsync([(IPEndPoint)gateway.Client.LocalEndPoint!],
            53317, TimeSpan.FromSeconds(30), timeout.Token);
        UdpReceiveResult first = await gateway.ReceiveAsync(timeout.Token);
        UdpReceiveResult retry = await gateway.ReceiveAsync(timeout.Token);
        Assert.Equal(first.RemoteEndPoint, retry.RemoteEndPoint);
        Assert.Equal(first.Buffer, retry.Buffer);
        byte[] response = Response;
        retry.Buffer.AsSpan(24, 12).CopyTo(response.AsSpan(24));
        await gateway.SendAsync(response, retry.RemoteEndPoint, timeout.Token);
        using PcpClient.PcpMapping? mapping = await pending;
        Assert.NotNull(mapping);
    }

    [Fact]
    public async Task Ipv6Gateway_CreatesAdvertisedMappingAndReleasesIt()
    {
        using var gateway = new FakeGateway(IPAddress.IPv6Loopback)
        {
            PcpExternalAddress = IPAddress.Parse("2001:db8::66"),
        };
        PinholeNode node = await PinholeNode.BindAsync(new PinholeOptions
        {
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            StunServers = [], IrohRelayUrls = [], EnableNetworkWatch = false,
            GatewayOverride = [gateway.Endpoint], PortMappingLease = TimeSpan.FromSeconds(30),
        });
        try
        {
            await TestPoll.UntilAsync(TimeSpan.FromSeconds(10), () => node.PortMappedEndpoint is not null);
            var expected = new IPEndPoint(IPAddress.Parse("2001:db8::66"), 44444);
            Assert.Equal(expected, node.PortMappedEndpoint);
            Assert.Contains(ConnectionString.Parse(node.ConnectionString).Candidates,
                c => c.Kind == CandidateKind.Reflexive && c.Address.Equals(expected));
        }
        finally { await node.DisposeAsync(); }
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(10), () => gateway.Actions.Any(a => a.StartsWith("pcp-delete")));
    }

    [Fact]
    public async Task Renewal_PreservesAssignedEndpointAndDetectsAddressChanges()
    {
        using var gateway = new FakeGateway();
        PcpClient.PcpMapping? mapping = await PcpClient.TryMapAsync([gateway.Endpoint], 53317,
            TimeSpan.FromSeconds(30), CancellationToken.None);
        Assert.NotNull(mapping);
        using (mapping)
        {
            Assert.True(await mapping.RenewAsync(CancellationToken.None));
            byte[] renewed = gateway.PcpRequests.Last();
            Assert.Equal((ushort)44444, BinaryPrimitives.ReadUInt16BigEndian(renewed.AsSpan(42)));
            Assert.Equal(IPAddress.Parse("203.0.113.66").MapToIPv6().GetAddressBytes(), renewed[44..60]);
            Assert.Equal(gateway.PcpRequests.First()[24..36], renewed[24..36]);

            gateway.PcpExternalAddress = IPAddress.Parse("203.0.113.67");
            Assert.False(await mapping.RenewAsync(CancellationToken.None));
            await mapping.ReleaseAsync(CancellationToken.None);
            Assert.Contains(gateway.Actions, a => a.StartsWith("pcp-delete"));
        }
    }
}
