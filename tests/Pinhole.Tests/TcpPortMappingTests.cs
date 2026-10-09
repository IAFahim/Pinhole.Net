using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Independent RFC byte fixtures and SOAP fixtures through an injected HTTP
/// handler. These test protocol semantics without making router or socket claims.</summary>
public sealed class TcpPortMappingTests
{
    private static byte[] PcpTcpRequest => Convert.FromHexString(
        "020100000000001E00000000000000000000FFFFC000020A" +
        "000102030405060708090A0B06000000D0450000" +
        "00000000000000000000FFFF00000000");
    private static byte[] PcpTcpResponse => Convert.FromHexString(
        "028100000000001E00001234000000000000000000000000" +
        "000102030405060708090A0B06000000D045AD9C" +
        "00000000000000000000FFFFCB007142");

    [Fact]
    public void PcpTcp_UsesIpProtocolSixAndRejectsAValidUdpReply()
    {
        byte[] actual = PcpClient.BuildMapRequest(Convert.FromHexString("000102030405060708090A0B"),
            IPAddress.Parse("192.0.2.10"), 53317, TimeSpan.FromSeconds(30), protocol: ProtocolType.Tcp);
        Assert.Equal(PcpTcpRequest, actual);
        Assert.True(PcpClient.TryParseMapResponse(PcpTcpResponse, actual, out IPEndPoint? address, out uint lifetime));
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.66"), 44444), address);
        Assert.Equal(30u, lifetime);
        byte[] udp = PcpTcpResponse; udp[36] = 17;
        Assert.False(PcpClient.TryParseMapResponse(udp, actual, out _, out _));
        Assert.False(PcpClient.TryParseMapResponse(PcpTcpResponse, new byte[12], out _, out _));
    }

    [Theory]
    [InlineData(1, false)]
    [InlineData(2, true)]
    public void NatPmp_UsesDistinctOpcodesAndZeroExternalPortForDeletion(int opcode, bool tcp)
    {
        ProtocolType protocol = tcp ? ProtocolType.Tcp : ProtocolType.Udp;
        byte[] expected = Convert.FromHexString("00000000D045AD9C0000001E"); expected[1] = (byte)opcode;
        Assert.Equal(expected, NatPmpClient.BuildMapRequest(53317, TimeSpan.FromSeconds(30), 44444, protocol));
        byte[] deletion = Convert.FromHexString("00000000D045000000000000"); deletion[1] = (byte)opcode;
        Assert.Equal(deletion, NatPmpClient.BuildMapRequest(53317, TimeSpan.Zero, 44444, protocol));
        byte[] response = Convert.FromHexString("0080000000001234D045AD9C0000001E"); response[1] = (byte)(128 + opcode);
        Assert.True(NatPmpClient.TryParseMapResponse(response, expected, out int port, out uint granted));
        Assert.Equal(44444, port); Assert.Equal(30u, granted);
        response[1] = (byte)(128 + (tcp ? 1 : 2));
        Assert.False(NatPmpClient.TryParseMapResponse(response, expected, out _, out _));
        byte[] deleted = Convert.FromHexString("0080000000001234D045000000000000"); deleted[1] = (byte)(128 + opcode);
        Assert.True(NatPmpClient.TryParseMapResponse(deleted, deletion, out int zeroPort, out uint zeroLifetime));
        Assert.Equal(0, zeroPort); Assert.Equal(0u, zeroLifetime);
    }

    [Fact]
    public void NatPmp_RejectsUnrelatedPortsErrorsTruncationZeroLeaseAndInvalidPublicAddresses()
    {
        byte[] request = Convert.FromHexString("00020000D04500000000001E");
        byte[] response = Convert.FromHexString("0082000000001234D045AD9C0000001E");
        Assert.True(NatPmpClient.TryParseMapResponse(response, request, out _, out _));
        foreach (int offset in new[] { 0, 2, 8, 10, 12 })
        {
            byte[] changed = (byte[])response.Clone();
            if (offset is 10 or 12) changed.AsSpan(offset, offset == 10 ? 2 : 4).Clear();
            else changed[offset] ^= 1;
            Assert.False(NatPmpClient.TryParseMapResponse(changed, request, out _, out _));
        }
        Assert.False(NatPmpClient.TryParseMapResponse(response[..15], request, out _, out _));
        Assert.False(NatPmpClient.TryParseMapResponse([.. response, 0], request, out _, out _));
        byte[] publicIp = Convert.FromHexString("0080000000001234CB007142");
        Assert.True(NatPmpClient.TryParsePublicAddress(publicIp, out IPAddress? parsed));
        Assert.Equal(IPAddress.Parse("203.0.113.66"), parsed);
        foreach (byte first in new byte[] { 0, 224, 239, 255 })
        {
            publicIp[8] = first;
            Assert.False(NatPmpClient.TryParsePublicAddress(publicIp, out _));
        }
    }

    private sealed class SoapHandler : HttpMessageHandler
    {
        internal List<(string Action, XDocument Body)> Requests { get; } = [];
        internal string? InvalidResponse;
        internal string ExternalAddress = "203.0.113.40";
        internal bool Disposed;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string action = request.Headers.GetValues("SOAPACTION").Single().Trim('"').Split('#')[1];
            string body = await request.Content!.ReadAsStringAsync(ct);
            Requests.Add((action, XDocument.Parse(body)));
            string response = action == "GetExternalIPAddress" ? $"<NewExternalIPAddress>{ExternalAddress}</NewExternalIPAddress>" : "";
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(InvalidResponse ??
                    $"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body>{response}</s:Body></s:Envelope>", Encoding.UTF8, "text/xml"),
            };
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }

    private static UpnpIgdClient.UpnpMapping UpnpLease(SoapHandler handler, int duration = 30) => new(new HttpClient(handler),
        new Uri("http://192.168.1.1:5000/control"), "urn:schemas-upnp-org:service:WANIPConnection:2",
        new IPEndPoint(IPAddress.Parse("203.0.113.40"), 55555), 53317,
        IPAddress.Parse("192.168.1.10"), duration, TimeSpan.FromSeconds(30), ProtocolType.Tcp);
    private static string Argument(XDocument body, string name) => body.Descendants().Single(e => e.Name.LocalName == name).Value;

    [Theory]
    [InlineData(30)]
    [InlineData(0)] // IGDv1 permanent-only fault retry must keep using permanent leases
    public async Task UpnpLease_RenewsTheGrantedPortAndReleasesTheTcpMapping(int duration)
    {
        var handler = new SoapHandler();
        using (var lease = UpnpLease(handler, duration))
        {
            Assert.True(await lease.RenewAsync(default));
            Assert.Equal(new[] { "AddPortMapping", "GetExternalIPAddress" }, handler.Requests.Select(r => r.Action));
            XDocument body = handler.Requests[0].Body;
            Assert.Equal("TCP", Argument(body, "NewProtocol"));
            Assert.Equal("55555", Argument(body, "NewExternalPort"));
            Assert.Equal("53317", Argument(body, "NewInternalPort"));
            Assert.Equal(duration.ToString(), Argument(body, "NewLeaseDuration"));
            await lease.ReleaseAsync(default);
            Assert.Equal("DeletePortMapping", handler.Requests[^1].Action);
            Assert.Equal("TCP", Argument(handler.Requests[^1].Body, "NewProtocol"));
            Assert.Equal("55555", Argument(handler.Requests[^1].Body, "NewExternalPort"));
        }
        Assert.True(handler.Disposed);
    }

    [Theory]
    [InlineData("truncated")]
    [InlineData("<!DOCTYPE x [<!ENTITY a 'data'>]><x>&a;</x>")]
    public async Task UpnpLease_InvalidXmlCannotBeReportedAsARenewal(string xml)
    {
        var handler = new SoapHandler { InvalidResponse = xml };
        using var lease = UpnpLease(handler);
        Assert.False(await lease.RenewAsync(default));
    }

    [Fact]
    public async Task UpnpLease_DetectsWanAddressChangesAndRefusesOversizedResponses()
    {
        var handler = new SoapHandler { ExternalAddress = "203.0.113.41" };
        using var lease = UpnpLease(handler);
        Assert.False(await lease.RenewAsync(default));
        handler.InvalidResponse = "<x>" + new string('a', 65537) + "</x>";
        Assert.False(await lease.RenewAsync(default));
    }

    [Fact]
    public void UpnpDescription_CannotRedirectControlToAnotherHostOrNonHttpProtocol()
    {
        var description = XDocument.Parse("""
            <root><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType><controlURL>/control</controlURL></service>
            <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>http://203.0.113.99/admin</controlURL></service>
            <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>file:///etc/passwd</controlURL></service></root>
            """);
        var services = UpnpIgdClient.FindConnectionServices(description, new Uri("http://192.168.1.1/device.xml"));
        Assert.Equal(new Uri("http://192.168.1.1/control"), Assert.Single(services).ControlUrl);
        Assert.False(UpnpIgdClient.IsHttpUrl(new Uri("http://name:secret@192.168.1.1/control")));
        Assert.False(UpnpIgdClient.IsHttpUrl(new Uri("http://192.168.1.1/control#fragment")));
        Assert.True(UpnpIgdClient.IsRouterAddress(IPAddress.Parse("192.168.1.1")));
        Assert.True(UpnpIgdClient.IsRouterAddress(IPAddress.Parse("100.64.0.1")));
        Assert.False(UpnpIgdClient.IsRouterAddress(IPAddress.Parse("203.0.113.99")));
    }
}
