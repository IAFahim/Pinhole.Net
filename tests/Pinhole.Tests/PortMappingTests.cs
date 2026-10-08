using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Router port mappings — the UPnP / NAT-PMP / PCP strategy iroh's portmapper
/// also uses. All fakes are in-process and loopback-only: the client library carries test
/// seams (gateway override, SSDP unicast override) so CI never touches a real router.</summary>
public sealed class PortMappingTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static PinholeOptions Opts(IPEndPoint? ssdp = null, IReadOnlyList<IPEndPoint>? gateways = null,
        bool enabled = true, TimeSpan? lease = null) => new()
    {
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [],
        PublishIrohAddress = false,
        EnableLanDiscovery = false,
        EnableNetworkWatch = false,
        EnablePathValidation = false,
        EnablePortMapping = enabled,
        SsdpUnicastOverride = ssdp,
        GatewayOverride = gateways ?? [],
        PortMappingLease = lease ?? TimeSpan.FromSeconds(30),
    };

    private static async Task UntilAsync(Func<bool> condition, string what) =>
        await TestPoll.UntilAsync(Timeout, condition);

    private static PinholeCandidate? ReflexiveCandidate(PinholeNode node) =>
        Pinhole.ConnectionString.Parse(node.ConnectionString).Candidates
            .FirstOrDefault(c => c.Kind == CandidateKind.Reflexive);

    [Fact]
    public async Task PcpMapping_IsAdvertisedAsReflexiveCandidate()
    {
        using var gateway = new FakeGateway();
        await using PinholeNode node = await PinholeNode.BindAsync(Opts(gateways: [gateway.Endpoint]));

        await UntilAsync(() => node.PortMappedEndpoint is not null, "pcp mapping landed");
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.66"), 44444), node.PortMappedEndpoint);
        Assert.Equal(node.PortMappedEndpoint, ReflexiveCandidate(node)?.Address);
        Assert.Contains(gateway.Actions, a => a.StartsWith("pcp-map") && a.Contains($"int={node.LocalPort}"));
    }

    [Fact]
    public async Task PmpMapping_WorksWhenPcpIsRefused()
    {
        using var gateway = new FakeGateway { RefusePcp = true };
        await using PinholeNode node = await PinholeNode.BindAsync(Opts(gateways: [gateway.Endpoint]));

        await UntilAsync(() => node.PortMappedEndpoint is not null, "pmp mapping landed");
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.66"), 44444), node.PortMappedEndpoint);
        Assert.Contains(gateway.Actions, a => a.StartsWith("pmp-map") && a.Contains($"int={node.LocalPort}"));
        Assert.DoesNotContain(gateway.Actions, a => a.StartsWith("pcp-map"));
    }

    [Fact]
    public async Task UpnpAnyPortMapping_WorksWhenGatewayProtocolsAreRefused()
    {
        using var gateway = new FakeGateway { RefusePcp = true, RefusePmp = true };
        await using FakeUpnpIgd igd = new();
        await using PinholeNode node = await PinholeNode.BindAsync(
            Opts(ssdp: igd.SsdpEndpoint, gateways: [gateway.Endpoint]));

        await UntilAsync(() => node.PortMappedEndpoint is not null, "upnp mapping landed");
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.40"), 55555), node.PortMappedEndpoint);
        Assert.Equal(node.PortMappedEndpoint, ReflexiveCandidate(node)?.Address);
        Assert.Contains(igd.Actions, a => a.StartsWith("AddAnyPortMapping") && a.Contains($"internal={node.LocalPort}"));
    }

    [Fact]
    public async Task UpnpV1Device_FallsBackToAddPortMapping()
    {
        using var gateway = new FakeGateway { RefusePcp = true, RefusePmp = true };
        await using FakeUpnpIgd igd = new() { RejectAddAnyPort = true };
        await using PinholeNode node = await PinholeNode.BindAsync(
            Opts(ssdp: igd.SsdpEndpoint, gateways: [gateway.Endpoint]));

        await UntilAsync(() => node.PortMappedEndpoint is not null, "v1 fallback mapping landed");
        Assert.Contains(igd.Actions, a => a.StartsWith("AddPortMapping") && a.Contains($"external={node.LocalPort}"));
    }

    [Fact]
    public async Task UnsupportedIpv6PcpGateway_StillReachesUpnpFallback()
    {
        using var gateway = new FakeGateway(IPAddress.IPv6Loopback) { RefusePcp = true };
        await using FakeUpnpIgd igd = new();
        await using PinholeNode node = await PinholeNode.BindAsync(
            Opts(ssdp: igd.SsdpEndpoint, gateways: [gateway.Endpoint]));

        await UntilAsync(() => node.PortMappedEndpoint is not null, "upnp fallback landed");
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.40"), 55555), node.PortMappedEndpoint);
        Assert.Contains(igd.Actions, a => a.StartsWith("AddAnyPortMapping"));
        Assert.DoesNotContain(gateway.Actions, a => a.StartsWith("pmp-"));
    }

    [Fact]
    public async Task Disabled_NeverProbesTheNetwork()
    {
        using var gateway = new FakeGateway();
        await using FakeUpnpIgd igd = new();
        await using PinholeNode node = await PinholeNode.BindAsync(
            Opts(ssdp: igd.SsdpEndpoint, gateways: [gateway.Endpoint], enabled: false));

        await Task.Delay(500);
        Assert.Null(node.PortMappedEndpoint);
        Assert.Empty(gateway.Actions);
        Assert.Empty(igd.Actions);
    }

    [Fact]
    public async Task Dispose_ReleasesTheMapping()
    {
        using var gateway = new FakeGateway();
        PinholeNode node = await PinholeNode.BindAsync(Opts(gateways: [gateway.Endpoint]));
        await UntilAsync(() => node.PortMappedEndpoint is not null, "mapping landed");

        await node.DisposeAsync();
        await UntilAsync(() => gateway.Actions.Any(a => a.StartsWith("pcp-delete")), "release reached the gateway");
    }

    [Fact]
    public async Task Renewal_RefreshesTheLeaseAtHalfLife()
    {
        using var gateway = new FakeGateway();
        await using PinholeNode node = await PinholeNode.BindAsync(
            Opts(gateways: [gateway.Endpoint], lease: TimeSpan.FromSeconds(1)));

        await UntilAsync(() => node.PortMappedEndpoint is not null, "mapping landed");
        await UntilAsync(() => gateway.Actions.Count(a => a.StartsWith("pcp-map")) >= 2, "lease renewed");
    }

    [Fact]
    public async Task LiveMapping_MakesTheHintCone_EvenBehindSymmetricObservations()
    {
        // A symmetric NAT whose router nevertheless grants a mapping: the mapped endpoint
        // is punchable from anywhere, so telling dialers "symmetric, skip the punch" would
        // throw away a working direct path. The honest hint is cone.
        using FakeStunServer s1 = new() { ReportMappedOverride = new IPEndPoint(IPAddress.Parse("198.51.100.7"), 40000) };
        using FakeStunServer s2 = new() { ReportMappedOverride = new IPEndPoint(IPAddress.Parse("198.51.100.7"), 41000) };
        using var gateway = new FakeGateway();
        await using PinholeNode node = await PinholeNode.BindAsync(new PinholeOptions
        {
            StunServers = [s1.LocalEndPoint, s2.LocalEndPoint],
            Relays = [],
            IrohRelayUrls = [],
            PublishIrohAddress = false,
            EnableLanDiscovery = false,
            EnableNetworkWatch = false,
            EnablePathValidation = false,
            GatewayOverride = [gateway.Endpoint],
        });

        await UntilAsync(() => node.PortMappedEndpoint is not null, "mapping landed");
        Assert.Equal(NatHint.Cone, node.NatHint);
    }

    [Fact]
    public async Task InterfaceLoss_RecreatesTheMappingForTheNewPort()
    {
        using var gateway = new FakeGateway();
        await using PinholeNode node = await PinholeNode.BindAsync(Opts(gateways: [gateway.Endpoint]));
        int portBefore = node.LocalPort;
        await UntilAsync(() => node.PortMappedEndpoint is not null, "mapping landed");
        Assert.Contains(gateway.Actions, a => a.StartsWith("pcp-map") && a.Contains($"int={portBefore}"));

        await node.Engine.SimulateInterfaceLossAsync().WaitAsync(Timeout);
        Assert.NotEqual(portBefore, node.LocalPort);

        await UntilAsync(
            () => gateway.Actions.Any(a => a.StartsWith("pcp-map") && a.Contains($"int={node.LocalPort}")),
            "mapping recreated for the new port");
        Assert.Contains(gateway.Actions, a => a.StartsWith("pcp-delete"));
        await UntilAsync(() => node.PortMappedEndpoint is not null, "mapped endpoint restored");
    }
}

/// <summary>An in-process UDP gateway speaking both NAT-PMP (version 0) and PCP (version 2)
/// on one loopback port, mirroring a home router's control plane.</summary>
public sealed class FakeGateway : IDisposable
{
    private readonly UdpClient _udp;
    private readonly byte[] _buf = new byte[1500];
    private readonly byte[] _externalIp = { 203, 0, 113, 66 };

    public FakeGateway(IPAddress? bindAddress = null)
    {
        _udp = new UdpClient(new IPEndPoint(bindAddress ?? IPAddress.Loopback, 0));
        Endpoint = (IPEndPoint)_udp.Client.LocalEndPoint!;
        _ = Task.Run(RunAsync);
    }

    public IPEndPoint Endpoint { get; }

    /// <summary>Answer PCP MAP requests with UNSUPPORTED_OPCODE, forcing the PMP leg.</summary>
    public bool RefusePcp { get; set; }

    /// <summary>Answer PMP requests with a failure, forcing the UPnP leg.</summary>
    public bool RefusePmp { get; set; }

    public ushort ExternalPort { get; set; } = 44444;

    public IPAddress PcpExternalAddress { get; set; } = IPAddress.Parse("203.0.113.66");

    public ConcurrentQueue<byte[]> PcpRequests { get; } = new();

    public ConcurrentQueue<string> Actions { get; } = new();

    private async Task RunAsync()
    {
        while (true)
        {
            UdpReceiveResult res;
            try
            {
                res = await _udp.ReceiveAsync().ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            byte[] d = res.Buffer;
            if (d.Length == 0)
            {
                continue;
            }

            if (d[0] == 0 && d.Length >= 2)
            {
                await HandlePmpAsync(d, res.RemoteEndPoint).ConfigureAwait(false);
            }
            else if (d[0] == 2 && d.Length >= 60)
            {
                await HandlePcpAsync(d, res.RemoteEndPoint).ConfigureAwait(false);
            }
        }
    }

    private async Task HandlePmpAsync(byte[] d, IPEndPoint from)
    {
        if (d[1] == 0 && d.Length == 2)
        {
            byte[] reply = new byte[12];
            reply[1] = 128;
            if (RefusePmp)
            {
                BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(2), 3); // NetworkFailure
            }
            else
            {
                _externalIp.CopyTo(reply, 8);
            }

            await _udp.SendAsync(reply, from).ConfigureAwait(false);
            return;
        }

        if (d[1] == 1 && d.Length == 12)
        {
            int internalPort = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(4));
            int suggested = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(6));
            uint lifetime = BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(8));
            byte[] reply = new byte[16];
            reply[1] = 129;
            if (RefusePmp)
            {
                BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(2), 3);
            }
            else
            {
                BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(8), (ushort)internalPort);
                BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(10), (ushort)(suggested != 0 ? suggested : ExternalPort));
                BinaryPrimitives.WriteUInt32BigEndian(reply.AsSpan(12), lifetime);
                Actions.Enqueue(lifetime == 0
                    ? $"pmp-delete int={internalPort} ext={suggested}"
                    : $"pmp-map int={internalPort} ext={suggested} life={lifetime}");
            }

            await _udp.SendAsync(reply, from).ConfigureAwait(false);
        }
    }

    private async Task HandlePcpAsync(byte[] d, IPEndPoint from)
    {
        // RFC 6887 sections 7.1 and 11.1: a 24-byte common header, then
        // a 36-byte MAP body. Refuse requests whose claimed client differs
        // from the source address, as a real PCP server must do.
        if (d[1] != 1 || d[36] != 17
            || !d.AsSpan(8, 16).SequenceEqual(from.Address.MapToIPv6().GetAddressBytes()))
        {
            return;
        }

        PcpRequests.Enqueue(d);
        uint lifetime = BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(4));
        byte[] nonce = d[24..36];
        int internalPort = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(40));

        byte[] reply = new byte[RefusePcp ? 24 : 60];
        reply[0] = 2;
        reply[1] = 129;
        reply[3] = RefusePcp ? (byte)4 : (byte)0; // UNSUPP_OPCODE
        BinaryPrimitives.WriteUInt32BigEndian(reply.AsSpan(4), lifetime);
        if (RefusePcp)
        {
            await _udp.SendAsync(reply, from).ConfigureAwait(false);
            return;
        }
        nonce.CopyTo(reply, 24);
        reply[36] = 17; // UDP
        BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(40), (ushort)internalPort);
        if (!RefusePcp)
        {
            BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(42), ExternalPort);
            PcpExternalAddress.MapToIPv6().GetAddressBytes().CopyTo(reply, 44);
            Actions.Enqueue(lifetime == 0
                ? $"pcp-delete int={internalPort}"
                : $"pcp-map int={internalPort} ext={ExternalPort} life={lifetime}");
        }

        await _udp.SendAsync(reply, from).ConfigureAwait(false);
    }

    public void Dispose() => _udp.Dispose();
}

/// <summary>An in-process IGD: an SSDP responder pointing at an HTTP device description,
/// plus the SOAP control endpoint a real router exposes.</summary>
public sealed class FakeUpnpIgd : IAsyncDisposable
{
    private readonly HttpListener _http = new();
    private readonly UdpClient _ssdp;
    private readonly byte[] _buf = new byte[2048];
    private readonly Uri _base;
    private readonly Task _ssdpLoop;
    private readonly Task _httpLoop;

    public FakeUpnpIgd()
    {
        using var port = new TcpListener(IPAddress.Loopback, 0);
        port.Start();
        int httpPort = ((IPEndPoint)port.LocalEndpoint).Port;
        port.Stop();
        _base = new Uri($"http://127.0.0.1:{httpPort}/");
        _http.Prefixes.Add(_base.AbsoluteUri);
        _http.Start();
        _ssdp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        SsdpEndpoint = (IPEndPoint)_ssdp.Client.LocalEndPoint!;
        _ssdpLoop = Task.Run(SsdpLoopAsync);
        _httpLoop = Task.Run(HttpLoopAsync);
    }

    public IPEndPoint SsdpEndpoint { get; }

    public IPAddress ExternalIp { get; } = IPAddress.Parse("203.0.113.40");

    public int ExternalPort { get; } = 55555;

    /// <summary>Reject AddAnyPortMapping like an IGDv1 device, forcing the fallback.</summary>
    public bool RejectAddAnyPort { get; set; }

    public ConcurrentQueue<string> Actions { get; } = new();

    private async Task SsdpLoopAsync()
    {
        while (true)
        {
            UdpReceiveResult res;
            try
            {
                res = await _ssdp.ReceiveAsync().ConfigureAwait(false);
            }
            catch (ObjectDisposedException)
            {
                return;
            }

            if (Encoding.ASCII.GetString(res.Buffer).Contains("M-SEARCH"))
            {
                byte[] reply = Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\n" +
                    "CACHE-CONTROL: max-age=1800\r\n" +
                    $"LOCATION: {_base}igd.xml\r\n" +
                    "SERVER: FakeOS UPnP/1.0\r\n" +
                    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n");
                await _ssdp.SendAsync(reply, res.RemoteEndPoint).ConfigureAwait(false);
            }
        }
    }

    private async Task HttpLoopAsync()
    {
        while (_http.IsListening)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _http.GetContextAsync().ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpListenerException or ObjectDisposedException)
            {
                return;
            }

            _ = Task.Run(() => ServeAsync(ctx));
        }
    }

    private async Task ServeAsync(HttpListenerContext ctx)
    {
        try
        {
            if (ctx.Request.HttpMethod == "GET")
            {
                byte[] xml = Encoding.UTF8.GetBytes(DeviceXml);
                ctx.Response.ContentType = "text/xml";
                ctx.Response.ContentLength64 = xml.Length;
                await ctx.Response.OutputStream.WriteAsync(xml).ConfigureAwait(false);
                ctx.Response.Close();
                return;
            }

            string action = ctx.Request.Headers["SOAPACTION"] ?? "";
            action = action.Trim('"');
            string name = action.Contains('#') ? action[(action.LastIndexOf('#') + 1)..] : "";
            string body;
            using (var reader = new StreamReader(ctx.Request.InputStream))
            {
                body = await reader.ReadToEndAsync().ConfigureAwait(false);
            }

            switch (name)
            {
                case "GetExternalIPAddress":
                    Actions.Enqueue("GetExternalIPAddress");
                    body = Response($"<NewExternalIPAddress>{ExternalIp}</NewExternalIPAddress>");
                    break;
                case "AddAnyPortMapping" when RejectAddAnyPort:
                    body = Fault(401); // InvalidAction: IGDv1 vocabulary only
                    ctx.Response.StatusCode = 500;
                    break;
                case "AddAnyPortMapping":
                {
                    int internalPort = int.Parse(XmlArg(body, "NewInternalPort"));
                    Actions.Enqueue($"AddAnyPortMapping internal={internalPort} lease={XmlArg(body, "NewLeaseDuration")}");
                    body = Response($"<NewReservedPort>{ExternalPort}</NewReservedPort>");
                    break;
                }
                case "AddPortMapping":
                {
                    int external = int.Parse(XmlArg(body, "NewExternalPort"));
                    Actions.Enqueue($"AddPortMapping external={external} lease={XmlArg(body, "NewLeaseDuration")}");
                    body = Response("");
                    break;
                }
                case "DeletePortMapping":
                    Actions.Enqueue($"DeletePortMapping external={XmlArg(body, "NewExternalPort")}");
                    body = Response("");
                    break;
                default:
                    body = Fault(401);
                    ctx.Response.StatusCode = 500;
                    break;
            }

            byte[] payload = Encoding.UTF8.GetBytes(body);
            ctx.Response.ContentType = "text/xml";
            ctx.Response.ContentLength64 = payload.Length;
            await ctx.Response.OutputStream.WriteAsync(payload).ConfigureAwait(false);
            ctx.Response.Close();
        }
        catch (Exception ex) when (ex is HttpListenerException or ObjectDisposedException or IOException)
        {
        }
    }

    private static string XmlArg(string soap, string name) =>
        XElement.Parse(soap).Descendants().First(e => e.Name.LocalName == name).Value;

    private static string Response(string inner) =>
        $"<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xml.org/soap/envelope/\" " +
        $"s:encodingStyle=\"http://schemas.xml.org/soap/envelope/\"><s:Body>{inner}</s:Body></s:Envelope>";

    private static string Fault(int code) =>
        Response($"<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>" +
                 $"<detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">" +
                 $"<errorCode>{code}</errorCode><errorDescription>Action rejected</errorDescription>" +
                 $"</UPnPError></detail></s:Fault>");

    private string DeviceXml => $"""
        <?xml version="1.0"?>
        <root xmlns="urn:schemas-upnp-org:device-1-0">
          <device>
            <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
            <friendlyName>Fake IGD</friendlyName>
            <deviceList><device>
              <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
              <deviceList><device>
                <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
                <serviceList><service>
                  <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                  <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                  <controlURL>{_base}ctrl</controlURL>
                  <eventSubURL>/event</eventSubURL>
                  <SCPDURL>/scpd.xml</SCPDURL>
                </service></serviceList>
              </device></deviceList>
            </device></deviceList>
          </device>
        </root>
        """;

    public async ValueTask DisposeAsync()
    {
        _ssdp.Dispose();
        try { _http.Stop(); }
        catch (ObjectDisposedException) { }
        await Task.WhenAny(_ssdpLoop, Task.Delay(TimeSpan.FromSeconds(1))).ConfigureAwait(false);
        await Task.WhenAny(_httpLoop, Task.Delay(TimeSpan.FromSeconds(1))).ConfigureAwait(false);
        try { _http.Close(); }
        catch (ObjectDisposedException) { }
    }
}
