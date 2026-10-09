using System.Net;
using System.Net.Sockets;
using System.Text;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Real socket checks. These must run on platform CI/a network-capable
/// workspace; the offline fixture suite does not select or substitute for them.</summary>
public sealed class IPv6FirewallSocketTests
{
    [Fact]
    public async Task HttpControl_ConnectsFromTheSelectedIPv6Source()
    {
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        Task server = Task.Run(async () =>
        {
            using TcpClient incoming = await listener.AcceptTcpClientAsync(deadline.Token);
            Assert.Equal(IPAddress.IPv6Loopback, ((IPEndPoint)incoming.Client.RemoteEndPoint!).Address);
            using var stream = incoming.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
            Assert.StartsWith("GET /device.xml HTTP/1.1", (await reader.ReadLineAsync(deadline.Token))!);
            while (await reader.ReadLineAsync(deadline.Token) is { Length: > 0 }) { }
            await stream.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n<root/>"u8.ToArray(), deadline.Token);
        }, deadline.Token);
        using HttpClient http = UpnpIPv6FirewallClient.CreateHttpClient(IPAddress.IPv6Loopback, IPAddress.IPv6Loopback);
        string description = await http.GetStringAsync(new Uri($"http://[::1]:{((IPEndPoint)listener.LocalEndpoint).Port}/device.xml"), deadline.Token);
        Assert.Equal("<root/>", description);
        await server.WaitAsync(deadline.Token);
        // A different literal must be refused by the pinned connector before dialing it.
        await Assert.ThrowsAsync<HttpRequestException>(() => http.GetStringAsync(new Uri("http://[::2]/device.xml"), deadline.Token));
    }

    [Fact]
    public async Task Ssdp_UsesIpv6QueriesAndPinsOnlyTheLocalResponderLocation()
    {
        using var router = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
        router.Bind(new IPEndPoint(IPAddress.IPv6Loopback, 0));
        var endpoint = (IPEndPoint)router.LocalEndPoint!;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        var queries = new List<string>();
        Task server = Task.Run(async () =>
        {
            byte[] bytes = new byte[2048];
            for (int i = 0; i < 2; i++)
            {
                var query = await router.ReceiveFromAsync(bytes, SocketFlags.None, new IPEndPoint(IPAddress.IPv6Any, 0), deadline.Token);
                queries.Add(Encoding.ASCII.GetString(bytes, 0, query.ReceivedBytes));
                // A peer-supplied remote control URL must not become a discovered router.
                byte[] bad = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nLOCATION: http://[2001:db8::99]/device.xml\r\n\r\n");
                await router.SendToAsync(bad, SocketFlags.None, query.RemoteEndPoint, deadline.Token);
                byte[] good = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nLOCATION: http://[::1]:5000/device.xml\r\n\r\n");
                await router.SendToAsync(good, SocketFlags.None, query.RemoteEndPoint, deadline.Token);
            }
        }, deadline.Token);
        var locations = await UpnpIPv6FirewallClient.DiscoverAsync(new(IPAddress.IPv6Loopback, 1), endpoint, deadline.Token);
        await server.WaitAsync(deadline.Token);
        Assert.Equal(new Uri("http://[::1]:5000/device.xml"), Assert.Single(locations));
        Assert.Equal(2, queries.Count);
        Assert.All(queries, q => Assert.Contains("HOST: [FF02::C]:1900\r\n", q));
        Assert.Contains(queries, q => q.Contains("ST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n"));
        Assert.Contains(queries, q => q.Contains("ST: urn:schemas-upnp-org:service:WANIPv6FirewallControl:1\r\n"));
    }
}
