using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Pinhole;

/// <summary>A concrete LAN source for router control. The index is local routing
/// state and never becomes part of an advertised global IPv6 address.</summary>
internal readonly record struct IPv6LanSource(IPAddress Address, long InterfaceIndex);

/// <summary>WANIPv6FirewallControl:1 creates filter leases, not translated addresses.
/// Control HTTP is bound to the exact IPv6 InternalClient so ordinary IGD access
/// control can verify that the request concerns this host. Only locally discovered,
/// pinned link-local/ULA router addresses are contacted.</summary>
internal static class UpnpIPv6FirewallClient
{
    internal const string ServiceType = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1";
    private const string Igd2 = "urn:schemas-upnp-org:device:InternetGatewayDevice:2";
    private static readonly TimeSpan RequestedLifetime = TimeSpan.FromHours(1);

    internal static bool IsGlobalUnicast(IPAddress address) => address.AddressFamily == AddressFamily.InterNetworkV6
        && (address.GetAddressBytes()[0] & 0xe0) == 0x20 && !address.IsIPv6Teredo;

    internal static async Task<IPortMapLease?> TryCreateAsync(IPv6LanSource source, int port,
        ProtocolType protocol, CancellationToken ct)
    {
        if (!IsGlobalUnicast(source.Address) || source.InterfaceIndex <= 0 || port is < 1024 or > 65535) return null;
        foreach (Uri location in await DiscoverAsync(source, null, ct).ConfigureAwait(false))
        {
            ct.ThrowIfCancellationRequested();
            IPAddress router = IPAddress.Parse(location.DnsSafeHost);
            HttpClient http = CreateHttpClient(source.Address, router);
            bool transferred = false;
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(TimeSpan.FromSeconds(2));
                using var response = await http.GetAsync(location, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode) continue;
                XDocument description = await UpnpIgdClient.ReadXmlAsync(response.Content, timeout.Token).ConfigureAwait(false);
                foreach (var service in UpnpIgdClient.FindServices(description, location, [ServiceType]))
                {
                    IPv6FirewallLease? lease = await TryCreateOnServiceAsync(http, service.ControlUrl,
                        new IPEndPoint(source.Address, port), protocol, RequestedLifetime, ct).ConfigureAwait(false);
                    if (lease is null) continue;
                    transferred = true; // the granted lease now owns the source-bound client
                    return lease;
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or SocketException or IOException or XmlException or OperationCanceledException) { }
            finally { if (!transferred) http.Dispose(); }
        }
        return null;
    }

    internal static HttpClient CreateHttpClient(IPAddress source, IPAddress router) => new(new SocketsHttpHandler
    {
        UseProxy = false, AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(1.5),
        ConnectCallback = async (context, ct) =>
        {
            // Do not resolve another host or follow a description to a different router.
            // HttpClient versions differ in whether the local zone survives into
            // DnsEndPoint. Always connect using our pinned scope, never a URL's zone.
            if (!IPAddress.TryParse(context.DnsEndPoint.Host, out IPAddress? target)
                || !target.GetAddressBytes().SequenceEqual(router.GetAddressBytes())
                || target.AddressFamily == AddressFamily.InterNetworkV6 && target.ScopeId != 0 && target.ScopeId != router.ScopeId)
                throw new HttpRequestException("IPv6 router control address changed");
            var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                socket.Bind(new IPEndPoint(source, 0));
                await socket.ConnectAsync(new IPEndPoint(router, context.DnsEndPoint.Port), ct).ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch { socket.Dispose(); throw; }
        },
    });

    internal static async Task<IReadOnlyList<Uri>> DiscoverAsync(IPv6LanSource source, IPEndPoint? unicast, CancellationToken ct)
    {
        using var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(source.Address, 0));
        if (unicast is null) socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, checked((int)source.InterfaceIndex));
        IPEndPoint target = unicast ?? new IPEndPoint(new IPAddress(IPAddress.Parse("ff02::c").GetAddressBytes(), source.InterfaceIndex), 1900);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(unicast is null ? TimeSpan.FromSeconds(1) : TimeSpan.FromMilliseconds(300));
        var locations = new HashSet<Uri>();
        try
        {
            foreach (string type in new[] { Igd2, ServiceType })
            {
                byte[] query = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: [FF02::C]:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: " + type + "\r\n\r\n");
                await socket.SendToAsync(query, SocketFlags.None, target, timeout.Token).ConfigureAwait(false);
            }
            byte[] buffer = new byte[2048];
            int received = 0;
            while (locations.Count < 4 && received++ < 16)
            {
                SocketReceiveFromResult response = await socket.ReceiveFromAsync(buffer, SocketFlags.None,
                    new IPEndPoint(IPAddress.IPv6Any, 0), timeout.Token).ConfigureAwait(false);
                var responder = (IPEndPoint)response.RemoteEndPoint;
                if (unicast is not null && !responder.Equals(unicast)) continue;
                string text = Encoding.ASCII.GetString(buffer, 0, response.ReceivedBytes);
                Uri? location = PinLocation(text, responder.Address, source.InterfaceIndex, allowLoopback: unicast is not null);
                if (location is not null) locations.Add(location);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
        return locations.ToArray();
    }

    internal static Uri? PinLocation(string response, IPAddress responder, long interfaceIndex, bool allowLoopback = false)
    {
        if (responder.AddressFamily != AddressFamily.InterNetworkV6 || responder.IsIPv4MappedToIPv6
            || responder.IsIPv6LinkLocal && interfaceIndex <= 0
            || !(responder.IsIPv6LinkLocal || (responder.GetAddressBytes()[0] & 0xfe) == 0xfc
                || allowLoopback && responder.Equals(IPAddress.IPv6Loopback))) return null;
        if (!response.StartsWith("HTTP/1.1 200 ", StringComparison.OrdinalIgnoreCase)
            && !response.StartsWith("HTTP/1.0 200 ", StringComparison.OrdinalIgnoreCase)) return null;
        foreach (string line in response.Split('\n'))
        {
            int colon = line.IndexOf(':');
            if (colon < 1 || !line[..colon].Trim().Equals("LOCATION", StringComparison.OrdinalIgnoreCase)) continue;
            if (!Uri.TryCreate(line[(colon + 1)..].Trim(), UriKind.Absolute, out Uri? uri) || !UpnpIgdClient.IsHttpUrl(uri)
                || !IPAddress.TryParse(uri.DnsSafeHost, out IPAddress? locationAddress)
                || !locationAddress.GetAddressBytes().SequenceEqual(responder.GetAddressBytes())) return null;
            IPAddress pinned = responder.IsIPv6LinkLocal ? new IPAddress(responder.GetAddressBytes(), interfaceIndex) : responder;
            return new UriBuilder(uri) { Host = pinned.ToString() }.Uri;
        }
        return null;
    }

    internal static async Task<IPv6FirewallLease?> TryCreateOnServiceAsync(HttpClient http, Uri control,
        IPEndPoint internalEndpoint, ProtocolType protocol, TimeSpan requested, CancellationToken ct)
    {
        if (!IsGlobalUnicast(internalEndpoint.Address) || internalEndpoint.Port is < 1024 or > 65535)
            throw new ArgumentException("A pinhole requires this node's global IPv6 listening endpoint", nameof(internalEndpoint));
        if (protocol is not (ProtocolType.Udp or ProtocolType.Tcp)) throw new ArgumentOutOfRangeException(nameof(protocol));
        if (requested <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(requested));
        int seconds = (int)Math.Clamp(requested.TotalSeconds, 1, 86400);
        if (!await IsAllowedAsync(http, control, ct).ConfigureAwait(false)) return null;
        string args = Arg("RemoteHost", "") + Arg("RemotePort", "0")
            + Arg("InternalClient", internalEndpoint.Address.ToString()) + Arg("InternalPort", Number(internalEndpoint.Port))
            + Arg("Protocol", Number(protocol == ProtocolType.Tcp ? 6 : 17)) + Arg("LeaseTime", Number(seconds));
        XElement? reply = await ActionAsync(http, control, "AddPinhole", args, ct).ConfigureAwait(false);
        string? raw = Field(reply, "UniqueID");
        if (!ushort.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out ushort uniqueId)) return null;
        return new IPv6FirewallLease(http, control, new IPEndPoint(internalEndpoint.Address, internalEndpoint.Port), uniqueId, seconds);
    }

    private static string Number(int value) => value.ToString(CultureInfo.InvariantCulture);
    private static string Arg(string name, string value) => $"<{name}>{value}</{name}>";
    private static bool True(string? value) => value?.Trim().ToLowerInvariant() is "1" or "true" or "yes";
    private static string? Field(XElement? reply, string name)
    {
        XElement[] fields = reply?.Elements().Where(e => e.Name.LocalName == name
            && e.Name.NamespaceName is "" or ServiceType).ToArray() ?? [];
        return fields.Length == 1 ? fields[0].Value.Trim() : null;
    }
    private static async Task<bool> IsAllowedAsync(HttpClient http, Uri control, CancellationToken ct)
    {
        XElement? reply = await ActionAsync(http, control, "GetFirewallStatus", "", ct).ConfigureAwait(false);
        return True(Field(reply, "FirewallEnabled")) && True(Field(reply, "InboundPinholeAllowed"));
    }

    private static async Task<XElement?> ActionAsync(HttpClient http, Uri control, string action, string args, CancellationToken ct)
    {
        try
        {
            XDocument? body = await UpnpIgdClient.SoapCallAsync(http, control, ServiceType, action, args, ct).ConfigureAwait(false);
            XNamespace soap = "http://schemas.xmlsoap.org/soap/envelope/";
            return body?.Element(soap + "Envelope")?.Element(soap + "Body")?.Element(XName.Get(action + "Response", ServiceType));
        }
        catch (UpnpIgdClient.UpnpFaultException) { return null; }
    }

    internal sealed class IPv6FirewallLease(HttpClient http, Uri control, IPEndPoint endpoint, ushort uniqueId, int seconds) : IPortMapLease
    {
        public IPEndPoint External { get; } = endpoint; // no translation; already a host candidate
        public TimeSpan Lifetime => TimeSpan.FromSeconds(seconds);
        public async Task<bool> RenewAsync(CancellationToken ct) => await IsAllowedAsync(http, control, ct).ConfigureAwait(false)
            && await ActionAsync(http, control, "UpdatePinhole", Arg("UniqueID", Number(uniqueId))
                + Arg("NewLeaseTime", Number(seconds)), ct).ConfigureAwait(false) is not null;
        public async Task ReleaseAsync(CancellationToken ct) => _ = await ActionAsync(http, control, "DeletePinhole",
            Arg("UniqueID", Number(uniqueId)), ct).ConfigureAwait(false);
        public void Dispose() => http.Dispose();
    }
}
