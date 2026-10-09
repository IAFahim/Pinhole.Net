using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Globalization;
using System.Xml.Linq;
using System.Xml;

namespace Pinhole;

/// <summary>UPnP Internet Gateway Device client: SSDP discovery, device-description parsing,
/// and the SOAP actions a pinhole needs (AddAnyPortMapping with AddPortMapping fallback,
/// GetExternalIPAddress, DeletePortMapping). The same technique iroh's portmapper uses —
/// asking the router for an explicit UDP/TCP mapping turns many hard home NATs into easy ones
/// before hole punching even starts. Every failure is silent: a router that does not speak
/// UPnP simply contributes no mapping.</summary>
internal sealed class UpnpIgdClient : IDisposable
{
    private const string IgdSearchTarget1 = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
    private const string IgdSearchTarget2 = "urn:schemas-upnp-org:device:InternetGatewayDevice:2";
    private static readonly TimeSpan SsdpWindow = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan HttpTimeout = TimeSpan.FromSeconds(1500 / 1000.0 + 500);

    private static HttpClient CreateHttpClient() => new(new SocketsHttpHandler
    {
        ConnectTimeout = TimeSpan.FromSeconds(1.5),
        UseProxy = false,
        AllowAutoRedirect = false,
    });
    private readonly HttpClient _http = CreateHttpClient();

    /// <summary>Asks the network's IGD for a mapping to <paramref name="internalPort"/>
    /// and returns the lease, or null when no gateway answered or none accepted the request.
    /// <paramref name="ssdpUnicast"/> overrides multicast discovery (test seam).</summary>
    public async Task<UpnpMapping?> TryMapAsync(int internalPort, TimeSpan lease,
        IPEndPoint? ssdpUnicast, CancellationToken ct, ProtocolType protocol = ProtocolType.Udp)
    {
        if (internalPort is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(internalPort));
        if (protocol is not (ProtocolType.Udp or ProtocolType.Tcp)) throw new ArgumentOutOfRangeException(nameof(protocol));
        if (lease <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(lease));
        lease = TimeSpan.FromSeconds(Math.Clamp((long)lease.TotalSeconds, 1, 604800));
        foreach (Uri location in await DiscoverAsync(ssdpUnicast, ct).ConfigureAwait(false))
        {
            ct.ThrowIfCancellationRequested();
            UpnpMapping? mapping = await TryMapDeviceAsync(location, internalPort, lease, ct, protocol).ConfigureAwait(false);
            if (mapping is not null)
            {
                return mapping;
            }
        }

        return null;
    }

    private static async Task<List<Uri>> DiscoverAsync(IPEndPoint? unicast, CancellationToken ct)
    {
        var locations = new List<Uri>();
        TimeSpan window = unicast is null ? SsdpWindow : TimeSpan.FromMilliseconds(300); // unicast replies are immediate; multicast needs the full window
        using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
        {
            ReceiveTimeout = (int)window.TotalMilliseconds,
        };
        udp.Bind(new IPEndPoint(IPAddress.Any, 0));

        IPEndPoint target = unicast ?? new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);
        byte[] msearch1 = Encoding.ASCII.GetBytes(BuildMSearch(IgdSearchTarget1, unicast is null));
        byte[] msearch2 = Encoding.ASCII.GetBytes(BuildMSearch(IgdSearchTarget2, unicast is null));
        _ = udp.SendTo(msearch1, SocketFlags.None, target);
        _ = udp.SendTo(msearch2, SocketFlags.None, target);

        // Responses are unicast to our ephemeral port; collect LOCATION headers until the
        // window closes. Duplicate locations across the two search targets are expected.
        var buf = new byte[2048];
        long deadline = Environment.TickCount64 + (long)window.TotalMilliseconds;
        var seen = new HashSet<Uri>();
        while (Environment.TickCount64 < deadline && locations.Count < 8)
        {
            ct.ThrowIfCancellationRequested();
            int n;
            EndPoint source = new IPEndPoint(IPAddress.Any, 0);
            try
            {
                if (!udp.Poll((int)Math.Max(1, deadline - Environment.TickCount64) * 1000, SelectMode.SelectRead))
                {
                    break;
                }

                n = udp.ReceiveFrom(buf, ref source);
            }
            catch (SocketException)
            {
                break;
            }

            string? location = ParseLocationHeader(buf.AsSpan(0, n));
            if (source is not IPEndPoint responder || unicast is not null && !responder.Equals(unicast)) continue;
            if (location is not null && Uri.TryCreate(location, UriKind.Absolute, out Uri? uri)
                && await PinLocationAsync(uri, responder.Address, ct).ConfigureAwait(false) is { } pinned && seen.Add(pinned))
            {
                locations.Add(pinned);
            }
        }

        return locations;
    }

    private static async Task<Uri?> PinLocationAsync(Uri uri, IPAddress responder, CancellationToken ct)
    {
        if (!IsRouterAddress(responder) || !IsHttpUrl(uri)) return null;
        try
        {
            IPAddress[] addresses = IPAddress.TryParse(uri.Host, out IPAddress? literal) ? [literal]
                : await Dns.GetHostAddressesAsync(uri.DnsSafeHost, ct).ConfigureAwait(false);
            if (!addresses.Contains(responder)) return null;
            return new UriBuilder(uri) { Host = responder.ToString() }.Uri;
        }
        catch (SocketException) { return null; }
    }

    internal static bool IsRouterAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (IPAddress.IsLoopback(address)) return true; // explicit local fixtures
        if (address.AddressFamily == AddressFamily.InterNetworkV6) return address.IsIPv6LinkLocal || (address.GetAddressBytes()[0] & 0xfe) == 0xfc;
        byte[] bytes = address.GetAddressBytes();
        return bytes[0] == 10 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31
            || bytes[0] == 192 && bytes[1] == 168 || bytes[0] == 169 && bytes[1] == 254
            || bytes[0] == 100 && bytes[1] is >= 64 and <= 127;
    }

    internal static bool IsHttpUrl(Uri uri) => uri.IsAbsoluteUri && uri.Scheme is "http" or "https"
        && string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment);

    private static string BuildMSearch(string searchTarget, bool multicast) =>
        "M-SEARCH * HTTP/1.1\r\n" +
        $"HOST: {(multicast ? "239.255.255.250:1900" : "host")}\r\n" +
        "MAN: \"ssdp:discover\"\r\n" +
        "MX: 1\r\n" +
        $"ST: {searchTarget}\r\n\r\n";

    private static string? ParseLocationHeader(ReadOnlySpan<byte> response)
    {
        string text = Encoding.ASCII.GetString(response);
        if (!text.StartsWith("HTTP/1.1 200 ", StringComparison.OrdinalIgnoreCase)
            && !text.StartsWith("HTTP/1.0 200 ", StringComparison.OrdinalIgnoreCase)) return null;
        foreach (string line in text.Split('\n'))
        {
            int colon = line.IndexOf(':');
            if (colon > 0 && line[..colon].Trim().Equals("LOCATION", StringComparison.OrdinalIgnoreCase))
            {
                return line[(colon + 1)..].Trim();
            }
        }

        return null;
    }

    private async Task<UpnpMapping?> TryMapDeviceAsync(Uri location, int internalPort, TimeSpan lease, CancellationToken ct, ProtocolType protocol)
    {
        XDocument? description = await TryGetXmlAsync(location, ct).ConfigureAwait(false);
        if (description is null)
        {
            return null;
        }

        foreach ((string serviceType, Uri controlUrl) in FindConnectionServices(description, location))
        {
            IPAddress? externalIp = await TryGetExternalIpAsync(controlUrl, serviceType, ct).ConfigureAwait(false);
            if (externalIp is null)
            {
                continue; // without the public address the mapping is not advertizable
            }

            IPAddress localIp = LocalAddressTowards(controlUrl.Host);
            (int externalPort, int wireLease)? added =
                await TryAddAnyPortAsync(controlUrl, serviceType, internalPort, localIp, lease, ct, protocol).ConfigureAwait(false)
                ?? await TryAddPortAsync(controlUrl, serviceType, internalPort, localIp, lease, ct, protocol).ConfigureAwait(false);
            if (added is not { } result)
            {
                continue;
            }

            // The lease owns its HTTP client. Disposing discovery cannot break later
            // renewals/releases, which used to share this short-lived client's handle.
            return new UpnpMapping(CreateHttpClient(), controlUrl, serviceType, new IPEndPoint(externalIp, result.externalPort),
                internalPort, localIp, result.wireLease, lease, protocol);
        }

        return null;
    }

    internal static List<(string ServiceType, Uri ControlUrl)> FindConnectionServices(XDocument description, Uri baseUrl)
    {
        // Namespace-agnostic walk: device trees vary more than the spec admits, and a
        // strict namespace match silently loses routers that ship creative XML.
        string[] preference =
        [
            "urn:schemas-upnp-org:service:WANIPConnection:2",
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANPPPConnection:1",
        ];

        return FindServices(description, baseUrl, preference);
    }

    internal static List<(string ServiceType, Uri ControlUrl)> FindServices(XDocument description, Uri baseUrl, string[] preference)
    {
        var found = new List<(string ServiceType, Uri ControlUrl)>();

        foreach (XElement service in description.Descendants().Where(e => e.Name.LocalName == "service"))
        {
            string? type = service.Elements().FirstOrDefault(e => e.Name.LocalName == "serviceType")?.Value.Trim();
            string? control = service.Elements().FirstOrDefault(e => e.Name.LocalName == "controlURL")?.Value.Trim();
            if (type is null || control is null || !preference.Contains(type))
            {
                continue;
            }

            if (Uri.TryCreate(baseUrl, control, out Uri? resolved) && IsHttpUrl(resolved)
                && resolved.Host.Equals(baseUrl.Host, StringComparison.OrdinalIgnoreCase))
            {
                found.Add((type, resolved));
                if (found.Count >= 8) break;
            }
        }

        return found.OrderBy(s => Array.IndexOf(preference, s.ServiceType)).ToList();
    }

    private async Task<XDocument?> TryGetXmlAsync(Uri url, CancellationToken ct)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(HttpTimeout);
            using HttpResponseMessage response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            return await ReadXmlAsync(response.Content, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or XmlException or OperationCanceledException or IOException or SocketException)
        {
            return null;
        }
    }

    private async Task<IPAddress?> TryGetExternalIpAsync(Uri controlUrl, string serviceType, CancellationToken ct)
    {
        try
        {
            XDocument? body = await SoapCallAsync(controlUrl, serviceType, "GetExternalIPAddress", "", ct).ConfigureAwait(false);
            string? ip = body?.Descendants().FirstOrDefault(e => e.Name.LocalName == "NewExternalIPAddress")?.Value.Trim();
            return IPAddress.TryParse(ip, out IPAddress? parsed) && parsed.AddressFamily == AddressFamily.InterNetwork
                && parsed.GetAddressBytes()[0] is > 0 and < 224
                ? parsed
                : null;
        }
        catch (UpnpFaultException)
        {
            return null;
        }
    }

    private async Task<(int Port, int WireLease)?> TryAddAnyPortAsync(Uri controlUrl, string serviceType,
        int internalPort, IPAddress localIp, TimeSpan lease, CancellationToken ct, ProtocolType protocol)
    {
        try
        {
            string args =
                Arg("NewRemoteHost", "") +
                Arg("NewExternalPort", "0") +
                Arg("NewProtocol", ProtocolName(protocol)) +
                Arg("NewInternalPort", internalPort.ToString()) +
                Arg("NewInternalClient", localIp.ToString()) +
                Arg("NewEnabled", "1") +
                Arg("NewPortMappingDescription", "pinhole") +
                Arg("NewLeaseDuration", ((int)lease.TotalSeconds).ToString());
            XDocument? body = await SoapCallAsync(controlUrl, serviceType, "AddAnyPortMapping", args, ct).ConfigureAwait(false);
            string? reserved = body?.Descendants().FirstOrDefault(e => e.Name.LocalName == "NewReservedPort")?.Value.Trim();
            return int.TryParse(reserved, out int port) && port is > 0 and <= 65535 ? (port, (int)lease.TotalSeconds) : null;
        }
        catch (UpnpFaultException)
        {
            return null; // IGDv1 devices do not know the action; the AddPortMapping fallback is next
        }
    }

    private async Task<(int Port, int WireLease)?> TryAddPortAsync(Uri controlUrl, string serviceType,
        int internalPort, IPAddress localIp, TimeSpan lease, CancellationToken ct, ProtocolType protocol)
    {
        // IGDv1 has no "pick a port" action: try our own port first (the best case — the
        // reflexive candidate then matches the mapped one), then a couple past it. A 725
        // fault means "only permanent leases supported" and is retried with an infinite one.
        for (int attempt = 0; attempt < 3; attempt++)
        {
            int external = internalPort + attempt;
            if (external > 65535) break;
            int wireLease = (int)lease.TotalSeconds;
            string args =
                Arg("NewRemoteHost", "") +
                Arg("NewExternalPort", external.ToString()) +
                Arg("NewProtocol", ProtocolName(protocol)) +
                Arg("NewInternalPort", internalPort.ToString()) +
                Arg("NewInternalClient", localIp.ToString()) +
                Arg("NewEnabled", "1") +
                Arg("NewPortMappingDescription", "pinhole") +
                Arg("NewLeaseDuration", ((int)lease.TotalSeconds).ToString());
            (XDocument? body, int fault) = await SoapCallWithFaultAsync(controlUrl, serviceType, "AddPortMapping", args, ct).ConfigureAwait(false);

            if (fault == 725)
            {
                wireLease = 0;
                args = args.Replace(Arg("NewLeaseDuration", ((int)lease.TotalSeconds).ToString()),
                    Arg("NewLeaseDuration", "0"));
                (body, fault) = await SoapCallWithFaultAsync(controlUrl, serviceType, "AddPortMapping", args, ct).ConfigureAwait(false);
            }

            if (fault == 0)
            {
                return (external, wireLease);
            }

            if (fault != 718)
            {
                return null; // conflict is retryable; anything else is this device's final word
            }
        }

        return null;
    }

    private async Task<(XDocument? Body, int FaultCode)> SoapCallWithFaultAsync(Uri controlUrl, string serviceType,
        string action, string args, CancellationToken ct)
    {
        try
        {
            XDocument? body = await SoapCallAsync(controlUrl, serviceType, action, args, ct).ConfigureAwait(false);
            return (body, body is null ? -1 : 0);
        }
        catch (UpnpFaultException fault)
        {
            return (null, fault.Code);
        }
    }

    private static string Arg(string name, string value) => $"<{name}>{value}</{name}>";
    private static string ProtocolName(ProtocolType protocol) => protocol == ProtocolType.Tcp ? "TCP" : "UDP";

    internal static async Task<XDocument?> SoapCallAsync(HttpClient http, Uri controlUrl, string serviceType,
        string action, string args, CancellationToken ct)
    {
        string envelope =
            $"<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xml.org/soap/envelope/\" " +
            $"s:encodingStyle=\"http://schemas.xml.org/soap/envelope/\"><s:Body>" +
            $"<u:{action} xmlns:u=\"{serviceType}\">{args}</u:{action}></s:Body></s:Envelope>";
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(HttpTimeout);
            using var content = new StringContent(envelope, Encoding.UTF8, "text/xml");
            using HttpRequestMessage request = new(HttpMethod.Post, controlUrl);
            request.Content = content;
            request.Headers.TryAddWithoutValidation("SOAPACTION", $"\"{serviceType}#{action}\"");
            using HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            XDocument? body = null;
            if (response.Content is not null)
            {
                try { body = await ReadXmlAsync(response.Content, timeout.Token).ConfigureAwait(false); }
                catch (XmlException) { body = null; }
            }

            if (response.IsSuccessStatusCode)
            {
                return body;
            }

            throw UpnpFaultException.Parse(body) ?? new UpnpFaultException(0);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or SocketException or OperationCanceledException)
        {
            return null; // transport failure: this device's answer is silence
        }
        catch (UpnpFaultException)
        {
            throw; // SOAP faults are meaningful to the caller, not transport noise
        }
    }

    private Task<XDocument?> SoapCallAsync(Uri controlUrl, string serviceType, string action, string args, CancellationToken ct) =>
        SoapCallAsync(_http, controlUrl, serviceType, action, args, ct);

    internal static async Task<XDocument> ReadXmlAsync(HttpContent content, CancellationToken ct)
    {
        const int limit = 65536;
        if (content.Headers.ContentLength > limit) throw new IOException("UPnP XML exceeds the response limit");
        using Stream stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var bytes = new MemoryStream();
        byte[] scratch = new byte[4096];
        int count;
        while ((count = await stream.ReadAsync(scratch, ct).ConfigureAwait(false)) != 0)
        {
            if (bytes.Length + count > limit) throw new IOException("UPnP XML exceeds the response limit");
            bytes.Write(scratch, 0, count);
        }
        bytes.Position = 0;
        using XmlReader reader = XmlReader.Create(bytes, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = limit,
        });
        return XDocument.Load(reader);
    }

    private static IPAddress LocalAddressTowards(string host)
    {
        // Which local address routes to the IGD: a zero-byte "connect" on a UDP socket
        // performs no traffic yet makes the OS choose the source address.
        try
        {
            if (!IPAddress.TryParse(host, out IPAddress? ip))
            {
                ip = Dns.GetHostAddresses(host).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            }

            if (ip is null)
            {
                return IPAddress.Loopback;
            }

            using var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            probe.Connect(new IPEndPoint(ip, 9));
            return ((IPEndPoint)probe.LocalEndPoint!).Address;
        }
        catch (SocketException)
        {
            return IPAddress.Loopback;
        }
    }

    public void Dispose() => _http.Dispose();

    /// <summary>A live router mapping and the SOAP handles to keep it that way.</summary>
    internal sealed class UpnpMapping(HttpClient http, Uri controlUrl, string serviceType, IPEndPoint external,
        int internalPort, IPAddress internalClient, int wireLease, TimeSpan lease, ProtocolType protocol) : IPortMapLease
    {
        public IPEndPoint External { get; } = external;
        public TimeSpan Lifetime => lease;

        public async Task<bool> RenewAsync(CancellationToken ct)
        {
            // Renew the exact granted port. AddAny with external=0 could allocate a
            // different entry, leave the first one behind, and publish a stale address.
            try
            {
                string args =
                    Arg("NewRemoteHost", "") +
                    Arg("NewExternalPort", External.Port.ToString(CultureInfo.InvariantCulture)) +
                    Arg("NewProtocol", ProtocolName(protocol)) +
                    Arg("NewInternalPort", internalPort.ToString()) +
                    Arg("NewInternalClient", internalClient.ToString()) +
                    Arg("NewEnabled", "1") +
                    Arg("NewPortMappingDescription", "pinhole") +
                    Arg("NewLeaseDuration", wireLease.ToString(CultureInfo.InvariantCulture));
                XDocument? body = await SoapCallAsync(http, controlUrl, serviceType,
                    "AddPortMapping", args, ct).ConfigureAwait(false);
                if (body is null)
                {
                    return false;
                }

                body = await SoapCallAsync(http, controlUrl, serviceType, "GetExternalIPAddress", "", ct).ConfigureAwait(false);
                string? address = body?.Descendants().FirstOrDefault(e => e.Name.LocalName == "NewExternalIPAddress")?.Value.Trim();
                return IPAddress.TryParse(address, out IPAddress? renewed) && renewed.Equals(External.Address);
            }
            catch (UpnpFaultException)
            {
                return false;
            }
        }

        public async Task ReleaseAsync(CancellationToken ct)
        {
            string args =
                Arg("NewRemoteHost", "") +
                Arg("NewExternalPort", External.Port.ToString()) +
                Arg("NewProtocol", ProtocolName(protocol));
            await SoapCallAsync(http, controlUrl, serviceType, "DeletePortMapping", args, ct).ConfigureAwait(false);
        }

        public void Dispose() => http.Dispose();
    }

    /// <summary>A UPnP SOAP fault carrying its errorCode (718 conflict, 725 leases, ...).</summary>
    internal sealed class UpnpFaultException(int code) : Exception
    {
        public int Code { get; } = code;

        public static UpnpFaultException? Parse(XDocument? body)
        {
            XElement? detail = body?.Descendants().FirstOrDefault(e => e.Name.LocalName == "UPnPError");
            string? raw = detail?.Descendants().FirstOrDefault(e => e.Name.LocalName == "errorCode")?.Value.Trim();
            return int.TryParse(raw, out int code) ? new UpnpFaultException(code) : new UpnpFaultException(-1);
        }
    }
}
