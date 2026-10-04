using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;
using System.Xml;

namespace Pinhole;

/// <summary>UPnP Internet Gateway Device client: SSDP discovery, device-description parsing,
/// and the SOAP actions a pinhole needs (AddAnyPortMapping with AddPortMapping fallback,
/// GetExternalIPAddress, DeletePortMapping). The same technique iroh's portmapper uses —
/// asking the router for an explicit UDP mapping turns many hard home NATs into easy ones
/// before hole punching even starts. Every failure is silent: a router that does not speak
/// UPnP simply contributes no mapping.</summary>
internal sealed class UpnpIgdClient : IDisposable
{
    private const string IgdSearchTarget1 = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
    private const string IgdSearchTarget2 = "urn:schemas-upnp-org:device:InternetGatewayDevice:2";
    private static readonly TimeSpan SsdpWindow = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan HttpTimeout = TimeSpan.FromSeconds(1500 / 1000.0 + 500);

    private readonly HttpClient _http = new(new SocketsHttpHandler
    {
        ConnectTimeout = TimeSpan.FromSeconds(1.5),
        UseProxy = false,
    });

    /// <summary>Asks the network's IGD for a UDP mapping to <paramref name="internalPort"/>
    /// and returns the lease, or null when no gateway answered or none accepted the request.
    /// <paramref name="ssdpUnicast"/> overrides multicast discovery (test seam).</summary>
    public async Task<UpnpMapping?> TryMapAsync(int internalPort, TimeSpan lease,
        IPEndPoint? ssdpUnicast, CancellationToken ct)
    {
        foreach (Uri location in await DiscoverAsync(ssdpUnicast, ct).ConfigureAwait(false))
        {
            UpnpMapping? mapping = await TryMapDeviceAsync(location, internalPort, lease, ct).ConfigureAwait(false);
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
        using var udp = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
        {
            ReceiveTimeout = (int)SsdpWindow.TotalMilliseconds,
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
        long deadline = Environment.TickCount64 + (long)SsdpWindow.TotalMilliseconds;
        var seen = new HashSet<Uri>();
        while (Environment.TickCount64 < deadline)
        {
            int n;
            try
            {
                if (!udp.Poll((int)Math.Max(1, deadline - Environment.TickCount64), SelectMode.SelectRead))
                {
                    break;
                }

                n = udp.Receive(buf);
            }
            catch (SocketException)
            {
                break;
            }

            string? location = ParseLocationHeader(buf.AsSpan(0, n));
            if (location is not null && Uri.TryCreate(location, UriKind.Absolute, out Uri? uri) && seen.Add(uri))
            {
                locations.Add(uri);
            }
        }

        return locations;
    }

    private static string BuildMSearch(string searchTarget, bool multicast) =>
        "M-SEARCH * HTTP/1.1\r\n" +
        $"HOST: {(multicast ? "239.255.255.250:1900" : "host")}\r\n" +
        "MAN: \"ssdp:discover\"\r\n" +
        "MX: 1\r\n" +
        $"ST: {searchTarget}\r\n\r\n";

    private static string? ParseLocationHeader(ReadOnlySpan<byte> response)
    {
        string text = Encoding.ASCII.GetString(response);
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

    private async Task<UpnpMapping?> TryMapDeviceAsync(Uri location, int internalPort, TimeSpan lease, CancellationToken ct)
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
            (int externalPort, bool anyPort)? added =
                await TryAddAnyPortAsync(controlUrl, serviceType, internalPort, localIp, lease, ct).ConfigureAwait(false)
                ?? await TryAddPortAsync(controlUrl, serviceType, internalPort, localIp, lease, ct).ConfigureAwait(false);
            if (added is not { } result)
            {
                continue;
            }

            return new UpnpMapping(_http, controlUrl, serviceType, new IPEndPoint(externalIp, result.externalPort),
                internalPort, localIp, result.anyPort, lease);
        }

        return null;
    }

    private static List<(string ServiceType, Uri ControlUrl)> FindConnectionServices(XDocument description, Uri baseUrl)
    {
        // Namespace-agnostic walk: device trees vary more than the spec admits, and a
        // strict namespace match silently loses routers that ship creative XML.
        var found = new List<(string ServiceType, Uri ControlUrl)>();
        string[] preference =
        [
            "urn:schemas-upnp-org:service:WANIPConnection:2",
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANPPPConnection:1",
        ];

        foreach (XElement service in description.Descendants().Where(e => e.Name.LocalName == "service"))
        {
            string? type = service.Elements().FirstOrDefault(e => e.Name.LocalName == "serviceType")?.Value.Trim();
            string? control = service.Elements().FirstOrDefault(e => e.Name.LocalName == "controlURL")?.Value.Trim();
            if (type is null || control is null || !preference.Contains(type))
            {
                continue;
            }

            if (Uri.TryCreate(baseUrl, control, out Uri? resolved))
            {
                found.Add((type, resolved));
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
            using HttpResponseMessage response = await _http.GetAsync(url, timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            using Stream stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
            return XDocument.Load(stream);
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
                ? parsed
                : null;
        }
        catch (UpnpFaultException)
        {
            return null;
        }
    }

    private async Task<(int Port, bool AnyPort)?> TryAddAnyPortAsync(Uri controlUrl, string serviceType,
        int internalPort, IPAddress localIp, TimeSpan lease, CancellationToken ct)
    {
        try
        {
            string args =
                Arg("NewRemoteHost", "") +
                Arg("NewExternalPort", "0") +
                Arg("NewProtocol", "UDP") +
                Arg("NewInternalPort", internalPort.ToString()) +
                Arg("NewInternalClient", localIp.ToString()) +
                Arg("NewEnabled", "1") +
                Arg("NewPortMappingDescription", "pinhole") +
                Arg("NewLeaseDuration", ((int)lease.TotalSeconds).ToString());
            XDocument? body = await SoapCallAsync(controlUrl, serviceType, "AddAnyPortMapping", args, ct).ConfigureAwait(false);
            string? reserved = body?.Descendants().FirstOrDefault(e => e.Name.LocalName == "NewReservedPort")?.Value.Trim();
            return int.TryParse(reserved, out int port) && port > 0 ? (port, true) : null;
        }
        catch (UpnpFaultException)
        {
            return null; // IGDv1 devices do not know the action; the AddPortMapping fallback is next
        }
    }

    private async Task<(int Port, bool AnyPort)?> TryAddPortAsync(Uri controlUrl, string serviceType,
        int internalPort, IPAddress localIp, TimeSpan lease, CancellationToken ct)
    {
        // IGDv1 has no "pick a port" action: try our own port first (the best case — the
        // reflexive candidate then matches the mapped one), then a couple past it. A 725
        // fault means "only permanent leases supported" and is retried with an infinite one.
        for (int attempt = 0; attempt < 3; attempt++)
        {
            int external = internalPort + attempt;
            string args =
                Arg("NewRemoteHost", "") +
                Arg("NewExternalPort", external.ToString()) +
                Arg("NewProtocol", "UDP") +
                Arg("NewInternalPort", internalPort.ToString()) +
                Arg("NewInternalClient", localIp.ToString()) +
                Arg("NewEnabled", "1") +
                Arg("NewPortMappingDescription", "pinhole") +
                Arg("NewLeaseDuration", ((int)lease.TotalSeconds).ToString());
            (XDocument? body, int fault) = await SoapCallWithFaultAsync(controlUrl, serviceType, "AddPortMapping", args, ct).ConfigureAwait(false);

            if (fault == 725)
            {
                args = args.Replace(Arg("NewLeaseDuration", ((int)lease.TotalSeconds).ToString()),
                    Arg("NewLeaseDuration", "0"));
                (body, fault) = await SoapCallWithFaultAsync(controlUrl, serviceType, "AddPortMapping", args, ct).ConfigureAwait(false);
            }

            if (fault == 0)
            {
                return (external, false);
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
            return (body, 0);
        }
        catch (UpnpFaultException fault)
        {
            return (null, fault.Code);
        }
    }

    private static string Arg(string name, string value) => $"<{name}>{value}</{name}>";

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
            using HttpResponseMessage response = await http.SendAsync(request, timeout.Token).ConfigureAwait(false);
            XDocument? body = null;
            if (response.Content is not null)
            {
                using Stream stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
                try { body = XDocument.Load(stream); }
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
        int internalPort, IPAddress internalClient, bool anyPort, TimeSpan lease) : IPortMapLease
    {
        public IPEndPoint External { get; } = external;
        public TimeSpan Lifetime => lease;

        public async Task<bool> RenewAsync(CancellationToken ct)
        {
            // Re-adding with the same values refreshes the lease (and AddAnyPortMapping
            // returns the same reserved port).
            try
            {
                string args =
                    Arg("NewRemoteHost", "") +
                    (anyPort
                        ? Arg("NewExternalPort", "0")
                        : Arg("NewExternalPort", External.Port.ToString())) +
                    Arg("NewProtocol", "UDP") +
                    Arg("NewInternalPort", internalPort.ToString()) +
                    Arg("NewInternalClient", internalClient.ToString()) +
                    Arg("NewEnabled", "1") +
                    Arg("NewPortMappingDescription", "pinhole") +
                    Arg("NewLeaseDuration", ((int)lease.TotalSeconds).ToString());
                XDocument? body = await SoapCallAsync(http, controlUrl, serviceType,
                    anyPort ? "AddAnyPortMapping" : "AddPortMapping", args, ct).ConfigureAwait(false);
                if (body is null)
                {
                    return false;
                }

                if (anyPort)
                {
                    string? reserved = body.Descendants().FirstOrDefault(e => e.Name.LocalName == "NewReservedPort")?.Value.Trim();
                    return int.TryParse(reserved, out int port) && port == External.Port;
                }

                return true;
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
                Arg("NewProtocol", "UDP");
            await SoapCallAsync(http, controlUrl, serviceType, "DeletePortMapping", args, ct).ConfigureAwait(false);
        }

        public void Dispose()
        {
        }
    }

    /// <summary>A UPnP SOAP fault carrying its errorCode (718 conflict, 725 leases, ...).</summary>
    private sealed class UpnpFaultException(int code) : Exception
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
