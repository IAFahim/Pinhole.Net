using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Independent SOAP fixtures for the standard firewall-control service,
/// combined with the real serialized lease worker. No OS socket success is assumed.</summary>
public sealed class IPv6FirewallTests
{
    private const string Service = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1";
    private static readonly Uri Control = new("http://[fe80::1%3]:5000/firewall");
    private static readonly IPEndPoint Internal = new(IPAddress.Parse("2001:db8:123::10"), 53317);
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(4);
    private static string Field(XDocument body, string name) => body.Descendants().Single(e => e.Name.LocalName == name).Value;
    private static string Response(string action, string args) => $"<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body><u:{action}Response xmlns:u='{Service}'>{args}</u:{action}Response></s:Body></s:Envelope>";

    private sealed class Router : HttpMessageHandler
    {
        internal readonly List<(string Action, XDocument Body)> Requests = [];
        internal string Status = "<FirewallEnabled>1</FirewallEnabled><InboundPinholeAllowed>1</InboundPinholeAllowed>";
        internal string Id = "<UniqueID>42</UniqueID>";
        internal string? FaultAction, Override;
        internal bool Disposed;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string soapAction = request.Headers.GetValues("SOAPACTION").Single().Trim('"');
            Assert.StartsWith(Service + "#", soapAction);
            string action = soapAction.Split('#')[1];
            Requests.Add((action, XDocument.Parse(await request.Content!.ReadAsStringAsync(ct))));
            bool fault = action == FaultAction;
            string body = Override ?? (fault
                ? "<s:Envelope xmlns:s='http://schemas.xmlsoap.org/soap/envelope/'><s:Body><s:Fault><detail><UPnPError><errorCode>606</errorCode></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
                : Response(action, action switch { "GetFirewallStatus" => Status, "AddPinhole" => Id, _ => "" }));
            return new(fault ? HttpStatusCode.InternalServerError : HttpStatusCode.OK)
            { Content = new StringContent(body, Encoding.UTF8, "text/xml") };
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }

    [Theory]
    [InlineData(false, 17)]
    [InlineData(true, 6)]
    public async Task Lease_RequestsOnlyItsEndpointAndRenewsAndDeletesTheGrantedId(bool tcp, int protocol)
    {
        var router = new Router();
        using var http = new HttpClient(router);
        var lease = await UpnpIPv6FirewallClient.TryCreateOnServiceAsync(http, Control, Internal,
            tcp ? ProtocolType.Tcp : ProtocolType.Udp, TimeSpan.FromHours(1), default);
        Assert.NotNull(lease);
        using (lease)
        {
            Assert.Equal(Internal, lease.External);
            Assert.Equal(TimeSpan.FromHours(1), lease.Lifetime);
            Assert.Equal(new[] { "GetFirewallStatus", "AddPinhole" }, router.Requests.Select(r => r.Action));
            XDocument add = router.Requests[1].Body;
            Assert.Equal(new[] { "RemoteHost", "RemotePort", "InternalClient", "InternalPort", "Protocol", "LeaseTime" },
                add.Descendants(XName.Get("AddPinhole", Service)).Single().Elements().Select(e => e.Name.LocalName));
            Assert.Equal("", Field(add, "RemoteHost")); Assert.Equal("0", Field(add, "RemotePort"));
            Assert.Equal("2001:db8:123::10", Field(add, "InternalClient"));
            Assert.Equal("53317", Field(add, "InternalPort"));
            Assert.Equal(protocol.ToString(), Field(add, "Protocol")); Assert.Equal("3600", Field(add, "LeaseTime"));
            Assert.True(await lease.RenewAsync(default));
            Assert.Equal("GetFirewallStatus", router.Requests[^2].Action);
            Assert.Equal("UpdatePinhole", router.Requests[^1].Action);
            Assert.Equal("42", Field(router.Requests[^1].Body, "UniqueID"));
            Assert.Equal("3600", Field(router.Requests[^1].Body, "NewLeaseTime"));
            await lease.ReleaseAsync(default);
            Assert.Equal("DeletePinhole", router.Requests[^1].Action);
            Assert.Equal("42", Field(router.Requests[^1].Body, "UniqueID"));
        }
        Assert.True(router.Disposed);
    }

    [Theory]
    [InlineData("0", "1")]
    [InlineData("1", "0")]
    [InlineData("maybe", "1")]
    [InlineData("1", "")]
    public async Task RefusedOrDisabledFirewall_DoesNotRequestOrPublishALease(string enabled, string allowed)
    {
        var router = new Router { Status = $"<FirewallEnabled>{enabled}</FirewallEnabled><InboundPinholeAllowed>{allowed}</InboundPinholeAllowed>" };
        using var http = new HttpClient(router);
        Assert.Null(await UpnpIPv6FirewallClient.TryCreateOnServiceAsync(http, Control, Internal, ProtocolType.Udp, TimeSpan.FromHours(1), default));
        Assert.Equal("GetFirewallStatus", Assert.Single(router.Requests).Action);
    }

    [Theory]
    [InlineData("GetFirewallStatus")]
    [InlineData("AddPinhole")]
    public async Task AuthorizationFault_DoesNotYieldALease(string action)
    {
        var router = new Router { FaultAction = action };
        using var http = new HttpClient(router);
        Assert.Null(await UpnpIPv6FirewallClient.TryCreateOnServiceAsync(http, Control, Internal, ProtocolType.Tcp, TimeSpan.FromHours(1), default));
    }

    [Theory]
    [InlineData("<UniqueID>-1</UniqueID>")]
    [InlineData("<UniqueID>65536</UniqueID>")]
    [InlineData("")]
    [InlineData("<UniqueID>42</UniqueID><UniqueID>43</UniqueID>")]
    public async Task MalformedGrantedId_DoesNotYieldALease(string id)
    {
        var router = new Router { Id = id };
        using var http = new HttpClient(router);
        Assert.Null(await UpnpIPv6FirewallClient.TryCreateOnServiceAsync(http, Control, Internal, ProtocolType.Udp, TimeSpan.FromHours(1), default));
    }

    [Fact]
    public async Task ZeroIdAndNamespacedFields_AreValidAndLeaseDurationIsBounded()
    {
        var router = new Router
        {
            Status = $"<FirewallEnabled xmlns='{Service}'>true</FirewallEnabled><InboundPinholeAllowed xmlns='{Service}'>yes</InboundPinholeAllowed>",
            Id = $"<UniqueID xmlns='{Service}'>0</UniqueID>",
        };
        using var http = new HttpClient(router);
        using var lease = await UpnpIPv6FirewallClient.TryCreateOnServiceAsync(http, Control, Internal, ProtocolType.Udp, TimeSpan.FromDays(3), default);
        Assert.NotNull(lease); Assert.Equal(TimeSpan.FromDays(1), lease.Lifetime);
        await lease.ReleaseAsync(default);
        Assert.Equal("0", Field(router.Requests[^1].Body, "UniqueID"));
    }

    [Fact]
    public async Task ChangedPolicyOrMissingPinhole_InvalidatesRenewal()
    {
        var router = new Router();
        using var http = new HttpClient(router);
        using var lease = await UpnpIPv6FirewallClient.TryCreateOnServiceAsync(http, Control, Internal, ProtocolType.Udp, TimeSpan.FromHours(1), default);
        Assert.NotNull(lease);
        router.Status = "<FirewallEnabled>1</FirewallEnabled><InboundPinholeAllowed>0</InboundPinholeAllowed>";
        Assert.False(await lease.RenewAsync(default));
        Assert.Equal("GetFirewallStatus", router.Requests[^1].Action);
        router.Status = "<FirewallEnabled>1</FirewallEnabled><InboundPinholeAllowed>1</InboundPinholeAllowed>";
        router.FaultAction = "UpdatePinhole";
        Assert.False(await lease.RenewAsync(default));
    }

    [Fact]
    public async Task XmlFaultsTruncationAndWrongAction_CannotBecomeSuccessfulReplies()
    {
        foreach (string xml in new[] { "truncated", "<!DOCTYPE x [<!ENTITY a 'data'>]><x>&a;</x>", "<x>" + new string('a', 65537) + "</x>", Response("WrongAction", "<FirewallEnabled>1</FirewallEnabled><InboundPinholeAllowed>1</InboundPinholeAllowed>") })
        {
            var router = new Router { Override = xml };
            using var http = new HttpClient(router);
            Assert.Null(await UpnpIPv6FirewallClient.TryCreateOnServiceAsync(http, Control, Internal, ProtocolType.Udp, TimeSpan.FromHours(1), default));
        }
    }

    [Fact]
    public void DescriptionAndLocation_CannotRedirectToAnotherHostAndScopesAreLocal()
    {
        string response = "HTTP/1.1 200 OK\r\nLOCATION: http://[fe80::1%999]:5000/device.xml\r\n\r\n";
        Uri? pinned = UpnpIPv6FirewallClient.PinLocation(response, IPAddress.Parse("fe80::1%3"), 7);
        Assert.NotNull(pinned);
        Assert.Equal(IPAddress.Parse("fe80::1%7"), IPAddress.Parse(pinned.DnsSafeHost));
        foreach (string bad in new[] { "http://[fe80::2]/device.xml", "http://example.com/device.xml", "file:///device.xml", "http://user:password@[fe80::1]/device.xml", "http://[fe80::1]/device.xml#x" })
            Assert.Null(UpnpIPv6FirewallClient.PinLocation("HTTP/1.1 200 OK\r\nLOCATION: " + bad + "\r\n\r\n", IPAddress.Parse("fe80::1%3"), 7));
        Assert.Null(UpnpIPv6FirewallClient.PinLocation(response.Replace("200 OK", "404 Missing"), IPAddress.Parse("fe80::1%3"), 7));
        Assert.Null(UpnpIPv6FirewallClient.PinLocation(response, IPAddress.Parse("2001:db8::1"), 7));
        string description = $"<root><service><serviceType>{Service}</serviceType><controlURL>/firewall</controlURL></service><service><serviceType>{Service}</serviceType><controlURL>http://[fe80::2]/firewall</controlURL></service></root>";
        var services = UpnpIgdClient.FindServices(XDocument.Parse(description), pinned, [Service]);
        Assert.Equal("/firewall", Assert.Single(services).ControlUrl.AbsolutePath);
        Assert.Equal(IPAddress.Parse("fe80::1%7"), IPAddress.Parse(services[0].ControlUrl.DnsSafeHost));
    }

    [Fact]
    public async Task OnlyGlobalIPv6AndTheActualNonPrivilegedPort_AreEligible()
    {
        using var http = new HttpClient(new Router());
        foreach (string ip in new[] { "192.168.1.1", "fe80::123", "fd00::123", "::", "::1", "ff02::1" })
            await Assert.ThrowsAsync<ArgumentException>(() => UpnpIPv6FirewallClient.TryCreateOnServiceAsync(http, Control,
                new IPEndPoint(IPAddress.Parse(ip), 53317), ProtocolType.Udp, TimeSpan.FromHours(1), default));
        await Assert.ThrowsAsync<ArgumentException>(() => UpnpIPv6FirewallClient.TryCreateOnServiceAsync(http, Control,
            new IPEndPoint(Internal.Address, 80), ProtocolType.Tcp, TimeSpan.FromHours(1), default));
        Assert.Empty(IPv6FirewallService.Gather(new IPEndPoint(IPAddress.Loopback, 53317)));
    }

    private sealed class Lease(IPEndPoint endpoint) : IPortMapLease
    {
        public IPEndPoint External => endpoint;
        public TimeSpan Lifetime => TimeSpan.FromHours(1);
        internal int Releases;
        public Task<bool> RenewAsync(CancellationToken ct) => Task.FromResult(true);
        public Task ReleaseAsync(CancellationToken ct) { Interlocked.Increment(ref Releases); return Task.CompletedTask; }
        public void Dispose() { }
    }

    [Fact]
    public async Task InterfaceAndPortChanges_WithdrawAndReleaseTheOldLeasesWithBoundedSources()
    {
        var calls = new ConcurrentQueue<(IPv6LanSource Source, int Port, ProtocolType Protocol)>();
        var leases = new ConcurrentQueue<Lease>();
        using var service = new IPv6FirewallService(new(), () => { }, (source, port, protocol, _) =>
        {
            calls.Enqueue((source, port, protocol)); var lease = new Lease(new IPEndPoint(source.Address, port)); leases.Enqueue(lease);
            return Task.FromResult<IPortMapLease?>(lease);
        });
        var sources = Enumerable.Range(1, 8).Select(i => new IPv6LanSource(IPAddress.Parse($"2001:db8::{i}"), i)).ToArray();
        service.Refresh(sources, 53317, 53318);
        await TestPoll.UntilAsync(Budget, () => service.Snapshot(ProtocolType.Udp).Count == 2 && service.Snapshot(ProtocolType.Tcp).Count == 2);
        Assert.Equal(4, calls.Count);
        Assert.All(calls, c => Assert.InRange(c.Source.InterfaceIndex, 1, 2));
        service.Refresh(sources, 53317, 53318); Assert.Equal(4, calls.Count); // no redundant request/lease renewal
        service.Refresh([sources[4]], 54417, null);
        Assert.Empty(service.Snapshot(ProtocolType.Tcp));
        await TestPoll.UntilAsync(Budget, () => service.Snapshot(ProtocolType.Udp).SingleOrDefault()?.Port == 54417 && leases.Take(4).All(l => l.Releases == 1));
        Assert.Equal(sources[4].Address, Assert.Single(service.Snapshot(ProtocolType.Udp)).Address);
        service.Dispose(); await service.Completed.WaitAsync(Budget);
        Assert.Empty(service.Snapshot(ProtocolType.Udp)); Assert.All(leases, l => Assert.Equal(1, l.Releases));
    }

    [Fact]
    public async Task ShutdownDuringDiscovery_ReleasesTheLateGrantAndDoesNotRetainIt()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var answer = new TaskCompletionSource<IPortMapLease?>(TaskCreationOptions.RunContinuationsAsynchronously);
        var late = new Lease(Internal);
        using var service = new IPv6FirewallService(new(), () => { }, (_, _, _, _) => { started.TrySetResult(); return answer.Task; });
        service.Refresh([new(Internal.Address, 3)], Internal.Port, null);
        await started.Task.WaitAsync(Budget);
        service.Dispose(); answer.SetResult(late); await service.Completed.WaitAsync(Budget);
        Assert.Empty(service.Snapshot(ProtocolType.Udp)); Assert.Equal(1, late.Releases);
        service.Refresh([new(Internal.Address, 3)], Internal.Port, null);
        Assert.Empty(service.Snapshot(ProtocolType.Udp));
    }

    [Fact]
    public async Task RapidInterfaceChurn_BoundsCancelledWorkersUntilTheirDiscoveriesFinish()
    {
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = new ConcurrentQueue<Lease>();
        using var service = new IPv6FirewallService(new(), () => { }, async (source, port, _, _) =>
        {
            var lease = new Lease(new IPEndPoint(source.Address, port)); calls.Enqueue(lease);
            await resume.Task; // deliberately model an uncancellable late gateway response
            return lease;
        });
        try
        {
            for (int i = 1; i <= IPv6FirewallService.MaxWorkers; i++)
            {
                service.Refresh([new(IPAddress.Parse($"2001:db8::{i:x}"), i)], Internal.Port, null);
                await TestPoll.UntilAsync(Budget, () => calls.Count == i);
            }
            for (int i = 50; i < 150; i++)
                service.Refresh([new(IPAddress.Parse($"2001:db8::{i:x}"), i)], Internal.Port, null);
            Assert.Equal(IPv6FirewallService.MaxWorkers, calls.Count);
            Assert.Empty(service.Snapshot(ProtocolType.Udp));
        }
        finally { service.Dispose(); resume.TrySetResult(); }
        await service.Completed.WaitAsync(Budget);
        Assert.All(calls, lease => Assert.Equal(1, lease.Releases));
    }
}
