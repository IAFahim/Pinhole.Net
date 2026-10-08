using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using Xunit;

namespace Pinhole.Tests;

public sealed class PinholeIrohDiscoveryTests
{
    private static PinholeOptions Options(HttpMessageHandler handler) => new()
    {
        Bind = new IPEndPoint(IPAddress.Loopback, 0), StunServers = [], IrohRelayUrls = [],
        EnableNetworkWatch = false, EnablePortMapping = false, StunRefreshInterval = TimeSpan.Zero,
        EnableLanDiscovery = false,
        IdentityKeySeed = RandomNumberGenerator.GetBytes(32), ReceiveBufferCapacity = 32,
        IrohDiscoveryHandler = handler,
        ConnectTimeout = TimeSpan.FromSeconds(5),
    };

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DefaultPublication_NativeIdOrTicket_DialsAnEncryptedDirectSession(bool useTicket)
    {
        using var service = new MemoryPkarr();
        await using var listener = await PinholeNode.BindAsync(Options(service));
        await using var dialer = await PinholeNode.BindAsync(Options(service) with { PublishIrohAddress = false });
        IrohAddress address = listener.IrohAddress;
        Task<PinholeConnection> incoming = listener.AcceptAsync();
        using PinholeConnection outgoing = await dialer.ConnectIrohAsync(useTicket ? address.ToString() : address.EndpointId);
        using PinholeConnection accepted = await incoming.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(outgoing.IsEncrypted);
        Assert.True(accepted.IsEncrypted);
        Assert.Equal(PathKind.Direct, outgoing.Path.Kind);
        Assert.Equal(PathKind.Direct, accepted.Path.Kind);
        outgoing.Send("native discovery; Pinhole session"u8);
        Assert.Equal("native discovery; Pinhole session"u8.ToArray(),
            (await accepted.ReceiveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5)))!.Value.ToArray());
        accepted.Send("authenticated reply"u8);
        Assert.Equal("authenticated reply"u8.ToArray(),
            (await outgoing.ReceiveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5)))!.Value.ToArray());
        byte[] payload = service.Records.Values.Single();
        IrohAddress record = IrohDiscovery.ParsePayload(address.Key, payload, out _);
        Assert.Contains(new IPEndPoint(IPAddress.Loopback, listener.LocalPort), record.DirectAddresses);
        Assert.Equal(PinholeNode.IrohProtocolPrefix + Convert.ToHexString(listener.StaticPublicKey!).ToLowerInvariant(), record.UserData);
    }

    [Fact]
    public async Task PublicationOptOut_DoesNotContactTheService()
    {
        using var service = new MemoryPkarr();
        await using var node = await PinholeNode.BindAsync(Options(service) with { PublishIrohAddress = false });
        Assert.Equal(0, service.PutAttempts);
        Assert.Empty(service.Records);
        Assert.NotNull(node.StaticPublicKey);
    }

    [Fact]
    public async Task DirectAddressOptOut_KeepsTheSignedSessionBinding()
    {
        using var service = new MemoryPkarr();
        await using var node = await PinholeNode.BindAsync(Options(service) with { PublishDirectIrohAddresses = false });
        IrohAddress record = IrohDiscovery.ParsePayload(node.IrohAddress.Key, service.Records.Values.Single(), out _);
        Assert.Empty(record.DirectAddresses);
        Assert.Equal(PinholeNode.IrohProtocolPrefix + Convert.ToHexString(node.StaticPublicKey!).ToLowerInvariant(), record.UserData);
    }

    [Fact]
    public async Task ManyDirectCandidates_FitNativeDiscoveryWithoutLosingTheSignedBinding()
    {
        using var service = new MemoryPkarr();
        using var http = new HttpClient(service, disposeHandler: false);
        var identity = new RelayIdentity();
        var discovery = new IrohDiscovery(http, new Uri("http://127.0.0.1/pkarr"));
        IPEndPoint[] local = Enumerable.Range(1, 24)
            .Select(i => new IPEndPoint(IPAddress.Parse($"fd00:1111:2222:3333:4444:5555:6666:{i:x}"), 65535)).ToArray();
        IPEndPoint[] routable = Enumerable.Range(1, 8)
            .Select(i => new IPEndPoint(IPAddress.Parse($"2001:db8:2222:3333:4444:5555:6666:{i:x}"), 65535)).ToArray();
        var address = new IrohAddress(Convert.ToHexString(identity.PublicKey), local.Concat(routable).ToArray(), PinholeOptions.PublicIrohRelays)
        { UserData = PinholeNode.IrohProtocolPrefix + new string('a', 64) };
        Assert.Throws<InvalidDataException>(() => IrohDiscovery.CreatePayload(address, identity, 1));

        await discovery.PublishAsync(address, identity, CancellationToken.None);
        byte[] payload = service.Records.Values.Single();
        Assert.InRange(payload.Length, 84, IrohDiscovery.MaxPayloadSize);
        IrohAddress record = IrohDiscovery.ParsePayload(identity.PublicKey, payload, out _);
        Assert.Equal(address.UserData, record.UserData);
        Assert.Equal(address.RelayUrls, record.RelayUrls);
        Assert.True(record.DirectAddresses.Count < address.DirectAddresses.Count);
        Assert.All(routable, ep => Assert.Contains(ep, record.DirectAddresses));
    }

    [Fact]
    public async Task DiscoveryOutage_DoesNotPreventAnEncryptedDirectConnection()
    {
        using var service = new MemoryPkarr { RejectPuts = true };
        await using var listener = await PinholeNode.BindAsync(Options(service));
        await using var dialer = await PinholeNode.BindAsync(Options(service) with { PublishIrohAddress = false });
        Task<PinholeConnection> incoming = listener.AcceptAsync();
        await using PinholeConnection outgoing = await dialer.ConnectAsync(listener.ConnectionString);
        await using PinholeConnection accepted = await incoming.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, service.PutAttempts);
        Assert.Empty(service.Records);
        Assert.True(outgoing.IsEncrypted);
        Assert.True(accepted.IsEncrypted);
        Assert.Equal(PathKind.Direct, outgoing.Path.Kind);
        outgoing.Send("discovery is best effort"u8);
        Assert.Equal("discovery is best effort"u8.ToArray(),
            (await accepted.ReceiveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5)))!.Value.ToArray());
    }

    [Fact]
    public async Task ModifiedDiscovery_CannotReplaceThePinnedSessionKey()
    {
        using var service = new MemoryPkarr();
        await using var listener = await PinholeNode.BindAsync(Options(service));
        await using var dialer = await PinholeNode.BindAsync(Options(service) with { PublishIrohAddress = false });
        service.Records.Values.Single()[^1] ^= 1;
        await Assert.ThrowsAsync<InvalidDataException>(() => dialer.ConnectIrohAsync(listener.IrohAddress.EndpointId));
        Assert.Empty(dialer.Connections);
    }

    [Fact]
    public async Task NativeEndpointWithoutPinholeBinding_IsRejectedBeforeDialing()
    {
        using var service = new MemoryPkarr();
        var options = Options(service);
        await using var listener = await PinholeNode.BindAsync(options);
        await using var dialer = await PinholeNode.BindAsync(Options(service) with { PublishIrohAddress = false });
        string key = service.Records.Keys.Single();
        service.Records[key] = IrohDiscovery.CreatePayload(listener.IrohAddress,
            new RelayIdentity(EndpointIdentity.DeriveEndpointSeed(options.IdentityKeySeed)!), 1);
        await Assert.ThrowsAsync<InvalidOperationException>(() => dialer.ConnectIrohAsync(listener.IrohAddress.EndpointId));
        Assert.Empty(dialer.Connections);
    }

    [Fact]
    public void UserData_HasTheNativeByteLimit_AndIsNotEncodedInTickets()
    {
        var identity = new RelayIdentity();
        var address = new IrohAddress(Convert.ToHexString(identity.PublicKey)) { UserData = new string('x', 245) };
        var payload = IrohDiscovery.CreatePayload(address, identity, 1);
        Assert.Equal(address.UserData, IrohDiscovery.ParsePayload(identity.PublicKey, payload, out _).UserData);
        Assert.Null(IrohAddress.Parse(address.ToString()).UserData);
        Assert.Throws<ArgumentException>(() => IrohDiscovery.CreatePayload(
            new IrohAddress(address.EndpointId) { UserData = new string('x', 246) }, identity, 2));
    }

    private sealed class MemoryPkarr : HttpMessageHandler
    {
        internal ConcurrentDictionary<string, byte[]> Records { get; } = new();
        internal bool RejectPuts { get; init; }
        internal int PutAttempts;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string key = request.RequestUri!.AbsolutePath;
            if (request.Method == HttpMethod.Put)
            {
                Interlocked.Increment(ref PutAttempts);
                if (RejectPuts) return new(HttpStatusCode.ServiceUnavailable);
                Records[key] = await request.Content!.ReadAsByteArrayAsync(ct);
                return new(HttpStatusCode.OK);
            }
            return Records.TryGetValue(key, out byte[]? payload)
                ? new(HttpStatusCode.OK) { Content = new ByteArrayContent(payload) }
                : new(HttpStatusCode.NotFound);
        }
    }
}
