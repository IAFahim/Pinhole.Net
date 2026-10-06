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
        IdentityKeySeed = RandomNumberGenerator.GetBytes(32), ReceiveBufferCapacity = 32,
        PublishIrohAddress = true, PublishDirectIrohAddresses = true, IrohDiscoveryHandler = handler,
        ConnectTimeout = TimeSpan.FromSeconds(5),
    };

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NativeIdOrTicket_DialsAnEncryptedPinholeSession(bool useTicket)
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
        outgoing.Send("native discovery; Pinhole session"u8);
        Assert.Equal("native discovery; Pinhole session"u8.ToArray(),
            (await accepted.ReceiveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5)))!.Value.ToArray());
        accepted.Send("authenticated reply"u8);
        Assert.Equal("authenticated reply"u8.ToArray(),
            (await outgoing.ReceiveAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5)))!.Value.ToArray());
        byte[] payload = service.Records.Values.Single();
        IrohAddress record = IrohDiscovery.ParsePayload(address.Key, payload, out _);
        Assert.Equal(PinholeNode.IrohProtocolPrefix + Convert.ToHexString(listener.StaticPublicKey!).ToLowerInvariant(), record.UserData);
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
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            string key = request.RequestUri!.AbsolutePath;
            if (request.Method == HttpMethod.Put)
            {
                Records[key] = await request.Content!.ReadAsByteArrayAsync(ct);
                return new(HttpStatusCode.OK);
            }
            return Records.TryGetValue(key, out byte[]? payload)
                ? new(HttpStatusCode.OK) { Content = new ByteArrayContent(payload) }
                : new(HttpStatusCode.NotFound);
        }
    }
}
