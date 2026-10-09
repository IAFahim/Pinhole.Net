using System.Net;
using System.Net.Sockets;
using System.Buffers.Binary;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Real-socket integration. Requires normal loopback socket permission;
/// the restricted editing session cannot run these, and they must pass before ship.</summary>
public sealed class TcpSessionTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(12);
    private static PinholeOptions Options(IPAddress bind) => new()
    {
        Bind = new IPEndPoint(bind, 0), StunServers = [], IrohRelayUrls = [],
        EnablePortMapping = false, PublishIrohAddress = false, EnableLanDiscovery = false,
        EnableNetworkWatch = false, EnableDirectUdp = false, ReceiveBufferCapacity = 16,
        ConnectTimeout = TimeSpan.FromSeconds(8),
    };

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    public async Task TcpOnly_AuthenticatesExchangesDatagramsAndClosesThePeer(string address)
    {
        IPAddress ip = IPAddress.Parse(address);
        await using var listener = await PinholeNode.BindAsync(Options(ip));
        await using var dialer = await PinholeNode.BindAsync(Options(ip));
        var ticket = new ConnectionString(listener.PeerId,
            [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(ip, listener.LocalPort))], staticKey: listener.StaticPublicKey);
        Task<PinholeConnection> accepted = listener.AcceptAsync();
        await using var outgoing = await dialer.ConnectAsync(ticket.ToString()).WaitAsync(Timeout);
        await using var incoming = await accepted.WaitAsync(Timeout);
        Assert.True(outgoing.IsEncrypted);
        Assert.True(incoming.IsEncrypted);
        Assert.Equal(PathKind.Direct, outgoing.Path.Kind);
        Assert.Equal(DirectTransport.Tcp, outgoing.Path.Transport);
        Assert.Equal(DirectTransport.Tcp, incoming.Path.Transport);
        foreach (int size in new[] { 1, 60, 1200 })
        {
            byte[] bytes = Enumerable.Range(0, size).Select(i => (byte)(i * 7)).ToArray();
            outgoing.Send(bytes);
            ReadOnlyMemory<byte>? received = await incoming.ReceiveAsync().AsTask().WaitAsync(Timeout);
            Assert.NotNull(received);
            Assert.Equal(bytes, received.Value.ToArray());
            incoming.Send(bytes);
            received = await outgoing.ReceiveAsync().AsTask().WaitAsync(Timeout);
            Assert.NotNull(received);
            Assert.Equal(bytes, received.Value.ToArray());
        }
        await outgoing.CloseAsync();
        await incoming.Closed.WaitAsync(Timeout);
        Assert.Equal(PinholeConnectionState.Closed, incoming.State);
    }

    [Fact]
    public async Task HealthyUdp_RemainsPreferredWithTcpEnabledByDefault()
    {
        var options = Options(IPAddress.Loopback) with { EnableDirectUdp = true };
        await using var listener = await PinholeNode.BindAsync(options);
        await using var dialer = await PinholeNode.BindAsync(options);
        Task<PinholeConnection> accepted = listener.AcceptAsync();
        await using var connection = await dialer.ConnectAsync(listener.ConnectionString).WaitAsync(Timeout);
        await using var incoming = await accepted.WaitAsync(Timeout);
        Assert.Equal(DirectTransport.Udp, connection.Path.Transport);
        connection.Send([4]);
        await incoming.ReceiveAsync().AsTask().WaitAsync(Timeout);
        await Task.Delay(1600);
        Assert.Equal(DirectTransport.Udp, connection.Path.Transport);
    }

    [Fact]
    public async Task TcpOptOut_DoesNotOpenTheSidecarPort()
    {
        await using var node = await PinholeNode.BindAsync(Options(IPAddress.Loopback) with { EnableTcpTransport = false });
        Assert.Null(node.TcpListeningPort);
        Assert.Null(node.TcpPortMappedEndpoint);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MalformedLengthOrPlaintextStranger_CannotCreateASession(bool plaintext)
    {
        await using var node = await PinholeNode.BindAsync(Options(IPAddress.Loopback));
        using var socket = new TcpClient();
        await socket.ConnectAsync(IPAddress.Loopback, node.TcpListeningPort!.Value).WaitAsync(Timeout);
        NetworkStream stream = socket.GetStream();
        await stream.WriteAsync("PHNTCP1\n"u8.ToArray());
        byte[] reply = new byte[8];
        await stream.ReadExactlyAsync(reply).AsTask().WaitAsync(Timeout);
        Assert.Equal("PHNTCP1\n"u8.ToArray(), reply);
        byte[] packet = plaintext ? new byte[15] : new byte[2];
        if (plaintext)
        {
            packet[1] = 13; packet[2] = 0x50;
            BinaryPrimitives.WriteUInt64LittleEndian(packet.AsSpan(3), 7);
            BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(11), 123);
        }
        await stream.WriteAsync(packet);
        Assert.Equal(0, await stream.ReadAsync(new byte[1]).AsTask().WaitAsync(Timeout));
        Assert.Empty(node.Connections);
    }

    [Fact]
    public async Task SidecarAdmissionAndDisposal_AreBounded()
    {
        using var pool = new TcpTransport(new IPEndPoint(IPAddress.Loopback, 0), (_, _) => { }, _ => { });
        var clients = new List<TcpClient>();
        try
        {
            for (int i = 0; i < TcpTransport.MaxLinks; i++)
            {
                var client = new TcpClient(); clients.Add(client);
                await client.ConnectAsync(IPAddress.Loopback, pool.ListeningPort!.Value).WaitAsync(Timeout);
                await client.GetStream().WriteAsync("PHNTCP1\n"u8.ToArray());
                await client.GetStream().ReadExactlyAsync(new byte[8]).AsTask().WaitAsync(Timeout);
            }
            Assert.Equal(TcpTransport.MaxLinks, pool.LiveLinks);
            using var extra = new TcpClient();
            await extra.ConnectAsync(IPAddress.Loopback, pool.ListeningPort!.Value).WaitAsync(Timeout);
            try { Assert.Equal(0, await extra.GetStream().ReadAsync(new byte[1]).AsTask().WaitAsync(Timeout)); }
            catch (IOException) { } // a reset is also a refusal; no protocol/session was admitted
            Assert.Equal(TcpTransport.MaxLinks, pool.LiveLinks);
            pool.Dispose();
            Assert.Null(pool.ListeningPort);
            await TestPoll.UntilAsync(Timeout, () => pool.LiveLinks == 0);
        }
        finally { foreach (TcpClient client in clients) client.Dispose(); }
    }
}
