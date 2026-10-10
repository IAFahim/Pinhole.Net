using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Issue #43 socket-level negative cases: oversized frames on a real stream,
/// a substituted ticket key over the TCP sidecar, and close/rebind of the listening
/// port. These need real loopback sockets, so they run with the main suite wherever
/// the runner allows binding.</summary>
public sealed class TcpSocketHardeningTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(12);
    private static PinholeOptions Options(IPAddress bind) => new()
    {
        Bind = new IPEndPoint(bind, 0), StunServers = [], IrohRelayUrls = [],
        EnablePortMapping = false, PublishIrohAddress = false, EnableLanDiscovery = false,
        EnableNetworkWatch = false, EnableDirectUdp = false, ReceiveBufferCapacity = 16,
        ConnectTimeout = TimeSpan.FromSeconds(8), // TCP rounds start after the 1.2 s UDP-first window
    };

    /// <summary>The sidecar reuses the UDP socket's numeric port; on Windows that TCP
    /// port can sit in an excluded range (Hyper-V reserves blocks), which legitimately
    /// leaves TcpListeningPort null. These cases need the sidecar, so retry on a fresh
    /// ephemeral port rather than treating the miss as a transport defect.</summary>
    private static async Task<PinholeNode> BindWithSidecarAsync(IPAddress address, IPEndPoint? bind = null)
    {
        for (int attempt = 0; ; attempt++)
        {
            PinholeNode node = await PinholeNode.BindAsync(bind is null ? Options(address) : Options(address) with { Bind = bind });
            if (node.TcpListeningPort is not null || attempt >= 7)
            {
                return node;
            }
            await node.DisposeAsync();
            await Task.Delay(150); // a busy runner's port pressure is transient
        }
    }

    [Theory]
    [InlineData(8193)]   // one past TcpTransport.MaxFrame
    [InlineData(65535)]  // the largest u16 header a stranger can write
    public async Task OversizedFrameHeader_ClosesTheStreamWithoutASession(int declaredLength)
    {
        await using var node = await BindWithSidecarAsync(IPAddress.Loopback);
        Assert.NotNull(node.TcpListeningPort);
        using var socket = new TcpClient();
        await socket.ConnectAsync(IPAddress.Loopback, node.TcpListeningPort!.Value).WaitAsync(Timeout);
        NetworkStream stream = socket.GetStream();
        await stream.WriteAsync("PHNTCP1\n"u8.ToArray());
        await stream.ReadExactlyAsync(new byte[8]).AsTask().WaitAsync(Timeout);

        // A length header outside 13..8192 is refused before any body is read; the
        // codec must not allocate or queue a declared-length buffer for a stranger.
        byte[] header = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(header, (ushort)declaredLength);
        await stream.WriteAsync(header);
        Assert.Equal(0, await stream.ReadAsync(new byte[1]).AsTask().WaitAsync(Timeout));
        Assert.Empty(node.Connections);
    }

    [Fact]
    public async Task WrongStaticKey_TcpOnlyDial_FailsCleanlyWithoutDowngrade()
    {
        // Key substitution: the ticket names the real listener candidate but pins a
        // key the listener cannot prove. The dial must die inside its budget — never
        // downgrade to plaintext, never surface an unauthenticated connection.
        await using var listener = await BindWithSidecarAsync(IPAddress.Loopback);
        await using var dialer = await PinholeNode.BindAsync(Options(IPAddress.Loopback));
        ConnectionString substituted = new(
            listener.PeerId,
            [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, listener.LocalPort))],
            staticKey: RandomNumberGenerator.GetBytes(32));

        Task<PinholeConnection> accepted = listener.AcceptAsync();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => dialer.ConnectAsync(substituted.ToString()).WaitAsync(TimeSpan.FromSeconds(15)));
        Assert.Contains("does not match its connection string", ex.Message);
        Assert.Contains("man in the middle", ex.Message);

        // Each side may hold the abandoned handshake as a bounded, revivable husk, but
        // it must never surface to the application and must be condemned on schedule.
        await TestPoll.UntilAsync(TimeSpan.FromSeconds(15), () =>
            listener.Connections.Concat(dialer.Connections)
                .All(c => c.State != PinholeConnectionState.Punching));
        Assert.False(accepted.IsCompletedSuccessfully, "an unauthenticated peer was accepted");
        // Node disposal cancels the pending accept; observe its fault off-thread.
        _ = accepted.ContinueWith(static t => _ = t.Exception, TaskScheduler.Default);
    }

    [Fact]
    public async Task CloseRebind_SamePort_NewTcpSessionsWorkAndOldAreGone()
    {
        int port;
        using (var probe = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        {
            probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            port = ((IPEndPoint)probe.LocalEndPoint!).Port;
        }
        // A UDP-ephemeral port can sit in a Windows-excluded TCP range; this case needs
        // the sidecar on this exact port, so probe TCP first and bow out if the runner
        // cannot provide it (the Linux/macOS matrix still covers the full path).
        try
        {
            using var tcpProbe = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            tcpProbe.Bind(new IPEndPoint(IPAddress.Loopback, port));
        }
        catch (SocketException)
        {
            return;
        }
        var bind = new IPEndPoint(IPAddress.Loopback, port);

        PinholeConnection firstIncoming, firstOutgoing;
        await using (var listener = await BindWithSidecarAsync(IPAddress.Loopback, bind))
        {
            Assert.Equal(port, listener.TcpListeningPort);
            await using var dialer = await PinholeNode.BindAsync(Options(IPAddress.Loopback));
            var ticket = new ConnectionString(listener.PeerId,
                [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, listener.LocalPort))],
                staticKey: listener.StaticPublicKey);
            Task<PinholeConnection> accepted = listener.AcceptAsync();
            await using var outgoing = await dialer.ConnectAsync(ticket.ToString()).WaitAsync(Timeout);
            firstOutgoing = outgoing;
            firstIncoming = await accepted.WaitAsync(Timeout);
            outgoing.Send([1]);
            ReadOnlyMemory<byte>? received = await firstIncoming.ReceiveAsync().AsTask().WaitAsync(Timeout);
            Assert.NotNull(received);
            Assert.Equal(1, received.Value.Length);
            await firstIncoming.DisposeAsync();
        }

        // Disposal tore the session down on both ends; the ports are free again.
        await TestPoll.UntilAsync(Timeout, () => firstIncoming.State != PinholeConnectionState.Open);
        Assert.NotEqual(PinholeConnectionState.Open, firstOutgoing.State);

        await using var reborn = await BindWithSidecarAsync(IPAddress.Loopback, bind);
        Assert.Equal(port, reborn.TcpListeningPort);
        await using var redialer = await PinholeNode.BindAsync(Options(IPAddress.Loopback));
        var rebornTicket = new ConnectionString(reborn.PeerId,
            [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, reborn.LocalPort))],
            staticKey: reborn.StaticPublicKey);
        Task<PinholeConnection> reaccepted = reborn.AcceptAsync();
        await using var reoutgoing = await redialer.ConnectAsync(rebornTicket.ToString()).WaitAsync(Timeout);
        await using var reincoming = await reaccepted.WaitAsync(Timeout);
        reoutgoing.Send([2, 2]);
        ReadOnlyMemory<byte>? echo = await reincoming.ReceiveAsync().AsTask().WaitAsync(Timeout);
        Assert.NotNull(echo);
        Assert.Equal(new byte[] { 2, 2 }, echo.Value.ToArray());
        Assert.Equal(DirectTransport.Tcp, reoutgoing.Path.Transport);
    }
}
