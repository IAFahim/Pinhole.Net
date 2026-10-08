using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Pinhole.Tests;

public sealed class DiscoveryLifecycleTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CancellationDuringDefaultPublication_ReleasesTheBoundSocket(bool rawTransport)
    {
        int port;
        using (var reservation = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        {
            reservation.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            port = ((IPEndPoint)reservation.LocalEndPoint!).Port;
        }

        using var service = new BlockingPkarr();
        using var cancelled = new CancellationTokenSource();
        var network = new PinholeOptions
        {
            Bind = new IPEndPoint(IPAddress.Loopback, port), StunServers = [], IrohRelayUrls = [],
            EnableNetworkWatch = false, EnablePortMapping = false, EnableLanDiscovery = false,
            IrohDiscoveryHandler = service,
        };
        Task pending = rawTransport
            ? IrohTransport.BindAsync(new IrohTransportOptions { Network = network, DiscoveryHandler = service }, cancelled.Token)
            : PinholeNode.BindAsync(network, cancelled.Token);
        await service.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(TimeSpan.FromSeconds(5)));

        // A cancelled bind must not leave its socket behind while discovery is enabled.
        using var replacement = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        replacement.Bind(new IPEndPoint(IPAddress.Loopback, port));
    }

    private sealed class BlockingPkarr : HttpMessageHandler
    {
        internal TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Assert.Equal(HttpMethod.Put, request.Method);
            Started.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            return new(HttpStatusCode.OK);
        }
    }
}
