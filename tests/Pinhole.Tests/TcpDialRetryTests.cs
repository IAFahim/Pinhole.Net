using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Pinhole.Tests;

/// <summary>A TCP dial round can fail transiently (slow greeting under runner load,
/// a listener rebinding, a refused connect). Those failures must not freeze the
/// endpoint for the five-second success-throttle window: the dial budget is only
/// a few seconds long, and Windows CI has seen one failed round eat the whole
/// budget (TimeoutException instead of the pinned-key InvalidOperationException in
/// TcpSocketHardeningTests, and the ::1 TcpOnly timeout in TcpSessionTests).</summary>
public sealed class TcpDialRetryTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(12);

    [Fact]
    public async Task FailedDial_DoesNotFreezeTheEndpointForTheSuccessThrottle()
    {
        // Phase 1 — a silent acceptor: the socket is accepted but never greets, so
        // the initiator's 3 s negotiation deadline fails the attempt deterministically.
        var sink = new TcpListener(IPAddress.Loopback, 0);
        sink.Start();
        int port = ((IPEndPoint)sink.LocalEndpoint).Port;
        using var transport = new TcpTransport(new IPEndPoint(IPAddress.Loopback, 0), (_, _) => { }, _ => { });
        try
        {
            Assert.Null(await transport.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port),
                CancellationToken.None).WaitAsync(Timeout));

            // Phase 2 — the silent sink is replaced by a real peer on the same port.
            // The very next dial must be able to attempt again: the old attempt-failure
            // path kept the endpoint in the five-second throttle table, so every retry
            // inside a normal ConnectTimeout returned null without even trying.
            sink.Stop();
            using var peer = new TcpTransport(new IPEndPoint(IPAddress.Loopback, port), (_, _) => { }, _ => { });
            var watch = Stopwatch.StartNew();
            TcpLink? link = await transport.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port),
                CancellationToken.None).WaitAsync(Timeout);
            watch.Stop();

            Assert.NotNull(link); // throttled retries return null instantly instead of dialing
            Assert.True(link!.IsReady);
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(3),
                $"retry took {watch.Elapsed.TotalSeconds:F1}s; a failed dial must not inherit the 5 s success throttle");
            link.Dispose();
        }
        finally
        {
            sink.Stop();
        }
    }
}
