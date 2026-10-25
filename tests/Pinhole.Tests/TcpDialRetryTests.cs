using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace Pinhole.Tests;

public sealed class TcpDialRetryTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(12);

    [Fact]
    public async Task ConcurrentRetries_ShareOneLinkAndReleaseFailedReservation()
    {
        var sink = new TcpListener(IPAddress.Loopback, 0);
        sink.Start();
        var endpoint = (IPEndPoint)sink.LocalEndpoint;
        using var transport = new TcpTransport(new IPEndPoint(IPAddress.Loopback, 0), (_, _) => { }, _ => { });
        using var firstAttempt = new CancellationTokenSource();
        try
        {
            Task<TcpLink?> pending = transport.ConnectAsync(endpoint, firstAttempt.Token);
            using var accepted = await sink.AcceptSocketAsync().WaitAsync(Timeout);
            // Receiving the preface proves AddLink already owns this socket, while
            // the silent sink keeps greeting incomplete. It still occupies one slot.
            using var stream = new NetworkStream(accepted, ownsSocket: false);
            var preface = new byte[TcpTransport.Preface.Length];
            await stream.ReadExactlyAsync(preface).AsTask().WaitAsync(Timeout);
            Assert.Equal(1, transport.LiveLinks);

            TcpLink?[] blocked = await Task.WhenAll(Enumerable.Range(0, 16)
                .Select(_ => transport.ConnectAsync(endpoint, CancellationToken.None))).WaitAsync(Timeout);
            Assert.All(blocked, link => Assert.Null(link));

            firstAttempt.Cancel();
            Assert.Null(await pending.WaitAsync(Timeout));
            Assert.Equal(0, transport.LiveLinks);
            // Windows exclusive listeners cannot reclaim a port while an accepted
            // socket from the previous listener still owns it.
            stream.Dispose();
            accepted.Dispose();
            sink.Stop();

            using var peer = new TcpTransport(endpoint, (_, _) => { }, _ => { });
            Assert.Equal(endpoint.Port, peer.ListeningPort);
            TcpLink?[] retries = await Task.WhenAll(Enumerable.Range(0, 16)
                .Select(_ => transport.ConnectAsync(endpoint, CancellationToken.None))).WaitAsync(Timeout);
            TcpLink link = Assert.Single(retries.OfType<TcpLink>().Distinct());
            Assert.True(link.IsReady);
            Assert.Equal(1, transport.LiveLinks);
            link.Dispose();
            Assert.Equal(0, transport.LiveLinks);
        }
        finally
        {
            firstAttempt.Cancel();
            sink.Stop();
        }
    }

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
