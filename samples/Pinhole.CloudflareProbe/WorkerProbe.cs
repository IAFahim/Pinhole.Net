using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Pinhole.CloudflareProbe;

internal sealed record WorkerResult(bool Encrypted, string Path, string Transport,
    string InvitationHash, long HostReadyMs, long JoinAndHandshakeMs,
    int RoundTripsEachDirection, int SendAttempts, double RttP50Ms, double RttP95Ms);

internal static class WorkerProbe
{
    internal static async Task<WorkerResult> RunAsync(Uri endpoint, string mode,
        Action<string> stage, CancellationToken ct)
    {
        var options = new PinholeOptions
        {
            Bind = new IPEndPoint(mode is "direct" or "tcp" ? IPAddress.Loopback : IPAddress.Any, 0),
            Relays = mode is "direct" or "tcp" ? [] : null, StunServers = mode != "auto" ? [] : null,
            IrohRelayUrls = [], RendezvousEndpoints = [], LookupProviders = [], PublishIrohAddress = false,
            EnableDirectUdp = mode is "direct" or "auto", EnableTcpTransport = mode is "tcp" or "auto",
            EnableInterfaceCandidates = mode == "auto", EnablePortMapping = false, EnablePortPrediction = false,
            EnableNetworkWatch = false, EnableLanDiscovery = false, EnablePmtud = false,
            StunRefreshInterval = TimeSpan.Zero, ReceiveBufferCapacity = 32,
            BindProbeBudget = TimeSpan.FromSeconds(20), ConnectTimeout = TimeSpan.FromSeconds(20)
        };
        stage("worker_host");
        var watch = Stopwatch.StartNew();
        await using var host = await PinholeSession.HostAsync(new PinholeHostSettings
        { CoordinatorUrl = endpoint, NodeOptions = options }, ct);
        long hostReady = watch.ElapsedMilliseconds;
        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(host.FullInvitation))).ToLowerInvariant();
        stage("worker_join");
        watch.Restart();
        await using var joiner = await PinholeSession.JoinAsync(host.Code, new PinholeJoinSettings
        { CoordinatorUrl = endpoint, NodeOptions = options }, ct);
        await using var accepted = await host.AcceptAsync(ct);
        long handshake = watch.ElapsedMilliseconds;
        RequirePath(accepted, joiner, mode);
        stage("worker_encrypted_datagrams");
        int attempts = 0;
        var rtts = new List<double>();
        for (int direction = 0; direction < 2; direction++)
        {
            PinholeConnection from = direction == 0 ? accepted : joiner;
            PinholeConnection to = direction == 0 ? joiner : accepted;
            for (int i = 0; i < 48; i++)
            {
                byte[] payload = RandomNumberGenerator.GetBytes(256);
                bool arrived = false;
                for (int retry = 0; retry < 3 && !arrived; retry++)
                {
                    using var packet = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    packet.CancelAfter(TimeSpan.FromSeconds(3));
                    watch.Restart();
                    RequirePath(accepted, joiner, mode);
                    attempts++; from.Send(payload);
                    try
                    {
                        await ReadAsync(to, payload, packet.Token);
                        attempts++; to.Send(payload);
                        await ReadAsync(from, payload, packet.Token);
                        rtts.Add(watch.Elapsed.TotalMilliseconds);
                        arrived = true;
                    }
                    catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
                }
                if (!arrived) throw new ProbeFailure("FAIL", "WORKER_ECHO_DEADLINE_EXCEEDED");
            }
        }
        RequirePath(accepted, joiner, mode);
        rtts.Sort();
        return new(true, joiner.Path.Kind.ToString(), mode == "relay" ? "Udp" : joiner.Path.Transport?.ToString() ?? "Unknown", hash,
            hostReady, handshake, 48, attempts, rtts[rtts.Count / 2], rtts[(int)(rtts.Count * 0.95)]);
    }

    private static void RequirePath(PinholeConnection a, PinholeConnection b, string mode)
    {
        if (!a.IsEncrypted || !b.IsEncrypted || mode == "relay" &&
            (a.Path.Kind != PathKind.Relay || b.Path.Kind != PathKind.Relay || a.Path.RelayUrl is not null || b.Path.RelayUrl is not null)
            || mode is "direct" or "tcp" && (a.Path.Kind != PathKind.Direct || b.Path.Kind != PathKind.Direct)
            || mode == "direct" && (a.Path.Transport != DirectTransport.Udp || b.Path.Transport != DirectTransport.Udp)
            || mode == "tcp" && (a.Path.Transport != DirectTransport.Tcp || b.Path.Transport != DirectTransport.Tcp))
            throw new ProbeFailure("FAIL", "UNEXPECTED_WORKER_PATH");
    }

    private static async Task ReadAsync(PinholeConnection peer, byte[] expected, CancellationToken ct)
    {
        while (true)
        {
            var data = await peer.ReceiveAsync(ct);
            if (data is null) throw new ProbeFailure("FAIL", "WORKER_EARLY_CONNECTION_CLOSE");
            if (data.Value.Span.SequenceEqual(expected)) return;
        }
    }
}
