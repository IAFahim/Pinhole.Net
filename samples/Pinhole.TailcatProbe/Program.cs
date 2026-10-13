using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Pinhole;

// A small connectivity check, never a throughput test on shared public relays.
List<Uri> relays = [];
string? output = null;
bool tlsOnly = false;
for (int i = 0; i < args.Length; i++)
{
    if (args[i] == "--output" && i + 1 < args.Length) output = args[++i];
    else if (args[i] == "--tls-only") tlsOnly = true;
    else if (args[i] == "--all")
        relays.AddRange(new[] { "tc304a.ipn.dev", "tc303a.ipn.dev", "tc301a.ipn.dev", "tc302a.ipn.dev" }
            .Select(host => new Uri($"https://{host}/")));
    else if (Uri.TryCreate(args[i], UriKind.Absolute, out Uri? relay) && relay.Scheme == "https") relays.Add(relay);
    else throw new ArgumentException("usage: [--all | https://your-derp/] [--tls-only] [--output report.json]");
}
if (relays.Count == 0) relays.Add(new Uri("https://tc304a.ipn.dev/"));
if (tlsOnly) return await TlsDiagnostics.RunAsync(relays, output);
List<object> results = [];
int failures = 0;
foreach (Uri relay in relays.Distinct())
{
    try
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        PinholeOptions options = new()
        {
            StunServers = [], Relays = [], IrohRelayUrls = [], DerpRelayUrls = [relay],
            PublishIrohAddress = false, EnableLanDiscovery = false, EnableNetworkWatch = false,
            EnablePortMapping = false, EnableInterfaceCandidates = false,
            EnableDirectUdp = false, EnableTcpTransport = false, EnablePmtud = false,
            StunRefreshInterval = TimeSpan.Zero, ReceiveBufferCapacity = 32,
            ConnectTimeout = TimeSpan.FromSeconds(20), BindProbeBudget = TimeSpan.FromSeconds(10),
        };
        await using var listener = await PinholeNode.BindAsync(options, deadline.Token);
        await using var dialer = await PinholeNode.BindAsync(options, deadline.Token);
        string ticket = listener.ConnectionString;
        var candidates = ConnectionString.Parse(ticket).Candidates;
        if (!candidates.Any(c => c.Kind == CandidateKind.DerpRelay) || !listener.HasRelay || !dialer.HasRelay)
            throw new IOException("DERP authentication did not become ready");
        Task<PinholeConnection> accepting = listener.AcceptAsync(deadline.Token);
        var connect = Stopwatch.StartNew();
        await using var client = await dialer.ConnectAsync(ticket, deadline.Token);
        await using var server = await accepting;
        connect.Stop();
        if (!client.IsEncrypted || !server.IsEncrypted || client.Path.Kind != PathKind.Relay
            || server.Path.Kind != PathKind.Relay || client.Path.RelayUrl != relay || server.Path.RelayUrl != relay)
            throw new IOException("the connection did not use an encrypted DERP path");
        List<double> rtts = [];
        for (int i = 0; i < 3; i++)
        {
            byte[] data = RandomNumberGenerator.GetBytes(32);
            var roundTrip = Stopwatch.StartNew();
            client.Send(data);
            ReadOnlyMemory<byte> arrived = await server.ReceiveAsync(deadline.Token) ?? throw new IOException("server EOF");
            if (!arrived.Span.SequenceEqual(data)) throw new IOException("server payload mismatch");
            server.Send(arrived.Span);
            ReadOnlyMemory<byte> echoed = await client.ReceiveAsync(deadline.Token) ?? throw new IOException("client EOF");
            if (!echoed.Span.SequenceEqual(data)) throw new IOException("echo payload mismatch");
            rtts.Add(roundTrip.Elapsed.TotalMilliseconds);
        }
        results.Add(new
        {
            relay = relay.AbsoluteUri, status = "PASS", encrypted = true, path = "DERP",
            connectMs = Math.Round(connect.Elapsed.TotalMilliseconds, 2), echoes = rtts.Count,
            rttP50Ms = Math.Round(rtts.Order().ElementAt(rtts.Count / 2), 2),
            listenerTicketSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(ticket))).ToLowerInvariant(),
        });
        Console.WriteLine($"PASS {relay.Host}: encrypted DERP, {rtts.Count} echoes");
    }
    catch (Exception ex)
    {
        failures++;
        results.Add(new { relay = relay.AbsoluteUri, status = "FAIL", errorType = ex.GetType().Name });
        Console.WriteLine($"FAIL {relay.Host}: {ex.GetType().Name}");
    }
}
string report = JsonSerializer.Serialize(new
{
    capturedAtUtc = DateTimeOffset.UtcNow,
    framework = RuntimeInformation.FrameworkDescription,
    scope = "same-host peers, public DERP TLS/WebSockets, direct UDP/TCP and all other relays disabled; no NAT or phone claim",
    results,
}, new JsonSerializerOptions { WriteIndented = true });
if (output is not null)
{
    string path = Path.GetFullPath(output);
    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    await File.WriteAllTextAsync(path, report + Environment.NewLine);
}
else Console.WriteLine(report);
return failures == 0 ? 0 : 1;
