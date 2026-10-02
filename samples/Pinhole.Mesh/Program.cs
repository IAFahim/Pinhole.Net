// Pinhole mesh harness — proves NAT-independent P2P between machines that know nothing
// about each other beforehand, using only the pure-C# session API (PinholeNode).
//
//   pinhole-mesh node <index> <count>    CI mode: discovers peers over a signaling channel,
//                                        runs 3 connect/exchange/drop rounds of fresh random
//                                        secrets, exits 0 only if all rounds verify, hard
//                                        shutdown at the 5-minute deadline. Node 0 additionally
//                                        hosts guest joins until the deadline.
//   pinhole-mesh guest <cs>              Local mode: join a live session from just the printed
//                                        connection string, exchange a random secret, print
//                                        what the mesh answered.
//
// Signaling is pluggable: MESH_SIGNAL_DIR switches to a local filesystem channel (used for
// same-machine runs); otherwise the GitHub Contents API on branch $MESH_BRANCH is used, so
// three unrelated GitHub-hosted runners can find each other with nothing shared in advance
// except the repo they were spawned from. The connection string each node announces is the
// real discovery artifact: peer ID + direct/reflexive candidates + free-relay fallback.
// MESH_FORCE_RELAY=1 strips the direct candidates from announced tickets, forcing every
// connection onto the TURN relay path.

using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Pinhole;

if (args is ["node", var indexText, var countText]
    && int.TryParse(indexText, out int index) && int.TryParse(countText, out int count))
{
    return await MeshNode.RunAsync(index, count);
}

if (args is ["guest", var ticket])
{
    return await Guest.RunAsync(ticket);
}

Console.Error.WriteLine("usage: pinhole-mesh node <index> <count> | pinhole-mesh guest <cs>");
return 2;

// ---------------------------------------------------------------------------------------------

internal static class MeshJson
{
    public static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
}

internal static class MeshNode
{
    private static readonly TimeSpan Deadline = TimeSpan.FromMilliseconds(
        double.TryParse(Environment.GetEnvironmentVariable("MESH_DEADLINE_MS"), CultureInfo.InvariantCulture, out double ms) ? ms : 300_000);

    public static async Task<int> RunAsync(int index, int count)
    {
        DateTimeOffset started = DateTimeOffset.UtcNow;
        DateTimeOffset deadline = started + Deadline;

        await using ISignal signal = Signal.Create();
        await using PinholeNode node = await PinholeNode.BindAsync().WaitAsync(Reserve(deadline, 60));
        Console.WriteLine($"[node {index}] bound (peer {node.PeerId:x16}, public: {string.Join(", ", node.PublicEndpoints)})");

        int roundsOk = 0;
        List<string> mySecrets = new();
        try
        {
            await signal.AnnounceAsync($"tickets/{index}.json", JsonSerializer.Serialize(new TicketAnnounce
            {
                Index = index,
                Ticket = TicketOf(node),
            }, MeshJson.Options)).WaitAsync(Reserve(deadline, 45));

            if (index == 0)
            {
                Console.WriteLine("TICKET " + node.ConnectionString);
                try
                {
                    await File.WriteAllTextAsync("ticket.txt", node.ConnectionString + "\n");
                }
                catch (IOException)
                {
                }
            }

            Console.WriteLine($"[node {index}] waiting for {count - 1} peer tickets…");
            Dictionary<int, string> tickets = await signal.WaitForCountAsync("tickets", count, Reserve(deadline, 150));
            Console.WriteLine($"[node {index}] all tickets present: {string.Join(", ", tickets.Keys.OrderBy(k => k))}");

            for (int round = 1; round <= 3; round++)
            {
                RoundReport report = await RunRoundAsync(index, count, round, node, signal, deadline);
                await signal.AnnounceAsync($"rounds/{round}/{index}.json", JsonSerializer.Serialize(report, MeshJson.Options))
                    .WaitAsync(Reserve(deadline, 20));
                Console.WriteLine($"[node {index}] round {round}: {(report.Ok ? "OK" : "FAILED")} — {Describe(report)}");
                if (!report.Ok)
                {
                    break;
                }

                roundsOk++;
                mySecrets.Add(report.Sent);
            }
        }
        catch (Exception exception)
        {
            Console.WriteLine($"[node {index}] fatal: {exception.Message}");
        }

        // Node 0 keeps accepting guests until the deadline so any machine (e.g. a dev PC)
        // can join with the connection string while the session is live.
        if (index == 0 && Environment.GetEnvironmentVariable("MESH_LINGER") == "1")
        {
            await HostGuestsAsync(node, mySecrets, deadline);
        }

        Console.WriteLine($"[node {index}] shutting down after {(DateTimeOffset.UtcNow - started).TotalSeconds:F0}s — {roundsOk}/3 rounds verified");
        return roundsOk == 3 ? 0 : 1;

        static string Describe(RoundReport report) =>
            string.Join(" ", report.Received
                .OrderBy(kv => kv.Key)
                .Select(kv => $"peer{kv.Key}={kv.Value[..12]}…({(report.Udp.TryGetValue(kv.Key, out bool udp) && udp ? "udp" : "relay")})"));

        static TimeSpan Reserve(DateTimeOffset deadline, double seconds) =>
            TimeSpan.FromSeconds(Math.Max(1, Math.Min(seconds, (deadline - DateTimeOffset.UtcNow).TotalSeconds - 1)));
    }

    // MESH_FORCE_RELAY=1 strips direct candidates from announced tickets: peers can then
    // only meet through the TURN relay — the CI canary uses this to exercise relay paths.
    private static string TicketOf(PinholeNode node)
    {
        if (Environment.GetEnvironmentVariable("MESH_FORCE_RELAY") != "1")
        {
            return node.ConnectionString;
        }

        ConnectionString full = ConnectionString.Parse(node.ConnectionString);
        var relayOnly = full.Candidates.Where(c => c.Kind == CandidateKind.Relay).ToList();
        return new ConnectionString(full.PeerId, relayOnly, full.NatHint).ToString();
    }

    private static async Task<RoundReport> RunRoundAsync(
        int index, int count, int round, PinholeNode node, ISignal signal, DateTimeOffset deadline)
    {
        string mySecret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var contexts = new List<ConnContext>();
        TimeSpan budget = TimeSpan.FromTicks(Math.Min(
            TimeSpan.FromSeconds(80).Ticks,
            (deadline - DateTimeOffset.UtcNow - TimeSpan.FromSeconds(4)).Ticks));
        using CancellationTokenSource roundCts = new(budget);

        try
        {
            // Fresh tickets per round: a peer that roamed or rebound since the session
            // started re-announces its current candidates instead of being dialed stale.
            await signal.AnnounceAsync($"rounds/{round}/tickets/{index}.json", JsonSerializer.Serialize(new TicketAnnounce
            {
                Index = index,
                Ticket = TicketOf(node),
            }, MeshJson.Options)).WaitAsync(budget);
            Dictionary<int, string> roundTickets = await signal.WaitForCountAsync($"rounds/{round}/tickets", count, budget);

            // Lower index listens, higher index dials: every pair forms exactly one
            // connection; ConnectAsync runs the direct->relay chain internally.
            CancellationToken roundToken = roundCts.Token;
            IEnumerable<Task<PinholeConnection>> pending = Enumerable.Range(0, index)
                .Select(j => node.ConnectAsync(roundTickets[j]).WaitAsync(roundToken))
                .Concat(Enumerable.Repeat(0, count - 1 - index)
                    .Select(_ => node.AcceptAsync(roundToken).WaitAsync(roundToken)));

            // Attach the receive handler the instant each connection resolves: a datagram
            // that lands before the handler exists is gone (no reliability to lean on),
            // and the acceptor side may resolve long after peers began blasting secrets.
            async Task<PinholeConnection> Watch(Task<PinholeConnection> pendingConn)
            {
                PinholeConnection conn = await pendingConn.ConfigureAwait(false);
                var context = new ConnContext(conn);
                lock (contexts)
                {
                    contexts.Add(context);
                }

                conn.Received += context.OnFrame;
                return conn;
            }

            await Task.WhenAll(pending.Select(Watch)).ConfigureAwait(false);

            // Datagrams are unreliable: keep re-sending our secret until every peer's
            // secret is in. "I heard everyone" is not "everyone heard me", so keep a
            // floor on the retransmit window before trusting that conclusion.
            byte[] body = Encoding.UTF8.GetBytes($"SECRET:{round}:{index}:{mySecret}");
            var sw = Stopwatch.StartNew();
            while (sw.Elapsed < TimeSpan.FromSeconds(25))
            {
                lock (contexts)
                {
                    foreach (ConnContext context in contexts)
                    {
                        try { context.Conn.Send(body); }
                        catch (Exception ex) when (ex is ObjectDisposedException or InvalidOperationException or SocketException)
                        {
                            // a dead member costs its own datagram; the round retransmits next tick
                        }
                    }
                }

                bool allHeard;
                lock (contexts)
                {
                    allHeard = contexts.All(c => c.Peer >= 0);
                }

                if (allHeard && sw.Elapsed >= TimeSpan.FromSeconds(8))
                {
                    break;
                }

                await Task.Delay(allHeard ? 500 : 300).ConfigureAwait(false);
            }

            ConnContext[] heard = contexts.Where(c => c.Peer >= 0).ToArray();
            return new RoundReport
            {
                Ok = heard.Count() == count - 1,
                Sent = mySecret,
                Received = new Dictionary<int, string>(heard.Select(c => KeyValuePair.Create(c.Peer, c.Secret))),
                Udp = new Dictionary<int, bool>(heard.Select(c => KeyValuePair.Create(c.Peer, c.IsDirect))),
            };
        }
        catch (Exception exception)
        {
            Console.WriteLine($"[node {index}] round {round} error: {exception.Message}");
            return new RoundReport { Ok = false, Sent = mySecret };
        }
        finally
        {
            roundCts.Cancel();
            ConnContext[] snapshot;
            lock (contexts)
            {
                snapshot = contexts.ToArray();
            }

            foreach (ConnContext context in snapshot)
            {
                try { await context.Conn.CloseAsync().ConfigureAwait(false); }
                catch (Exception ex) when (ex is ObjectDisposedException or InvalidOperationException or SocketException)
                {
                    // teardown is best-effort; the peer sees silence either way
                }
            }
        }
    }

    /// <summary>One established connection: learns the peer's index from the first SECRET frame it delivers.</summary>
    private sealed class ConnContext(PinholeConnection conn)
    {
        public readonly PinholeConnection Conn = conn;
        public int Peer = -1;
        public string Secret = "";
        public bool IsDirect;

        public void OnFrame(ReadOnlySpan<byte> frame)
        {
            string text = Encoding.UTF8.GetString(frame);
            if (text.StartsWith("SECRET:", StringComparison.Ordinal))
            {
                string[] parts = text.Split(':');
                if (parts.Length == 4 && int.TryParse(parts[2], out int peer))
                {
                    Peer = peer;
                    Secret = parts[3];
                    IsDirect = Conn.Path.Kind == PathKind.Direct;
                }
            }
        }
    }

    private static async Task HostGuestsAsync(PinholeNode node, List<string> secrets, DateTimeOffset deadline)
    {
        Console.WriteLine($"[node 0] hosting guest joins until deadline ({(deadline - DateTimeOffset.UtcNow).TotalSeconds:F0}s left)");
        while (DateTimeOffset.UtcNow < deadline - TimeSpan.FromSeconds(8))
        {
            PinholeConnection? conn = null;
            try
            {
                conn = await node.AcceptAsync().WaitAsync(deadline - DateTimeOffset.UtcNow - TimeSpan.FromSeconds(8))
                    .ConfigureAwait(false);

                var guestSecret = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
                void OnFrame(ReadOnlySpan<byte> frame)
                {
                    string text = Encoding.UTF8.GetString(frame);
                    if (text.StartsWith("GUEST:", StringComparison.Ordinal))
                    {
                        guestSecret.TrySetResult(text["GUEST:".Length..]);
                    }
                }

                conn.Received += OnFrame;
                byte[] body = Encoding.UTF8.GetBytes("WELCOME:" + JsonSerializer.Serialize(new { from = "pinhole-mesh", secrets }));
                conn.Send(body);

                if (await Task.WhenAny(guestSecret.Task, Task.Delay(TimeSpan.FromSeconds(10))).ConfigureAwait(false) == guestSecret.Task)
                {
                    Console.WriteLine($"GUEST joined ({conn.Path.Kind}) secret {guestSecret.Task.Result[..Math.Min(16, guestSecret.Task.Result.Length)]}…");
                }

                // Bounded teardown; a pathological guest session must not stall the hosting loop.
                try { await conn.CloseAsync().WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); }
                catch (Exception ex) when (ex is ObjectDisposedException or InvalidOperationException or SocketException or TimeoutException)
                {
                    // teardown is best-effort; the peer sees silence either way
                }
            }
            catch (Exception exception)
            {
                Console.WriteLine($"[node 0] guest session ended: {exception.Message}");
                if (conn is not null)
                {
                    try { await conn.CloseAsync().WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false); }
                catch (Exception ex) when (ex is ObjectDisposedException or InvalidOperationException or SocketException or TimeoutException)
                {
                    // teardown is best-effort; the peer sees silence either way
                }
                }
            }
        }
    }
}

internal static class Guest
{
    public static async Task<int> RunAsync(string connectionString)
    {
        string mySecret = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        await using PinholeNode node = await PinholeNode.BindAsync().WaitAsync(TimeSpan.FromSeconds(60));
        await using PinholeConnection conn = await node.ConnectAsync(connectionString).WaitAsync(TimeSpan.FromSeconds(60));
        Console.WriteLine("[guest] connected to the live session");

        var answered = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        void OnFrame(ReadOnlySpan<byte> frame)
        {
            string text = Encoding.UTF8.GetString(frame);
            if (text.StartsWith("WELCOME:", StringComparison.Ordinal))
            {
                answered.TrySetResult(text["WELCOME:".Length..]);
            }
        }

        conn.Received += OnFrame;
        byte[] hello = Encoding.UTF8.GetBytes("GUEST:" + mySecret);
        var guestSw = Stopwatch.StartNew();
        while (!answered.Task.IsCompleted && guestSw.Elapsed < TimeSpan.FromSeconds(15))
        {
            try { conn.Send(hello); }
            catch (Exception ex) when (ex is ObjectDisposedException or InvalidOperationException or SocketException)
            {
                // the welcome answer is retried on the next tick
            }
            await Task.Delay(300);
        }

        if (answered.Task.IsCompleted)
        {
            Console.WriteLine($"[guest] mesh answered over {conn.Path.Kind} with its secrets:");
            Console.WriteLine(answered.Task.Result);
            return 0;
        }

        Console.WriteLine("[guest] no answer within 15s");
        return 1;
    }
}

internal sealed record TicketAnnounce
{
    public int Index { get; init; }
    public string Ticket { get; init; } = "";
}

internal sealed record RoundReport
{
    public bool Ok { get; init; }
    public string Sent { get; init; } = "";
    public Dictionary<int, string> Received { get; init; } = new();
    public Dictionary<int, bool> Udp { get; init; } = new();
}

/// <summary>A minimal signaling channel: announce a file, wait until a directory holds N announcements.</summary>
internal interface ISignal : IAsyncDisposable
{
    Task AnnounceAsync(string path, string json);

    Task<Dictionary<int, string>> WaitForCountAsync(string dir, int count, TimeSpan timeout);
}

internal static class Signal
{
    public static ISignal Create() =>
        Environment.GetEnvironmentVariable("MESH_SIGNAL_DIR") is { Length: > 0 } dir
            ? new FileSignal(dir)
            : new GithubSignal(
                Environment.GetEnvironmentVariable("MESH_REPO") ?? throw new InvalidOperationException("MESH_REPO not set"),
                Environment.GetEnvironmentVariable("MESH_BRANCH") ?? throw new InvalidOperationException("MESH_BRANCH not set"),
                Environment.GetEnvironmentVariable("GITHUB_TOKEN") ?? throw new InvalidOperationException("GITHUB_TOKEN not set"));
}

/// <summary>Local-filesystem signaling for same-machine mesh runs (MESH_SIGNAL_DIR=...).</summary>
internal sealed class FileSignal(string root) : ISignal
{
    public Task AnnounceAsync(string path, string json)
    {
        string file = Path.Combine(root, path);
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, json);
        return Task.CompletedTask;
    }

    public async Task<Dictionary<int, string>> WaitForCountAsync(string dir, int count, TimeSpan timeout)
    {
        DateTimeOffset end = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < end)
        {
            string folder = Path.Combine(root, dir);
            string[] files = Directory.Exists(folder) ? Directory.GetFiles(folder, "*.json") : Array.Empty<string>();
            if (files.Length >= count)
            {
                Dictionary<int, string> result = new();
                foreach (string file in files)
                {
                    TicketAnnounce announce = JsonSerializer.Deserialize<TicketAnnounce>(await File.ReadAllTextAsync(file), MeshJson.Options)!;
                    result[announce.Index] = announce.Ticket;
                }

                return result;
            }

            await Task.Delay(500);
        }

        throw new TimeoutException($"signaling: expected {count} files in {dir}");
    }

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

/// <summary>GitHub Contents-API signaling on a per-run branch; lets unrelated CI machines meet.</summary>
internal sealed class GithubSignal(string repo, string branch, string token) : ISignal
{
    private readonly HttpClient _http = new();

    private HttpClient Http
    {
        get
        {
            _http.DefaultRequestHeaders.Authorization = new("Bearer", token);
            _http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("pinhole-mesh");
            return _http;
        }
    }

    public async Task AnnounceAsync(string path, string json)
    {
        for (int attempt = 0; attempt < 8; attempt++)
        {
            try
            {
                await EnsureBranchAsync();
                string api = $"https://api.github.com/repos/{repo}/contents/{path}?ref={Uri.EscapeDataString(branch)}";
                string? sha = null;
                using (HttpResponseMessage existing = await Http.GetAsync(api))
                {
                    if (existing.IsSuccessStatusCode)
                    {
                        sha = JsonDocument.Parse(await existing.Content.ReadAsStringAsync()).RootElement.GetProperty("sha").GetString();
                    }
                }

                using HttpResponseMessage put = await Http.PutAsync(api, new StringContent(JsonSerializer.Serialize(new
                {
                    message = $"mesh: {path}",
                    content = Convert.ToBase64String(Encoding.UTF8.GetBytes(json)),
                    branch,
                    sha,
                }), Encoding.UTF8, "application/json"));
                if (put.IsSuccessStatusCode)
                {
                    return;
                }
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
            {
            }

            await Task.Delay(TimeSpan.FromSeconds(2 + attempt));
        }

        throw new InvalidOperationException($"signaling put failed for {path}");
    }

    public async Task<Dictionary<int, string>> WaitForCountAsync(string dir, int count, TimeSpan timeout)
    {
        DateTimeOffset end = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < end)
        {
            try
            {
                using HttpResponseMessage list = await Http.GetAsync(
                    $"https://api.github.com/repos/{repo}/contents/{dir}?ref={Uri.EscapeDataString(branch)}");
                if (list.IsSuccessStatusCode)
                {
                    Dictionary<int, string> result = new();
                    foreach (JsonElement item in JsonDocument.Parse(await list.Content.ReadAsStringAsync()).RootElement.EnumerateArray())
                    {
                        using HttpResponseMessage download = await Http.GetAsync(item.GetProperty("download_url").GetString()!);
                        if (!download.IsSuccessStatusCode)
                        {
                            continue;
                        }

                        TicketAnnounce announce = JsonSerializer.Deserialize<TicketAnnounce>(await download.Content.ReadAsStringAsync(), MeshJson.Options)!;
                        result[announce.Index] = announce.Ticket;
                    }

                    if (result.Count >= count)
                    {
                        return result;
                    }
                }
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
            {
            }

            await Task.Delay(TimeSpan.FromSeconds(3));
        }

        throw new TimeoutException($"signaling: timed out waiting for {count} files in {dir}");
    }

    private async Task EnsureBranchAsync()
    {
        if (_branchReady)
        {
            return;
        }

        using HttpResponseMessage head = await Http.GetAsync($"https://api.github.com/repos/{repo}/git/commits/{Uri.EscapeDataString(branch)}");
        if (head.IsSuccessStatusCode)
        {
            _branchReady = true;
            return;
        }

        using HttpResponseMessage main = await Http.GetAsync($"https://api.github.com/repos/{repo}/git/ref/heads/main");
        main.EnsureSuccessStatusCode();
        string sha = JsonDocument.Parse(await main.Content.ReadAsStringAsync()).RootElement.GetProperty("object").GetProperty("sha").GetString()!;
        using HttpResponseMessage create = await Http.PostAsync(
            $"https://api.github.com/repos/{repo}/git/refs",
            new StringContent(JsonSerializer.Serialize(new { @ref = $"refs/heads/{branch}", sha }), Encoding.UTF8, "application/json"));
        _branchReady = create.IsSuccessStatusCode || create.StatusCode == HttpStatusCode.UnprocessableEntity;
    }

    private bool _branchReady;

    public ValueTask DisposeAsync()
    {
        _http.Dispose();
        return ValueTask.CompletedTask;
    }
}
