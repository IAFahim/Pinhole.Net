using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Pinhole;

/// <summary>HTTPS room metadata and credential exchange. Application data continues
/// through the existing node, including its pinned-key handshake and TURN permissions.</summary>
internal sealed class WorkerCoordinator
{
    private static readonly SocketsHttpHandler Handler = new() { AllowAutoRedirect = false };
    private static readonly HttpClient Http = new(Handler, disposeHandler: false) { Timeout = TimeSpan.FromSeconds(10) };
    private static readonly HttpMessageInvoker WebSocketHttp = new(Handler, disposeHandler: false);
    private readonly string _roomUrl;
    private readonly string _token = Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
    internal string Code { get; }

    internal WorkerCoordinator(Uri endpoint, string code)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!endpoint.IsAbsoluteUri || (endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && endpoint.IsLoopback))
            || endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 || endpoint.Fragment.Length != 0)
            throw new ArgumentException("CoordinatorUrl must use HTTPS (HTTP is allowed only on loopback), without user info, query or fragment.", nameof(endpoint));
        Code = NormalizeCode(code);
        _roomUrl = endpoint.AbsoluteUri.TrimEnd('/') + "/v1/rooms/" + Code;
    }

    internal static string NormalizeCode(string code)
    {
        string normalized = code.Replace("-", "", StringComparison.Ordinal).Trim().ToUpperInvariant();
        if (normalized.Length != 9 || normalized.Any(c => !"0123456789ABCDEFGHJKMNPQRSTVWXYZ".Contains(c)))
            throw new ArgumentException("Invitation codes contain nine base32 characters.", nameof(code));
        return normalized;
    }

    internal static async Task<PinholeHost> HostAsync(PinholeHostSettings settings, CancellationToken ct)
    {
        var worker = new WorkerCoordinator(settings.CoordinatorUrl!, PinholeHost.NewCode());
        PinholeNode? node = null;
        try
        {
            WorkerReply lease = await worker.RequestAsync(HttpMethod.Put, "", null, ct).ConfigureAwait(false);
            PinholeOptions options = await OptionsAsync(settings.NodeOptions, lease, ct).ConfigureAwait(false);
            node = await PinholeNode.BindAsync(options, ct).ConfigureAwait(false);
            RequireRoute(node, options);
            await worker.PublishAsync(node.ConnectionString, ct).ConfigureAwait(false);
            return new PinholeHost(node, worker, settings.RefreshInterval);
        }
        catch
        {
            if (node is not null) await node.DisposeAsync().ConfigureAwait(false);
            await worker.DeleteBestEffortAsync().ConfigureAwait(false);
            throw;
        }
    }

    internal static async Task<PinholeConnection> JoinAsync(string code, PinholeJoinSettings settings, CancellationToken ct)
    {
        if (settings.WaitTimeout <= TimeSpan.Zero || settings.PollInterval <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(settings));
        var worker = new WorkerCoordinator(settings.CoordinatorUrl!, code);
        PinholeNode? node = null;
        bool claimed = false;
        try
        {
            WorkerReply lease;
            using (var wait = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                wait.CancelAfter(settings.WaitTimeout);
                try
                {
                    while (true)
                    {
                        try { lease = await worker.RequestAsync(HttpMethod.Post, "/join", null, wait.Token).ConfigureAwait(false); break; }
                        catch (HttpRequestException ex) when (ex.StatusCode is HttpStatusCode.NotFound or (HttpStatusCode)425)
                        { await Task.Delay(settings.PollInterval, wait.Token).ConfigureAwait(false); }
                    }
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                { throw new TimeoutException("The invitation code was not found before WaitTimeout expired."); }
            }
            claimed = true;
            PinholeOptions options = await OptionsAsync(settings.NodeOptions, lease, ct).ConfigureAwait(false);
            node = await PinholeNode.BindAsync(options, ct).ConfigureAwait(false);
            RequireRoute(node, options);
            WorkerReply pair = await worker.PublishAsync(node.ConnectionString, ct).ConfigureAwait(false);
            string invitation = ValidateInvitation(pair.PeerInvitation ?? lease.PeerInvitation);
            PinholeConnection connection = await node.ConnectAsync(invitation, ct).ConfigureAwait(false);
            _ = RetireAsync(connection, node, worker);
            return connection;
        }
        catch
        {
            if (node is not null) await node.DisposeAsync().ConfigureAwait(false);
            if (claimed) await worker.DeleteBestEffortAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async Task RetireAsync(PinholeConnection connection, PinholeNode node, WorkerCoordinator worker)
    {
        await connection.Closed.ConfigureAwait(false);
        await node.DisposeAsync().ConfigureAwait(false);
        await worker.DeleteBestEffortAsync().ConfigureAwait(false);
    }

    internal async Task<PinholeConnection> ConnectHostAsync(PinholeNode node, CancellationToken ct)
    {
        string invitation = await WaitForPeerAsync(ct).ConfigureAwait(false);
        // Seeding both nodes with both relay candidates creates the remote data-IP
        // permissions before a strict TURN server receives the initial handshake.
        return await node.ConnectAsync(invitation, ct).ConfigureAwait(false);
    }

    internal Task<WorkerReply> PublishAsync(string invitation, CancellationToken ct) =>
        RequestAsync(HttpMethod.Put, "/ticket", new WorkerInvitation { Invitation = invitation }, ct);

    internal async Task DeleteBestEffortAsync()
    {
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(3));
        try { await RequestAsync(HttpMethod.Delete, "", null, stop.Token).ConfigureAwait(false); }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException) { }
    }

    private async Task<string> WaitForPeerAsync(CancellationToken ct)
    {
        try
        {
            using var socket = new ClientWebSocket();
            socket.Options.SetRequestHeader("Authorization", "Bearer " + _token);
            socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(20);
            var url = new UriBuilder(_roomUrl + "/events") { Scheme = _roomUrl.StartsWith("https:", StringComparison.Ordinal) ? "wss" : "ws" };
            using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                deadline.CancelAfter(TimeSpan.FromSeconds(5));
                await socket.ConnectAsync(url.Uri, WebSocketHttp, deadline.Token).ConfigureAwait(false);
            }
            var buffer = new byte[8192];
            int length = 0;
            while (true)
            {
                ValueWebSocketReceiveResult result = await socket.ReceiveAsync(buffer.AsMemory(length), ct).ConfigureAwait(false);
                if (result.MessageType == WebSocketMessageType.Close) throw new IOException("Coordinator signaling closed.");
                if (result.MessageType != WebSocketMessageType.Text || length + result.Count >= buffer.Length)
                    throw new InvalidDataException("Coordinator signaling message exceeded its bound.");
                length += result.Count;
                if (!result.EndOfMessage) continue;
                WorkerReply reply = ParseReply(buffer.AsSpan(0, length));
                if (reply.PeerInvitation is not null) return ValidateInvitation(reply.PeerInvitation);
                length = 0;
            }
        }
        catch (Exception ex) when (ex is WebSocketException or HttpRequestException or IOException
            || ex is OperationCanceledException && !ct.IsCancellationRequested)
        {
            // HTTPS polling also works behind proxies that refuse WebSocket upgrades.
        }
        while (true)
        {
            WorkerReply reply = await RequestAsync(HttpMethod.Get, "", null, ct).ConfigureAwait(false);
            if (reply.PeerInvitation is not null) return ValidateInvitation(reply.PeerInvitation);
            await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
        }
    }

    private async Task<WorkerReply> RequestAsync(HttpMethod method, string suffix, WorkerInvitation? body, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        CancellationToken requestToken = deadline.Token;
        using var request = new HttpRequestMessage(method, _roomUrl + suffix);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (method == HttpMethod.Put || method == HttpMethod.Post)
        {
            request.Content = new ByteArrayContent(body is null ? "{}"u8.ToArray()
                : JsonSerializer.SerializeToUtf8Bytes(body, WorkerJson.Default.WorkerInvitation));
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }
        using HttpResponseMessage response = await Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, requestToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException(response.StatusCode == HttpStatusCode.Conflict
                ? "The invitation code is already claimed by another participant."
                : $"Coordinator request failed with HTTP {(int)response.StatusCode}.", null, response.StatusCode);
        if (response.StatusCode == HttpStatusCode.NoContent) return new WorkerReply { Version = 1 };
        if (response.Content.Headers.ContentLength > 65536) throw new InvalidDataException("Coordinator response exceeded its bound.");
        await using Stream stream = await response.Content.ReadAsStreamAsync(requestToken).ConfigureAwait(false);
        using var buffer = new MemoryStream();
        byte[] scratch = new byte[4096];
        int read;
        while ((read = await stream.ReadAsync(scratch, requestToken).ConfigureAwait(false)) != 0)
        {
            if (buffer.Length + read > 65536) throw new InvalidDataException("Coordinator response exceeded its bound.");
            buffer.Write(scratch, 0, read);
        }
        return ParseReply(buffer.GetBuffer().AsSpan(0, (int)buffer.Length));
    }

    private static WorkerReply ParseReply(ReadOnlySpan<byte> bytes)
    {
        try
        {
            WorkerReply reply = JsonSerializer.Deserialize(bytes, WorkerJson.Default.WorkerReply)
                ?? throw new InvalidDataException("Coordinator returned an empty response.");
            if (reply.Version != 1 || reply.IceServers is null || reply.IceServers.Length > 8)
                throw new InvalidDataException("Unsupported coordinator response.");
            return reply;
        }
        catch (JsonException) { throw new InvalidDataException("Coordinator returned invalid JSON."); }
    }

    internal static string ValidateInvitation(string? invitation)
    {
        if (invitation is null || invitation.Length > 4096 || !ConnectionString.TryParse(invitation, out var parsed)
            || parsed.StaticKey is null || !parsed.Candidates.Any())
            throw new InvalidDataException("Coordinator returned an invalid or unpinned invitation.");
        return invitation;
    }

    private static void RequireRoute(PinholeNode node, PinholeOptions options)
    {
        if (!node.HasRelay && !options.EnableDirectUdp && !options.EnableTcpTransport)
            throw new IOException("TURN allocation failed and direct transports are disabled.");
    }

    private static async Task<PinholeOptions> OptionsAsync(PinholeOptions? supplied, WorkerReply lease, CancellationToken ct)
    {
        PinholeOptions options = supplied ?? new PinholeOptions { ReceiveBufferCapacity = 256 };
        if (options.Encryption != PinholeEncryption.Required)
            throw new ArgumentException("Coordinator sessions require pinned-key encryption.", nameof(supplied));
        if (lease.CredentialExpiresAt is { } expires && expires <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            throw new InvalidDataException("Coordinator TURN credentials have expired.");
        var turns = new List<TurnServerConfig>();
        var stuns = new List<IPEndPoint>();
        foreach (WorkerIce server in lease.IceServers)
        {
            if (server is null || server.Urls is null || server.Urls.Length > 16) throw new InvalidDataException("Invalid ICE URLs.");
            foreach (string raw in server.Urls)
            {
                if (raw is null || raw.Length > 1024) throw new InvalidDataException("Invalid ICE URL.");
                bool turn = raw.StartsWith("turn:", StringComparison.OrdinalIgnoreCase) && options.Relays is null;
                bool stun = raw.StartsWith("stun:", StringComparison.OrdinalIgnoreCase) && options.StunServers is null;
                if (!turn && !stun) continue;
                if (!Uri.TryCreate("udp://" + raw[5..], UriKind.Absolute, out Uri? uri) || uri.Port is < 1 or > 65535
                    || uri.UserInfo.Length != 0 || turn && uri.Query != "?transport=udp") continue;
                if (turn && (string.IsNullOrWhiteSpace(server.Username) || string.IsNullOrWhiteSpace(server.Credential)))
                    throw new InvalidDataException("TURN credentials are incomplete.");
                IPAddress[] addresses = await Dns.GetHostAddressesAsync(uri.Host, ct).ConfigureAwait(false);
                IPAddress? address = addresses.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork)
                    ?? addresses.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetworkV6);
                if (address is null) throw new IOException("The coordinator's ICE server has no usable address.");
                var endpoint = new IPEndPoint(address, uri.Port);
                if (turn) turns.Add(new(endpoint, server.Username!, server.Credential!));
                else stuns.Add(endpoint);
            }
        }
        return options with
        {
            Relays = options.Relays ?? turns.Distinct().Take(8).ToArray(),
            StunServers = options.StunServers ?? stuns.Distinct().Take(8).ToArray(),
            IrohRelayUrls = options.IrohRelayUrls ?? [],
            PublishIrohAddress = false,
        };
    }
}

internal sealed class WorkerReply
{
    public int Version { get; set; }
    public string? PeerInvitation { get; set; }
    public WorkerIce[] IceServers { get; set; } = [];
    public long? CredentialExpiresAt { get; set; }
}
internal sealed class WorkerIce
{
    public string[] Urls { get; set; } = [];
    public string? Username { get; set; }
    public string? Credential { get; set; }
}
internal sealed class WorkerInvitation
{
    public string Invitation { get; set; } = string.Empty;
}
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(WorkerReply))]
[JsonSerializable(typeof(WorkerInvitation))]
internal partial class WorkerJson : JsonSerializerContext;
