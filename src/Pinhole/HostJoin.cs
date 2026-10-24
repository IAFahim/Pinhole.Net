using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Pinhole;

/// <summary>Host side of the minimal code-share API (#45 M2): one node, one short code,
/// one accepted peer. The code maps to the host's full connection string through a
/// <c>Pinhole.Rendezvous</c> code directory or HTTPS coordinator; the underlying transport, tickets, keys,
/// NAT punching, racing, and recovery are exactly the existing engine's.</summary>
public sealed class PinholeHost : IAsyncDisposable
{
    /// <summary>The invitation code: 9 base32 characters, 45 bits of cryptographic
    /// randomness. Guessing it against a directory is the online attack, and the
    /// directory answers at its own rate.</summary>
    public string Code { get; }

    /// <summary>The full <c>pinhole1:</c> invitation. Sharing this out of band
    /// (chat, voice) authenticates the host key end to end without trusting the
    /// code directory; the short code is the convenience path.</summary>
    public string FullInvitation => _node.ConnectionString;

    /// <summary>A human-comparable fingerprint of the invitation (16 base32 chars,
    /// 80 bits). Hosts and joiners display it and compare out of band to detect a
    /// malicious directory substituting a different key. This is a fingerprint
    /// check, not a PAKE: it detects, it does not prevent.</summary>
    public string ConfirmationCode { get; }

    private readonly PinholeNode _node;
    private readonly CodeDirectory? _directory;
    private readonly WorkerCoordinator? _worker;
    private readonly Task<PinholeConnection>? _workerConnection;
    private string _token;
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Task _keepalive;
    private readonly TimeSpan _refreshInterval;
    private int _disposed;

    internal PinholeHost(PinholeNode node, CodeDirectory directory, string code, string token, TimeSpan refreshInterval)
    {
        _node = node;
        _directory = directory;
        Code = code;
        _token = token;
        _refreshInterval = refreshInterval;
        string raw = Fingerprint(Encoding.UTF8.GetBytes(node.ConnectionString));
        ConfirmationCode = $"{raw[..4]}-{raw[4..8]}-{raw[8..12]}-{raw[12..16]}";
        _keepalive = KeepaliveAsync();
    }

    internal PinholeHost(PinholeNode node, WorkerCoordinator worker, TimeSpan refreshInterval)
    {
        _node = node;
        _worker = worker;
        _token = string.Empty;
        Code = worker.Code;
        _refreshInterval = refreshInterval;
        string raw = Fingerprint(Encoding.UTF8.GetBytes(node.ConnectionString));
        ConfirmationCode = $"{raw[..4]}-{raw[4..8]}-{raw[8..12]}-{raw[12..16]}";
        _workerConnection = worker.ConnectHostAsync(node, _shutdown.Token);
        _keepalive = KeepaliveAsync();
    }

    /// <summary>Waits for a joiner to complete the pinned-key handshake. The returned
    /// connection is the engine's own <see cref="PinholeConnection"/>: datagrams,
    /// roaming, recovery, and disposal behave exactly as with ticket dials.</summary>
    public Task<PinholeConnection> AcceptAsync(CancellationToken ct = default) =>
        _workerConnection is { } paired ? paired.WaitAsync(ct) : _node.AcceptAsync(ct);

    /// <summary>Stops the keepalive, deletes the code from the directory (best effort,
    /// bounded), and disposes the underlying node and its sessions.</summary>
    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _shutdown.Cancel();
        try { await _keepalive.ConfigureAwait(false); }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is HttpRequestException or IOException) { }
        if (_worker is { } worker) await worker.DeleteBestEffortAsync().ConfigureAwait(false);
        else await _directory!.DeleteAsync(Code, _token).ConfigureAwait(false);
        await _node.DisposeAsync().ConfigureAwait(false);
        if (_workerConnection is { } paired)
        {
            try { await paired.ConfigureAwait(false); }
            catch (Exception ex) when (ex is OperationCanceledException or HttpRequestException or IOException or TimeoutException or InvalidOperationException) { }
        }
        _shutdown.Dispose();
    }

    private async Task KeepaliveAsync()
    {
        // Refresh at the default-directory TTL/3 so one lost datagram cannot expire
        // the code; the delete on dispose still ends the registration promptly.
        while (!_shutdown.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_refreshInterval, _shutdown.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            if (_worker is { } worker)
            {
                if (_workerConnection?.IsCompleted == true) return;
                try { await worker.PublishAsync(_node.ConnectionString, _shutdown.Token).ConfigureAwait(false); }
                catch (Exception ex) when (ex is HttpRequestException or IOException) { }
                catch (OperationCanceledException) when (!_shutdown.IsCancellationRequested) { }
            }
            else
            {
                // Desired state: the code maps to this host's live string. A refresh that
                // comes back NOCODE means the directory lost the code (restart, eviction)
                // and must not be retried with a token forever — reconcile by claiming
                // again. If another host grabbed the code in the gap the claim draws TokB
                // and the next refresh interval retries.
                if (await _directory!.RefreshAsync(Code, _token, _node.ConnectionString, _shutdown.Token).ConfigureAwait(false)
                    == CodeDirectory.RefreshOutcome.NoCode)
                {
                    string? reclaimed = await _directory.PutAsync(Code, _node.ConnectionString, _shutdown.Token).ConfigureAwait(false);
                    if (reclaimed is not null)
                    {
                        _token = reclaimed;
                    }
                }
            }
        }
    }

    internal static string Fingerprint(byte[] invitation)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(invitation, hash);
        return FormatBase32(hash[..10]); // 80 bits, formatted by the caller in groups
    }

    internal static string NewCode()
    {
        // Crockford-ish alphabet: no I, L, O, U, 0, 1 — unambiguous to read aloud.
        // Crockford's 32: no I, L, O, or U — unambiguous to read aloud.
        const string alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        Span<char> code = stackalloc char[9];
        RandomNumberGenerator.GetItems(alphabet, code);
        return new string(code);
    }

    internal static string FormatBase32(ReadOnlySpan<byte> bytes)
    {
        const string alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        var chars = new char[(bytes.Length * 8 + 4) / 5];
        int bitBuffer = 0, bitCount = 0, index = 0;
        foreach (byte b in bytes)
        {
            bitBuffer = (bitBuffer << 8) | b;
            bitCount += 8;
            while (bitCount >= 5 && index < chars.Length)
            {
                chars[index++] = alphabet[(bitBuffer >> (bitCount - 5)) & 31];
                bitCount -= 5;
            }
        }

        if (bitCount > 0 && index < chars.Length)
        {
            chars[index++] = alphabet[(bitBuffer << (5 - bitCount)) & 31];
        }

        return new string(chars, 0, index);
    }
}

/// <summary>Settings for hosting a code-share session.</summary>
public sealed record PinholeHostSettings
{
    /// <summary>Endpoints of <c>Pinhole.Rendezvous</c> introducers that provide the code
    /// directory. Supply these or <see cref="CoordinatorUrl"/>; there is no default
    /// coordination service.</summary>
    public IReadOnlyList<IPEndPoint> RendezvousEndpoints { get; init; } = [];

    /// <summary>HTTPS URL of a Pinhole Cloudflare coordinator. It supplies room
    /// pairing and expiring TURN credentials. HTTP is accepted only for loopback
    /// development. Short codes trust this coordinator to supply the peer's key.</summary>
    public Uri? CoordinatorUrl { get; init; }

    /// <summary>Options for the underlying node. Leave null for the transport defaults
    /// (STUN, relays, discovery). A coordinator supplies its own STUN/TURN defaults.
    /// Explicit empty <see cref="PinholeOptions.Relays"/> disables relay allocation.
    /// The host's connection string published
    /// under the code is whatever this node advertises.</summary>
    public PinholeOptions? NodeOptions { get; init; }

    /// <summary>How often the registration is refreshed so the directory's TTL cannot
    /// expire it. Default 40 s (the default directory TTL is 120 s). Set this to at most
    /// a third of your directory's TTL when running one with a shorter sweep.</summary>
    public TimeSpan RefreshInterval { get; init; } = TimeSpan.FromSeconds(40);
}

/// <summary>Settings for joining a code-share session.</summary>
public sealed record PinholeJoinSettings
{
    /// <summary>Endpoints of <c>Pinhole.Rendezvous</c> introducers that provide the code
    /// directory. Supply these or <see cref="CoordinatorUrl"/>.</summary>
    public IReadOnlyList<IPEndPoint> RendezvousEndpoints { get; init; } = [];

    /// <summary>HTTPS URL of the same Pinhole Cloudflare coordinator used by the
    /// host. HTTP is accepted only for loopback development.</summary>
    public Uri? CoordinatorUrl { get; init; }

    /// <summary>Node options for the dialer (defaults follow the transport).</summary>
    public PinholeOptions? NodeOptions { get; init; }

    /// <summary>How long to keep polling the directory for a code that has not been
    /// registered yet (host still starting, or datagram loss). Default 30 s. The
    /// underlying dial deadline remains <see cref="PinholeOptions.ConnectTimeout"/>.</summary>
    public TimeSpan WaitTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Interval between directory polls while waiting. Default 1 s.</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(1);
}

/// <summary>Entry points for the minimal host/join API (#45 M2). Names map to the
/// conceptual <c>Pinhole.HostAsync/JoinAsync</c> sketch; a static class avoids colliding
/// with the <c>Pinhole</c> namespace itself.</summary>
public static class PinholeSession
{
    /// <summary>Hosts a session: binds a node, claims a fresh invitation code in the
    /// directory, and keeps it alive until disposal. Callers read <see cref="PinholeHost.Code"/>,
    /// share it, and <see cref="PinholeHost.AcceptAsync"/> the joiner.</summary>
    public static async Task<PinholeHost> HostAsync(PinholeHostSettings settings, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (settings.RefreshInterval <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(settings));
        if (settings.CoordinatorUrl is not null)
            return await WorkerCoordinator.HostAsync(settings, ct).ConfigureAwait(false);
        var directory = new CodeDirectory(settings.RendezvousEndpoints);
        PinholeNode node = await PinholeNode.BindAsync(WithOptions(settings.NodeOptions), ct).ConfigureAwait(false);
        try
        {
            // A 45-bit random code colliding with a live claim is an astronomical event;
            // a fresh claim on retry still handles it (and any hostile squatting).
            for (int attempt = 0; ; attempt++)
            {
                string code = PinholeHost.NewCode();
                string? token = await directory.PutAsync(code, node.ConnectionString, ct).ConfigureAwait(false);
                if (token is not null)
                {
                    return new PinholeHost(node, directory, code, token, settings.RefreshInterval);
                }

                if (attempt >= 2)
                {
                    throw new InvalidOperationException("no rendezvous server acknowledged the invitation registration; check RendezvousEndpoints reachability");
                }
            }
        }
        catch
        {
            await node.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Joins a session by invitation code: resolves the host's connection
    /// string from the directory and dials it with the engine's pinned-key handshake.
    /// The returned connection is a regular <see cref="PinholeConnection"/>; dispose it
    /// (or the node beneath it) to close.</summary>
    public static async Task<PinholeConnection> JoinAsync(
        string code, PinholeJoinSettings settings, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(code);
        ArgumentNullException.ThrowIfNull(settings);
        if (settings.CoordinatorUrl is not null)
            return await WorkerCoordinator.JoinAsync(code, settings, ct).ConfigureAwait(false);
        var directory = new CodeDirectory(settings.RendezvousEndpoints);
        string? invitation = await directory.ResolveAsync(code, settings.WaitTimeout, settings.PollInterval, ct).ConfigureAwait(false);
        if (invitation is null)
        {
            throw new TimeoutException(
                $"invitation code was not found within {settings.WaitTimeout.TotalSeconds:F0}s. " +
                "Check the code, and confirm the host is running and can reach the directory.");
        }

        var node = await PinholeNode.BindAsync(WithOptions(settings.NodeOptions), ct).ConfigureAwait(false);
        try
        {
            PinholeConnection connection = await node.ConnectAsync(invitation, ct).ConfigureAwait(false);
            // The connection rides this node's engine: dispose the node when the session
            // ends so its sockets, relays, and timers retire with the connection. Disposing
            // the returned connection (or the peer closing it) is the documented exit.
            _ = connection.Closed.ContinueWith(
                async _ => await node.DisposeAsync().ConfigureAwait(false),
                TaskScheduler.Default);
            return connection;
        }
        catch
        {
            await node.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
    /// <summary>The minimal API promises pull-style receives out of the box, so a null
    /// NodeOptions gets a modest datagram buffer; explicit options are used verbatim
    /// (an app living on the Received event may prefer capacity zero).</summary>
    private static PinholeOptions? WithOptions(PinholeOptions? options) =>
        options ?? new PinholeOptions { ReceiveBufferCapacity = 256 };
}

/// <summary>Client half of the code-directory wire (PUTC/GETC/DELC). One short-lived
/// socket per operation, the same dual-mode and Windows-connreset handling as the
/// peer-ID lookup client.</summary>
internal sealed class CodeDirectory
{
    internal static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(40);
    private static readonly TimeSpan ReplyWait = TimeSpan.FromSeconds(2);
    private const int MaxCodeRecordLength = 8 * 1024; // keep UDP framing within the macOS datagram limit

    private readonly IPEndPoint[] _servers;

    public CodeDirectory(IReadOnlyList<IPEndPoint> servers)
    {
        if (servers.Count == 0)
        {
            throw new ArgumentException("at least one rendezvous endpoint is required", nameof(servers));
        }

        _servers = servers.ToArray();
    }

    /// <summary>Claims a code; returns the directory-issued token, or null when the
    /// code is already live.</summary>
    public async Task<string?> PutAsync(string code, string invitation, CancellationToken ct)
    {
        string message = $"PUTC {code} {EncodeInvitation(invitation)}";
        string? reply = await SendExpectAsync(message, "OKCG ", ["TokB"], ct).ConfigureAwait(false);
        return reply is not null && reply.StartsWith("OKCG ", StringComparison.Ordinal)
            ? reply["OKCG ".Length..]
            : null;
    }

    /// <summary>Outcome of a token-bearing refresh: confirmed, refused (the code belongs
    /// to another host now), or gone (the directory lost the code — restart or eviction —
    /// and the registration should reconcile by claiming again).</summary>
    public enum RefreshOutcome
    {
        Confirmed,
        Refused,
        NoCode,
        Failed,
    }

    public async Task<RefreshOutcome> RefreshAsync(string code, string token, string invitation, CancellationToken ct)
    {
        string? reply = await SendExpectAsync(
            $"PUTC {code} {EncodeInvitation(invitation)} {token}",
            "OKCG", ["TokB", "NOCODE"], ct).ConfigureAwait(false);
        return reply switch
        {
            null => RefreshOutcome.Failed,
            "TokB" => RefreshOutcome.Refused,
            "NOCODE" => RefreshOutcome.NoCode,
            _ => RefreshOutcome.Confirmed,
        };
    }

    private static string EncodeInvitation(string invitation)
    {
        string record = Base64Url.Encode(Encoding.UTF8.GetBytes(invitation));
        if (record.Length > MaxCodeRecordLength)
            throw new ArgumentException("invitation exceeds the UDP code-directory limit; share the full invitation or use an HTTPS coordinator", nameof(invitation));
        return record;
    }

    public Task DeleteAsync(string code, string token, CancellationToken ct = default) =>
        SendExpectAsync($"DELC {code} {token}", "OKCD", ["TokB", "NOCODE"], CancellationToken.None);

    /// <summary>Polls for a code until it appears or the deadline passes. Returns the
    /// decoded invitation, or null on timeout. A record that does not decode is treated
    /// as absence — the directory stores opaque bytes and never validates them.</summary>
    public async Task<string?> ResolveAsync(string code, TimeSpan deadline, TimeSpan pollInterval, CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < deadline)
        {
            string? record = await SendExpectAsync($"GETC {code}", "OKCC ", ["WAITC"], ct).ConfigureAwait(false) is { } reply
                && reply.StartsWith("OKCC ", StringComparison.Ordinal)
                ? reply["OKCC ".Length..]
                : null;
            if (record is not null)
            {
                try
                {
                    byte[] invitation = Base64Url.Decode(record);
                    if (invitation.Length is > 0 and <= ConnectionString.MaxEncodedLength)
                    {
                        return Encoding.UTF8.GetString(invitation);
                    }
                }
                catch (FormatException)
                {
                    // A lying directory cannot be argued with; treat as absence.
                }
            }

            await Task.Delay(pollInterval, ct).ConfigureAwait(false);
        }

        return null;
    }

    /// <summary>Sends one request to every configured server and returns the first
    /// accepted reply line — a success (starts with <paramref name="want"/>) or a named
    /// refusal (exactly a terminator). Null means timeout. Replies from endpoints that are
    /// not configured servers are dropped: an off-path sprayer that guesses the ephemeral
    /// port must not be able to inject an OKCC/OKCG verdict. (A request-id echo that also
    /// defeats source spoofing needs a wire-version bump; tracked with handshake v4.)</summary>
    private async Task<string?> SendExpectAsync(string message, string want, string[] terminators, CancellationToken ct)
    {
        using Socket udp = NewSocket();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(ReplyWait);
        foreach (IPEndPoint server in _servers)
        {
            await udp.SendToAsync(Encoding.ASCII.GetBytes(message), SocketFlags.None, ToWire(server), deadline.Token).ConfigureAwait(false);
        }

        byte[] buffer = new byte[(ConnectionString.MaxEncodedLength * 4 + 2) / 3 + 128];
        IPEndPoint any = new(IPAddress.IPv6Any, 0);
        while (!deadline.IsCancellationRequested)
        {
            SocketReceiveFromResult res;
            try
            {
                res = await udp.ReceiveFromAsync(buffer, SocketFlags.None, any, deadline.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return null;
            }
            catch (SocketException)
            {
                continue; // one dead server is not a verdict on the others
            }

            if (res.RemoteEndPoint is not IPEndPoint from || !IsConfiguredServer(from))
            {
                continue;
            }

            string reply = Encoding.ASCII.GetString(buffer, 0, res.ReceivedBytes).Trim();
            if (reply.StartsWith(want, StringComparison.Ordinal))
            {
                return reply;
            }

            foreach (string terminator in terminators)
            {
                if (reply == terminator)
                {
                    return reply;
                }
            }
        }

        return null;
    }

    private bool IsConfiguredServer(IPEndPoint from)
    {
        foreach (IPEndPoint server in _servers)
        {
            IPEndPoint wire = ToWire(server);
            if (wire.Port == from.Port && wire.Address.Equals(from.Address))
            {
                return true;
            }
        }

        return false;
    }

    private static Socket NewSocket()
    {
        var udp = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp) { DualMode = true };
        if (OperatingSystem.IsWindows())
        {
            const int sioUdpConnreset = -1744830452;
            udp.IOControl(sioUdpConnreset, new byte[] { 0 }, null);
        }

        udp.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
        return udp;
    }

    private static IPEndPoint ToWire(IPEndPoint ep)
    {
        if (ep.Address.AddressFamily == AddressFamily.InterNetwork || ep.Address.Equals(IPAddress.IPv6Any))
        {
            IPAddress mapped = ep.Address.Equals(IPAddress.IPv6Any) ? IPAddress.IPv6Loopback : ep.Address.MapToIPv6();
            ep = new IPEndPoint(mapped, ep.Port);
        }

        return ep;
    }
}
