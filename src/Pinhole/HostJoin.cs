using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Pinhole;

public sealed class PinholeHost : IAsyncDisposable
{
    public string Code { get; }

    public string FullInvitation => _node.ConnectionString;

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
        ConfirmationCode = FormatConfirmation(ConfirmationFingerprint(node.PeerId, node.StaticPublicKey, node.EndpointPublicKey));
        _keepalive = KeepaliveAsync();
    }

    internal PinholeHost(PinholeNode node, WorkerCoordinator worker, TimeSpan refreshInterval)
    {
        _node = node;
        _worker = worker;
        _token = string.Empty;
        Code = worker.Code;
        _refreshInterval = refreshInterval;
        ConfirmationCode = FormatConfirmation(ConfirmationFingerprint(node.PeerId, node.StaticPublicKey, node.EndpointPublicKey));
        _workerConnection = worker.ConnectHostAsync(node, _shutdown.Token);
        _keepalive = KeepaliveAsync();
    }

    public Task<PinholeConnection> AcceptAsync(CancellationToken ct = default) =>
        _workerConnection is { } paired ? paired.WaitAsync(ct) : _node.AcceptAsync(ct);

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

    internal static string ConfirmationFingerprint(ulong peerId, byte[]? staticKey, byte[]? endpointKey)
    {
        Span<byte> hash = stackalloc byte[32];
        var payload = new MemoryStream(24 + (staticKey?.Length ?? 0) + (endpointKey?.Length ?? 0));
        payload.Write(Encoding.ASCII.GetBytes("pinhole-confirmation-v1"));
        payload.WriteByte((byte)((staticKey is null ? 0 : 1) | (endpointKey is null ? 0 : 2)));
        Span<byte> tmp = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(tmp, peerId);
        payload.Write(tmp);
        if (staticKey is not null) payload.Write(staticKey);
        if (endpointKey is not null) payload.Write(endpointKey);
        SHA256.HashData(payload.GetBuffer().AsSpan(0, (int)payload.Length), hash);
        return FormatBase32(hash[..10]);
    }

    internal static string FormatConfirmation(string raw) => $"{raw[..4]}-{raw[4..8]}-{raw[8..12]}-{raw[12..16]}";

    internal static string NewCode()
    {

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

public sealed record PinholeHostSettings
{
    public IReadOnlyList<IPEndPoint> RendezvousEndpoints { get; init; } = [];

    public Uri? CoordinatorUrl { get; init; }

    public PinholeOptions? NodeOptions { get; init; }

    public TimeSpan RefreshInterval { get; init; } = TimeSpan.FromSeconds(40);
}

public sealed record PinholeJoinSettings
{
    public IReadOnlyList<IPEndPoint> RendezvousEndpoints { get; init; } = [];

    public Uri? CoordinatorUrl { get; init; }

    public PinholeOptions? NodeOptions { get; init; }

    public TimeSpan WaitTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(1);
}

public static class PinholeSession
{
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
    private static PinholeOptions? WithOptions(PinholeOptions? options) =>
        options ?? new PinholeOptions { ReceiveBufferCapacity = 256 };
}

internal sealed class CodeDirectory
{
    internal static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(40);
    private static readonly TimeSpan ReplyWait = TimeSpan.FromSeconds(2);
    private const int MaxCodeRecordLength = 8 * 1024;

    private readonly IPEndPoint[] _servers;

    public CodeDirectory(IReadOnlyList<IPEndPoint> servers)
    {
        if (servers.Count == 0)
        {
            throw new ArgumentException("at least one rendezvous endpoint is required", nameof(servers));
        }

        _servers = servers.ToArray();
    }

    public async Task<string?> PutAsync(string code, string invitation, CancellationToken ct)
    {
        string message = $"PUTC {code} {EncodeInvitation(invitation)}";
        string? reply = await SendExpectAsync(message, "OKCG ", ["TokB"], ct).ConfigureAwait(false);
        return reply is not null && reply.StartsWith("OKCG ", StringComparison.Ordinal)
            ? reply["OKCG ".Length..]
            : null;
    }

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

    public async Task<string?> ResolveAsync(string code, TimeSpan deadline, TimeSpan pollInterval, CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < deadline)
        {
            string? record = await SendExpectAsync(
                $"GETC {code}", "OKCC ", ["WAITC"], ct,
                reply => AnswerGetcChallenge(code, reply)).ConfigureAwait(false) is { } reply
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

                }
            }

            await Task.Delay(pollInterval, ct).ConfigureAwait(false);
        }

        return null;
    }

    private static string? AnswerGetcChallenge(string code, string reply)
    {
        string[] parts = reply.Split(' ');
        return parts.Length == 3 && parts[1] == code ? $"GETC {parts[1]} {parts[2]}" : null;
    }

    private async Task<string?> SendExpectAsync(string message, string want, string[] terminators, CancellationToken ct,
        Func<string, string?>? answerChallenge = null)
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
                continue;
            }

            if (res.RemoteEndPoint is not IPEndPoint from || !IsConfiguredServer(from))
            {
                continue;
            }

            string reply = Encoding.ASCII.GetString(buffer, 0, res.ReceivedBytes).Trim();
            if (answerChallenge is not null && reply.StartsWith("CHAL ", StringComparison.Ordinal))
            {

                if (answerChallenge(reply) is { } retry)
                {
                    await udp.SendToAsync(Encoding.ASCII.GetBytes(retry), SocketFlags.None, from, deadline.Token).ConfigureAwait(false);
                }

                continue;
            }

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
