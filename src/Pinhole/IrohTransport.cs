using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace Pinhole;

public sealed class IrohTransportOptions
{
    public PinholeOptions Network { get; init; } = new();
    public byte[]? SecretKeySeed { get; init; }
    public Uri DiscoveryUrl { get; init; } = new("https://dns.iroh.link/pkarr");
    public bool PublishAddress { get; init; } = true;
    public bool PublishDirectAddresses { get; init; } = true;
    public int ReceiveBufferCapacity { get; init; } = 256;
    internal HttpMessageHandler? DiscoveryHandler { get; init; }
}

public sealed class IrohPath
{
    private readonly IPEndPoint? _direct;
    internal byte[]? Key { get; }
    private IrohPath(IPEndPoint? direct, Uri? relay, byte[]? key)
    {
        _direct = direct;
        RelayUrl = relay;
        Key = key;
        EndpointId = key is null ? null : Convert.ToHexString(key).ToLowerInvariant();
    }
    public IPEndPoint? DirectAddress => _direct is null ? null : CloneEndpoint(_direct);
    public Uri? RelayUrl { get; }
    public string? EndpointId { get; }
    public static IrohPath Direct(IPEndPoint address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.Port == 0) throw new ArgumentException("a direct path needs a nonzero UDP port", nameof(address));
        IPAddress ip = address.Address.IsIPv4MappedToIPv6 ? address.Address.MapToIPv4() : address.Address;
        return new IrohPath(CloneEndpoint(new IPEndPoint(ip, address.Port)), null, null);
    }
    public static IrohPath Relay(Uri url, string endpointId) =>
        new(null, IrohAddress.ValidateRelay(url), IrohEncoding.ParseKey(endpointId));

    private static IPEndPoint CloneEndpoint(IPEndPoint endpoint) => new(
        endpoint.AddressFamily == AddressFamily.InterNetworkV6
            ? new IPAddress(endpoint.Address.GetAddressBytes(), endpoint.Address.ScopeId)
            : new IPAddress(endpoint.Address.GetAddressBytes()), endpoint.Port);
}

public sealed class IrohDatagram
{
    internal IrohDatagram(IrohPath path, byte[] payload) { Path = path; Payload = payload; }
    public IrohPath Path { get; }
    public ReadOnlyMemory<byte> Payload { get; }
}

public sealed class IrohRoute
{
    private readonly IrohTransport _transport;
    private IrohPath? _selected;
    internal IrohRoute(IrohTransport transport, IrohAddress address)
    {
        _transport = transport;
        Address = address;
        Paths = Array.AsReadOnly(address.RelayUrls.Select(x => IrohPath.Relay(x, address.EndpointId))
            .Concat(address.DirectAddresses.Select(IrohPath.Direct)).ToArray());
    }
    public IrohAddress Address { get; }
    public IReadOnlyList<IrohPath> Paths { get; }
    public IrohPath? SelectedPath => Volatile.Read(ref _selected);

    public void Send(ReadOnlySpan<byte> payload)
    {
        if (SelectedPath is { } path) { _transport.SendTo(path, payload); return; }
        bool sent = false;
        Exception? failure = null;
        foreach (IrohPath candidate in Paths)
        {
            if (candidate.RelayUrl is not null && (payload.IsEmpty || payload.Length > IrohRelay.MaxDatagramSize)) continue;
            try { _transport.SendTo(candidate, payload); sent = true; }
            catch (Exception ex) when (ex is IOException or SocketException) { failure = ex; }
        }
        if (!sent) throw new IOException("no usable iroh path", failure);
    }

    public void SelectPath(IrohPath? path)
    {
        if (path?.RelayUrl is not null && path.EndpointId != Address.EndpointId)
            throw new ArgumentException("the relay path belongs to a different endpoint", nameof(path));
        Volatile.Write(ref _selected, path);
    }
}

public sealed class IrohTransport : IAsyncDisposable, IDisposable
{
    private readonly NodeEngine _engine;
    private readonly RelayIdentity _identity;
    private readonly IrohTransportOptions _options;
    private readonly HttpClient _http;
    private readonly IrohDiscovery _discovery;
    private readonly Channel<IrohDatagram> _received;
    private readonly CancellationTokenSource _stop = new();
    private Task? _publisher;
    private int _disposed;

    private IrohTransport(IrohTransportOptions options, PinholeOptions network)
    {
        _options = options;
        _identity = new RelayIdentity(options.SecretKeySeed);
        _received = Channel.CreateBounded<IrohDatagram>(new BoundedChannelOptions(options.ReceiveBufferCapacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            AllowSynchronousContinuations = false,
        });
        _http = options.DiscoveryHandler is { } handler ? new HttpClient(handler, disposeHandler: false) : new HttpClient();
        _http.Timeout = TimeSpan.FromSeconds(5);
        _discovery = new IrohDiscovery(_http, options.DiscoveryUrl);
        _engine = new NodeEngine(network, _identity, OnDatagram);
    }

    public static async Task<IrohTransport> BindAsync(IrohTransportOptions? options = null, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        options ??= new();
        ArgumentNullException.ThrowIfNull(options.Network);
        if (options.SecretKeySeed is { Length: not 32 }) throw new ArgumentException("an iroh secret seed must have 32 bytes", nameof(options));
        ArgumentOutOfRangeException.ThrowIfLessThan(options.ReceiveBufferCapacity, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(options.ReceiveBufferCapacity, 65536);
        IrohAddress.ValidateRelay(options.DiscoveryUrl);
        PinholeOptions network = await PinholeOptions.ResolveAsync(options.Network with
        {
            IdentityKeySeed = null, Encryption = PinholeEncryption.Disabled, Listen = false,
            Relays = [], ResolvedRelays = [], DerpRelayUrls = [], ResolvedDerpRelays = [], LookupProviders = [], RendezvousEndpoints = [],
            EnableLanDiscovery = false, EnablePathValidation = false, EnablePmtud = false,
            KeepaliveInterval = TimeSpan.Zero, ReceiveBufferCapacity = 0,
            PublishIrohAddress = false,
        }, ct).ConfigureAwait(false);
        var transport = new IrohTransport(options, network);
        try
        {
            await transport._engine.BindAsync(ct).ConfigureAwait(false);
            if (options.PublishAddress)
            {
                try { await transport.PublishAddressAsync(ct).ConfigureAwait(false); }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
                catch (Exception ex) when (ex is HttpRequestException or IOException) { }
                transport._publisher = transport.PublishLoopAsync();
            }
            return transport;
        }
        catch { transport.Dispose(); throw; }
    }

    public string EndpointId => Convert.ToHexString(_identity.PublicKey).ToLowerInvariant();
    public IrohAddress Address
    {
        get
        {
            ThrowIfDisposed();
            IReadOnlyList<PinholeCandidate> candidates = _engine.LocalCandidatesSnapshot();
            return new IrohAddress(EndpointId,
                candidates.Where(x => x.Kind is CandidateKind.Direct or CandidateKind.Reflexive).Select(x => x.Address).ToArray(),
                candidates.Where(x => x.Kind == CandidateKind.IrohRelay).Select(x => x.RelayUrl!).ToArray());
        }
    }
    public int LocalPort => _engine.LocalPort;
    public bool HasRelay => _engine.HasRelay;

    public async Task<IrohAddress> ResolveAsync(string ticketOrEndpointId, CancellationToken ct = default)
    {
        ThrowIfDisposed();
        ct.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, _stop.Token);
        deadline.CancelAfter(_options.Network.ConnectTimeout);
        IrohAddress address = IrohAddress.Parse(ticketOrEndpointId);
        if (address.DirectAddresses.Count + address.RelayUrls.Count > 0) return address;
        return await _discovery.ResolveAsync(address.EndpointId, deadline.Token).ConfigureAwait(false);
    }

    public async Task<IrohRoute> ConnectAsync(string ticketOrEndpointId, CancellationToken ct = default)
    {
        ThrowIfDisposed();
        ct.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, _stop.Token);
        deadline.CancelAfter(_options.Network.ConnectTimeout);
        IrohAddress address = await ResolveAsync(ticketOrEndpointId, deadline.Token).ConfigureAwait(false);
        if (address.EndpointId == EndpointId) throw new ArgumentException("cannot dial this transport's own endpoint ID", nameof(ticketOrEndpointId));
        if (address.DirectAddresses.Count + address.RelayUrls.Count == 0) throw new IOException("iroh discovery returned no IP or relay paths");
        List<Task> attempts = address.RelayUrls.Select(x => _engine.PrepareRawRelayAsync(x, deadline.Token)).ToList();
        if (address.DirectAddresses.Count > 0)
        {
            deadline.Cancel(); // relay loops keep running; candidate-preparation waiters do not
            foreach (Task attempt in attempts) _ = ObserveRelayAsync(attempt);
        }
        else
        {
            Exception? failure = null;
            bool ready = false;
            while (attempts.Count > 0)
            {
                Task attempt = await Task.WhenAny(attempts).ConfigureAwait(false);
                attempts.Remove(attempt);
                try { await attempt.ConfigureAwait(false); ready = true; break; }
                catch (OperationCanceledException) { deadline.Token.ThrowIfCancellationRequested(); }
                catch (Exception ex) when (ex is IOException or InvalidOperationException) { failure = ex; }
            }
            deadline.Cancel();
            foreach (Task attempt in attempts) _ = ObserveRelayAsync(attempt);
            if (!ready) throw new IOException("no iroh relay could be reached", failure);
        }
        return new IrohRoute(this, address);
    }

    private static async Task ObserveRelayAsync(Task task)
    {
        try { await task.ConfigureAwait(false); }
        catch (Exception ex) when (ex is OperationCanceledException or IOException or InvalidOperationException) { }
    }

    public void SendTo(IrohPath path, ReadOnlySpan<byte> payload)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(path);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(payload.Length, path.RelayUrl is null ? 65507 : IrohRelay.MaxDatagramSize);
        if (path.RelayUrl is not null && payload.IsEmpty)
            throw new ArgumentException("native iroh relays require a nonempty datagram", nameof(payload));
        _engine.SendRaw(path, payload);
    }

    public async ValueTask<IrohDatagram> ReceiveAsync(CancellationToken ct = default)
    {
        ThrowIfDisposed();
        try { return await _received.Reader.ReadAsync(ct).ConfigureAwait(false); }
        catch (ChannelClosedException) { throw new ObjectDisposedException(nameof(IrohTransport)); }
    }

    private void OnDatagram(IrohPath path, ReadOnlyMemory<byte> payload) =>
        _received.Writer.TryWrite(new IrohDatagram(path, payload.ToArray()));

    public Task PublishAddressAsync(CancellationToken ct = default)
    {
        ThrowIfDisposed();
        IrohAddress full = Address;
        var published = new IrohAddress(EndpointId,
            _options.PublishDirectAddresses ? full.DirectAddresses : [], full.RelayUrls);
        return _discovery.PublishAsync(published, _identity, ct);
    }

    private async Task PublishLoopAsync()
    {
        int failures = 0;
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                double jitter = System.Security.Cryptography.RandomNumberGenerator.GetInt32(900, 1101) / 1000.0;
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(30L << Math.Min(failures, 4), 300) * jitter), _stop.Token).ConfigureAwait(false);
                await PublishAddressAsync(_stop.Token).ConfigureAwait(false);
                failures = 0;
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { return; }
            catch (ObjectDisposedException) when (_stop.IsCancellationRequested) { return; }
            catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException) { failures++; }
        }
    }

    public Task RoamNowAsync(CancellationToken ct = default)
    {
        ThrowIfDisposed();
        return _engine.RecoverAsync(forceRebind: false, ct);
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _stop.Cancel();
        _engine.Dispose();
        _received.Writer.TryComplete();
        _http.Dispose();
    }
    public async ValueTask DisposeAsync()
    {
        Dispose();
        if (_publisher is { } publisher) await publisher.ConfigureAwait(false);
    }
}
