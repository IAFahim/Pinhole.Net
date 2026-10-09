using System.Net;
using System.Net.Sockets;

namespace Pinhole;

/// <summary>A router-granted lease, including the current granted lifetime.</summary>
internal interface IPortMapLease : IDisposable
{
    IPEndPoint External { get; }
    TimeSpan Lifetime { get; }
    Task<bool> RenewAsync(CancellationToken ct);
    Task ReleaseAsync(CancellationToken ct);
}

/// <summary>One serialized, best-effort router-mapping worker. Stale discovery results
/// never become candidates, expired leases are withdrawn, and an old mapping is released
/// before its replacement is requested. UDP and TCP use independent instances.</summary>
internal sealed class PortMappingService : IDisposable
{
    private static readonly TimeSpan RetryDiscoveryAfter = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan FirstPassRetryAfter = TimeSpan.FromSeconds(4);
    private const int MaxDiscoveryPasses = 3;
    private readonly PinholeOptions _options;
    private readonly ProtocolType _protocol;
    private readonly Action<IPEndPoint?> _publish;
    private readonly Func<int, CancellationToken, Task<IPortMapLease?>> _discover;
    private readonly object _gate = new();
    private readonly SemaphoreSlim _wake = new(0, 1);
    private readonly Queue<IPortMapLease> _retiring = new();
    private readonly Queue<(long Generation, IPEndPoint? Endpoint)> _notifications = new();
    private readonly Task _worker;
    private Task? _publisher;
    private bool _publishing;
    private CancellationTokenSource? _operationStop;
    private IPortMapLease? _lease;
    private int _internalPort;
    private long _generation;
    private long _nextActionTicks = long.MaxValue;
    private long _expiresTicks;
    private bool _everMapped;
    private bool _disposed;
    private int _passes;

    public PortMappingService(PinholeOptions options, Action<IPEndPoint?> publish,
        ProtocolType protocol = ProtocolType.Udp,
        Func<int, CancellationToken, Task<IPortMapLease?>>? discover = null)
    {
        if (protocol is not (ProtocolType.Udp or ProtocolType.Tcp)) throw new ArgumentOutOfRangeException(nameof(protocol));
        _options = options;
        _publish = publish;
        _protocol = protocol;
        _discover = discover ?? DiscoverAsync;
        _worker = Task.Run(WorkerAsync);
    }

    internal async Task CompletedAsync()
    {
        await _worker.ConfigureAwait(false);
        Task? publisher;
        lock (_gate) publisher = _publisher;
        if (publisher is not null) await publisher.ConfigureAwait(false);
    }
    internal Task Completed => CompletedAsync();

    public IPEndPoint? Current
    {
        get
        {
            lock (_gate)
            {
                ExpireNoLock(Environment.TickCount64);
                return _lease?.External;
            }
        }
    }

    public void Ensure(int internalPort)
    {
        if (internalPort is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(internalPort));
        lock (_gate)
        {
            if (_disposed) return;
            if (_internalPort != 0 && _internalPort != internalPort) RebindNoLock(internalPort);
            else if (_internalPort == 0) { _internalPort = internalPort; _nextActionTicks = 0; }
            Signal();
        }
    }

    public void Rebind(int newInternalPort)
    {
        if (newInternalPort is < 0 or > 65535) throw new ArgumentOutOfRangeException(nameof(newInternalPort));
        lock (_gate)
        {
            if (_disposed) return;
            RebindNoLock(newInternalPort); // even the same port may now name another network
            Signal();
        }
    }

    private void RebindNoLock(int port)
    {
        _generation++;
        _internalPort = port;
        _passes = 0;
        _operationStop?.Cancel();
        RetireNoLock();
        _nextActionTicks = port == 0 ? long.MaxValue : 0;
    }

    /// <summary>The engine's maintenance tick also withdraws a lease while a renewal
    /// is still pending. The worker keeps its own deadlines when maintenance is disabled.</summary>
    public void Tick(long nowTicks)
    {
        lock (_gate)
        {
            if (_disposed) return;
            ExpireNoLock(nowTicks);
            Signal();
        }
    }

    private void ExpireNoLock(long now)
    {
        if (_lease is null || now < _expiresTicks) return;
        _operationStop?.Cancel();
        RetireNoLock();
        _nextActionTicks = now + (long)RetryDiscoveryAfter.TotalMilliseconds;
        Signal();
    }

    private void RetireNoLock()
    {
        if (_lease is not { } old) return;
        _lease = null;
        _retiring.Enqueue(old);
        NotifyNoLock(null);
    }

    private void Signal()
    {
        try { _wake.Release(); }
        catch (Exception ex) when (ex is SemaphoreFullException or ObjectDisposedException) { }
    }

    private async Task WorkerAsync()
    {
        try
        {
            while (true)
            {
                IPortMapLease? retired, live;
                long generation;
                int port, delay;
                CancellationTokenSource? operation;
                lock (_gate)
                {
                    ExpireNoLock(Environment.TickCount64);
                    retired = _retiring.Count == 0 ? null : _retiring.Dequeue();
                    if (_disposed && retired is null) return;
                    live = _lease;
                    generation = _generation;
                    port = _internalPort;
                    long now = Environment.TickCount64;
                    delay = _nextActionTicks == long.MaxValue ? Timeout.Infinite
                        : (int)Math.Clamp(_nextActionTicks - now, 0, int.MaxValue);
                    operation = retired is null && delay == 0 && port != 0 && !_disposed
                        ? new CancellationTokenSource() : null;
                    if (operation is not null)
                    {
                        _operationStop = operation;
                        operation.CancelAfter(live is null ? TimeSpan.FromSeconds(8)
                            : TimeSpan.FromMilliseconds(Math.Max(1, Math.Min(2_000, _expiresTicks - now))));
                        if (live is null) _passes++;
                    }
                }

                if (retired is not null)
                {
                    await ReleaseQuietlyAsync(retired).ConfigureAwait(false);
                    continue;
                }
                if (operation is null)
                {
                    await _wake.WaitAsync(delay).ConfigureAwait(false);
                    continue;
                }

                IPortMapLease? discovered = null;
                bool renewed = false;
                try
                {
                    if (live is null) discovered = await _discover(port, operation.Token).ConfigureAwait(false);
                    else renewed = await live.RenewAsync(operation.Token).ConfigureAwait(false);
                }
                catch (Exception) { } // an unsupported/refused router never fails the node
                finally
                {
                    lock (_gate) if (ReferenceEquals(_operationStop, operation)) _operationStop = null;
                    operation.Dispose();
                }

                bool releaseDiscovered = false;
                lock (_gate)
                {
                    if (_disposed || generation != _generation)
                    {
                        releaseDiscovered = discovered is not null;
                        // Rebind/Shutdown already queued the old live lease for release.
                    }
                    else if (live is not null)
                    {
                        if (ReferenceEquals(_lease, live))
                        {
                            if (renewed && live.Lifetime > TimeSpan.Zero) ScheduleLeaseNoLock(live);
                            else
                            {
                                RetireNoLock();
                                _nextActionTicks = Environment.TickCount64 + (long)RetryDiscoveryAfter.TotalMilliseconds;
                            }
                        }
                    }
                    else if (discovered is { Lifetime: var lifetime } && lifetime > TimeSpan.Zero)
                    {
                        _lease = discovered;
                        _everMapped = true;
                        ScheduleLeaseNoLock(discovered);
                        NotifyNoLock(discovered.External);
                    }
                    else
                    {
                        releaseDiscovered = discovered is not null;
                        _nextActionTicks = _everMapped
                            ? Environment.TickCount64 + (long)RetryDiscoveryAfter.TotalMilliseconds
                            : _passes < MaxDiscoveryPasses
                                ? Environment.TickCount64 + (long)FirstPassRetryAfter.TotalMilliseconds
                                : long.MaxValue;
                    }
                }
                if (releaseDiscovered) await ReleaseQuietlyAsync(discovered!).ConfigureAwait(false);
            }
        }
        finally { _wake.Dispose(); }
    }

    private void ScheduleLeaseNoLock(IPortMapLease lease)
    {
        long now = Environment.TickCount64;
        long duration = Math.Max(1, (long)Math.Min(uint.MaxValue * 1000d, lease.Lifetime.TotalMilliseconds));
        _expiresTicks = now + duration;
        _nextActionTicks = now + Math.Max(1, duration / 2);
    }

    private void NotifyNoLock(IPEndPoint? endpoint)
    {
        // A callback can enter node/session locks or dispose its owner. Never run it
        // under the lease lock. One publisher preserves order with a bounded backlog;
        // obsolete queued generations are discarded before invocation.
        if (_notifications.Count == 16) _notifications.Dequeue();
        _notifications.Enqueue((_generation, endpoint));
        if (_publishing) return;
        _publishing = true;
        _publisher = Task.Run(PublishNotifications);
    }

    private void PublishNotifications()
    {
        while (true)
        {
            IPEndPoint? endpoint;
            lock (_gate)
            {
                if (_notifications.Count == 0) { _publishing = false; return; }
                (long generation, IPEndPoint? next) = _notifications.Dequeue();
                if (generation != _generation) continue;
                endpoint = next;
            }
            try { _publish(endpoint); } catch (Exception) { }
        }
    }

    private async Task<IPortMapLease?> DiscoverAsync(int port, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        IPortMapLease? lease = await PcpClient.TryMapAsync(_options.GatewayOverride, port,
            _options.PortMappingLease, ct, _protocol).ConfigureAwait(false);
        if (lease is not null) return lease;
        ct.ThrowIfCancellationRequested();
        lease = await NatPmpClient.TryMapAsync(_options.GatewayOverride, port,
            _options.PortMappingLease, ct, _protocol).ConfigureAwait(false);
        if (lease is not null) return lease;
        ct.ThrowIfCancellationRequested();
        using var upnp = new UpnpIgdClient();
        return await upnp.TryMapAsync(port, _options.PortMappingLease, _options.SsdpUnicastOverride,
            ct, _protocol).ConfigureAwait(false);
    }

    public void Shutdown()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _generation++;
            _operationStop?.Cancel();
            RetireNoLock();
            _nextActionTicks = long.MaxValue;
            Signal();
        }
    }

    private static async Task ReleaseQuietlyAsync(IPortMapLease lease)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
            await lease.ReleaseAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (Exception) { }
        finally { lease.Dispose(); }
    }

    public void Dispose() => Shutdown();
}
