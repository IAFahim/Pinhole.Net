using System.Net;

namespace Pinhole;

/// <summary>A live router port mapping, protocol-agnostic: the external endpoint to
/// advertise, the granted lifetime, and how to renew or release it.</summary>
internal interface IPortMapLease : IDisposable
{
    IPEndPoint External { get; }

    TimeSpan Lifetime { get; }

    Task<bool> RenewAsync(CancellationToken ct);

    Task ReleaseAsync(CancellationToken ct);
}

/// <summary>Runs the router port-mapping strategy iroh runs (UPnP / NAT-PMP / PCP): ask
/// the network's gateway for an explicit UDP mapping to our socket so hard NATs become
/// punchable and the mapped endpoint can be advertised as a candidate. Entirely
/// best-effort and entirely background — discovery never delays a bind, and a network
/// without any mapping support simply contributes nothing.</summary>
internal sealed class PortMappingService : IDisposable
{
    private static readonly TimeSpan RetryDiscoveryAfter = TimeSpan.FromSeconds(60);

    private readonly PinholeOptions _options;
    private readonly Action<IPEndPoint?> _publish;
    private readonly object _gate = new();
    private IPortMapLease? _lease;
    private int _internalPort;
    private long _nextActionTicks = long.MaxValue; // 0 = an action (renew) is in flight
    private bool _everMapped;
    private int _discovering;

    public PortMappingService(PinholeOptions options, Action<IPEndPoint?> publish)
    {
        _options = options;
        _publish = publish;
    }

    /// <summary>The mapped external endpoint, or null when no mapping is currently live.</summary>
    public IPEndPoint? Current
    {
        get
        {
            lock (_gate)
            {
                return _lease?.External;
            }
        }
    }

    /// <summary>Discovers a mapping for <paramref name="internalPort"/> if none is live.
    /// Cheap UDP protocols first (PCP, then NAT-PMP), then UPnP's slower SSDP+SOAP walk.
    /// Single-flight: a pass already in progress swallows later requests.</summary>
    public void Ensure(int internalPort)
    {
        if (Interlocked.CompareExchange(ref _discovering, 1, 0) != 0)
        {
            return;
        }

        lock (_gate)
        {
            if (_lease is not null)
            {
                Volatile.Write(ref _discovering, 0);
                return;
            }

            _internalPort = internalPort;
        }

        _ = Task.Run(() => DiscoverAsync(internalPort));
    }

    private async Task DiscoverAsync(int internalPort)
    {
        IPortMapLease? lease = null;
        try
        {
            lease = await PcpClient.TryMapAsync(_options.GatewayOverride, internalPort, _options.PortMappingLease, CancellationToken.None).ConfigureAwait(false)
                ?? (IPortMapLease?)await NatPmpClient.TryMapAsync(_options.GatewayOverride, internalPort, _options.PortMappingLease, CancellationToken.None).ConfigureAwait(false);
            if (lease is null)
            {
                using var upnp = new UpnpIgdClient();
                lease = await upnp.TryMapAsync(internalPort, _options.PortMappingLease, _options.SsdpUnicastOverride, CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch
        {
            // A mapping strategy must never surface as a connection error.
        }
        finally
        {
            IPortMapLease? publish = lease;
            int rekick = 0;
            lock (_gate)
            {
                if (lease is not null && _internalPort != internalPort)
                {
                    // The socket moved while we were negotiating: this mapping targets a
                    // dead port, and one for the current port is still wanted.
                    _ = ReleaseQuietlyAsync(lease);
                    publish = null;
                }

                if (_internalPort != internalPort && _lease is null)
                {
                    rekick = _internalPort; // Rebind's Ensure was swallowed by this very pass
                }
            }

            Volatile.Write(ref _discovering, 0);
            PublishAndSchedule(publish);
            if (rekick != 0)
            {
                Ensure(rekick);
            }
        }
    }

    /// <summary>Releases the current mapping (network changed, local port changed) and
    /// starts discovery for the new port.</summary>
    public void Rebind(int newInternalPort)
    {
        IPortMapLease? old;
        lock (_gate)
        {
            old = _lease;
            _lease = null;
            _internalPort = newInternalPort;
        }

        if (old is not null)
        {
            _ = ReleaseQuietlyAsync(old);
            _publish(null);
        }

        Ensure(newInternalPort);
    }

    /// <summary>Maintenance tick: renews a live mapping at half its granted lifetime, and
    /// retries discovery once a minute after a previously-good mapping was lost.</summary>
    public void Tick(long nowTicks)
    {
        IPortMapLease? lease = null;
        int rediscoverPort = 0;
        lock (_gate)
        {
            if (_nextActionTicks == 0 || nowTicks < _nextActionTicks)
            {
                return;
            }

            if (_lease is { } live)
            {
                _nextActionTicks = 0; // busy until the renewal lands
                lease = live;
            }
            else if (_everMapped)
            {
                _nextActionTicks = long.MaxValue; // due at most once: rediscovery sets its own schedule
                rediscoverPort = _internalPort;
            }
        }

        if (lease is not null)
        {
            _ = RenewAsync(lease);
        }
        else if (rediscoverPort != 0)
        {
            Ensure(rediscoverPort);
        }
    }

    private async Task RenewAsync(IPortMapLease lease)
    {
        bool ok = false;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            ok = await lease.RenewAsync(timeout.Token).ConfigureAwait(false);
        }
        catch
        {
        }

        if (ok)
        {
            lock (_gate)
            {
                if (ReferenceEquals(_lease, lease))
                {
                    _nextActionTicks = Environment.TickCount64 + (long)lease.Lifetime.TotalMilliseconds / 2;
                }
            }

            return; // publish unchanged: the external endpoint is the same mapping
        }

        // The mapping died (router rebooted, lease expired elsewhere): stop advertising it
        // and retry the whole discovery soon rather than at the old lease's pace.
        lock (_gate)
        {
            if (ReferenceEquals(_lease, lease))
            {
                _lease = null;
                _nextActionTicks = Environment.TickCount64 + (long)RetryDiscoveryAfter.TotalMilliseconds;
            }
        }

        _ = ReleaseQuietlyAsync(lease);
        _publish(null);
    }

    private void PublishAndSchedule(IPortMapLease? lease)
    {
        lock (_gate)
        {
            _lease = lease;
            if (lease is not null)
            {
                _everMapped = true;
                _nextActionTicks = Environment.TickCount64 + (long)lease.Lifetime.TotalMilliseconds / 2;
            }
            else
            {
                // Nothing mapped. Retry only if a mapping ever worked here — a network that
                // never spoke UPnP/PMP/PCP must not be probed every minute forever.
                _nextActionTicks = _everMapped
                    ? Environment.TickCount64 + (long)RetryDiscoveryAfter.TotalMilliseconds
                    : long.MaxValue;
            }
        }

        _publish(lease?.External);
    }

    /// <summary>Best-effort release on shutdown; bounded by its own token so node disposal
    /// is never held hostage by a slow router.</summary>
    public void Shutdown()
    {
        IPortMapLease? lease;
        lock (_gate)
        {
            lease = _lease;
            _lease = null;
            _nextActionTicks = long.MaxValue;
        }

        if (lease is not null)
        {
            _ = ReleaseQuietlyAsync(lease);
        }
    }

    private static async Task ReleaseQuietlyAsync(IPortMapLease lease)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
            await lease.ReleaseAsync(timeout.Token).ConfigureAwait(false);
        }
        catch
        {
        }
        finally
        {
            lease.Dispose();
        }
    }

    public void Dispose() => Shutdown();
}
