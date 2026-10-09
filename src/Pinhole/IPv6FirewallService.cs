using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Pinhole;

/// <summary>At most two LAN source addresses and four protocol-specific leases.
/// Each lease uses the existing serialized cancellation/renewal/expiry worker.
/// Retired workers are bounded too, even during rapid interface churn.</summary>
internal sealed class IPv6FirewallService : IDisposable
{
    internal const int MaxSources = 2;
    internal const int MaxWorkers = 16;
    private readonly record struct Key(IPv6LanSource Source, ProtocolType Protocol);
    private readonly object _gate = new();
    private readonly PinholeOptions _options;
    private readonly Action _changed;
    private readonly Func<IPv6LanSource, int, ProtocolType, CancellationToken, Task<IPortMapLease?>> _create;
    private readonly Dictionary<Key, PortMappingService> _active = new();
    private readonly List<Task> _retiring = new();
    private bool _disposed;

    internal IPv6FirewallService(PinholeOptions options, Action changed,
        Func<IPv6LanSource, int, ProtocolType, CancellationToken, Task<IPortMapLease?>>? create = null)
    {
        _options = options; _changed = changed; _create = create ?? UpnpIPv6FirewallClient.TryCreateAsync;
    }

    internal static IReadOnlyList<IPv6LanSource> Gather(IPEndPoint? bind)
    {
        if (bind is not null && bind.AddressFamily != AddressFamily.InterNetworkV6) return [];
        var sources = new List<(int Rank, IPv6LanSource Source)>();
        try
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up
                    || nic.NetworkInterfaceType is not (NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.Ethernet)) continue;
                IPInterfaceProperties properties = nic.GetIPProperties();
                IPv6InterfaceProperties? ipv6 = properties.GetIPv6Properties();
                if (ipv6 is null || ipv6.Index <= 0) continue;
                foreach (UnicastIPAddressInformation unicast in properties.UnicastAddresses)
                {
                    IPAddress address = unicast.Address;
                    if (!UpnpIPv6FirewallClient.IsGlobalUnicast(address)
                        || bind is not null && !bind.Address.Equals(IPAddress.IPv6Any) && !bind.Address.Equals(address)) continue;
                    // Linux does not expose DAD/lifetimes through this API. Do not invent
                    // readiness from them there; a failed source bind simply yields no lease.
                    if (OperatingSystem.IsWindows() && unicast.DuplicateAddressDetectionState != DuplicateAddressDetectionState.Preferred) continue;
                    sources.Add((nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? 0 : 1,
                        new IPv6LanSource(address, ipv6.Index)));
                }
            }
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException) { }
        // Cover distinct links before spending both slots on one interface's privacy addresses.
        var ordered = sources.OrderBy(s => s.Rank).ThenBy(s => s.Source.InterfaceIndex).Select(s => s.Source).Distinct().ToArray();
        return ordered.DistinctBy(s => s.InterfaceIndex).Concat(ordered).Distinct().Take(MaxSources).ToArray();
    }

    internal void Refresh(IReadOnlyList<IPv6LanSource> sources, int udpPort, int? tcpPort, bool invalidate = false)
    {
        lock (_gate)
        {
            if (_disposed) return;
            _retiring.RemoveAll(t => t.IsCompleted);
            var desired = new Dictionary<Key, int>();
            foreach (IPv6LanSource source in sources.Where(s => s.InterfaceIndex > 0 && UpnpIPv6FirewallClient.IsGlobalUnicast(s.Address)).Distinct().Take(MaxSources))
            {
                if (udpPort is >= 1024 and <= 65535) desired[new Key(source, ProtocolType.Udp)] = udpPort;
                if (tcpPort is >= 1024 and <= 65535) desired[new Key(source, ProtocolType.Tcp)] = tcpPort.Value;
            }
            foreach (Key key in _active.Keys.Where(k => !desired.ContainsKey(k)).ToArray())
            {
                PortMappingService old = _active[key]; _active.Remove(key);
                old.Shutdown(); _retiring.Add(old.Completed);
            }
            foreach (var entry in desired)
            {
                if (!_active.TryGetValue(entry.Key, out PortMappingService? worker))
                {
                    if (_active.Count + _retiring.Count >= MaxWorkers) continue;
                    Key key = entry.Key;
                    worker = new PortMappingService(_options, _ => _changed(), key.Protocol,
                        (port, ct) => _create(key.Source, port, key.Protocol, ct));
                    _active.Add(key, worker);
                    worker.Ensure(entry.Value);
                }
                else if (invalidate) worker.Rebind(entry.Value);
                else worker.Ensure(entry.Value); // unchanged input never extends a failed lease
            }
        }
    }

    internal IReadOnlyList<IPEndPoint> Snapshot(ProtocolType protocol)
    {
        lock (_gate)
        {
            return _active.Where(e => e.Key.Protocol == protocol).Select(e => e.Value.Current)
                .OfType<IPEndPoint>().Select(e => new IPEndPoint(e.Address, e.Port)).ToArray();
        }
    }

    internal Task Completed
    {
        get { lock (_gate) return Task.WhenAll(_retiring.Concat(_active.Values.Select(v => v.Completed))); }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            foreach (PortMappingService worker in _active.Values)
            {
                worker.Shutdown(); _retiring.Add(worker.Completed);
            }
            _active.Clear();
        }
    }
}
