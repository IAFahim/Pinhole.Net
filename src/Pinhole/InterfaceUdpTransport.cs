using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Pinhole;

/// <summary>Observed candidates for one source-bound UDP socket. Different local
/// sockets can have different NAT mappings; these observations are kept separate.</summary>
public sealed record PinholeInterfaceCandidates(IPEndPoint LocalEndpoint, IReadOnlyList<IPEndPoint> ReflexiveEndpoints)
{
    /// <summary>The local OS interface index. It is routing state, not part of a ticket.</summary>
    public int InterfaceIndex { get; init; }
    /// <summary>The mapping hint from servers probing this same source socket.
    /// Unknown means insufficient comparable observations.</summary>
    public NatHint MappingHint { get; init; }
}

internal readonly record struct UdpInterfaceSource(IPAddress Address, int Index, int Rank = 0);

/// <summary>A bounded source-bound UDP pool. Its sockets remain listening after
/// gathering, and receive callbacks carry the actual local socket into path selection.</summary>
internal sealed class InterfaceUdpTransport : IDisposable
{
    internal const int MaxSources = 4;
    private readonly object _gate = new();
    private readonly object _refreshGate = new();
    private readonly PinholeOptions _options;
    private readonly UdpSocketFactory _factory;
    private readonly Func<IReadOnlyList<UdpInterfaceSource>> _sources;
    private readonly Func<IUdpSocket, IPEndPoint, CancellationToken, Task<IPEndPoint?>> _probe;
    private readonly Action<IUdpSocket, byte[], int, SocketAddress> _received;
    private readonly Action _changed;
    private readonly CancellationTokenSource _stop = new();
    private Slot[] _slots = [];
    private bool _disposed;
    private long _nextProbe;

    internal InterfaceUdpTransport(PinholeOptions options,
        Func<IUdpSocket, IPEndPoint, CancellationToken, Task<IPEndPoint?>> probe,
        Action<IUdpSocket, byte[], int, SocketAddress> received, Action changed)
    {
        _options = options; _probe = probe; _received = received; _changed = changed;
        _factory = options.InterfaceUdpSocketFactory ?? SystemUdpSocket.CreateForInterface;
        _sources = options.InterfaceSourceProvider ?? (() => Gather(options.Bind));
    }

    internal static bool Eligible(IPAddress address) => !IPAddress.IsLoopback(address)
        && !address.IsIPv4MappedToIPv6
        && !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any)
        && !address.IsIPv6LinkLocal && !address.IsIPv6Multicast && !address.IsIPv6Teredo
        && (address.AddressFamily != AddressFamily.InterNetwork || address.GetAddressBytes()[0] is > 0 and < 224);

    internal static IReadOnlyList<UdpInterfaceSource> Gather(IPEndPoint? bind)
    {
        if (bind is not null && !bind.Address.Equals(IPAddress.Any) && !bind.Address.Equals(IPAddress.IPv6Any)) return [];
        var all = new List<UdpInterfaceSource>();
        try
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                IPInterfaceProperties properties = nic.GetIPProperties();
                foreach (UnicastIPAddressInformation entry in properties.UnicastAddresses)
                {
                    IPAddress address = entry.Address;
                    if (!Eligible(address) || bind?.Address.Equals(IPAddress.Any) == true && address.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (OperatingSystem.IsWindows() && entry.DuplicateAddressDetectionState != DuplicateAddressDetectionState.Preferred) continue;
                    int index = address.AddressFamily == AddressFamily.InterNetwork
                        ? properties.GetIPv4Properties()?.Index ?? 0 : properties.GetIPv6Properties()?.Index ?? 0;
                    if (index <= 0) continue;
                    int rank = nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 ? 0
                        : nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet ? 1 : 2;
                    all.Add(new(address, index, rank));
                }
            }
        }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException) { }
        return Select(all);
    }

    internal static IReadOnlyList<UdpInterfaceSource> Select(IEnumerable<UdpInterfaceSource> sources)
    {
        UdpInterfaceSource[] valid = sources.Where(s => s.Index > 0 && Eligible(s.Address))
            .OrderBy(s => s.Rank).ThenBy(s => s.Index).ThenBy(s => s.Address.AddressFamily).Distinct().ToArray();
        // Keep both available families before expanding across interfaces, then take
        // extra families/addresses. Many IPv4 links or privacy addresses must not
        // crowd every IPv6 source out of the bounded pool.
        return valid.DistinctBy(s => s.Address.AddressFamily).Concat(valid.DistinctBy(s => s.Index))
            .Concat(valid.DistinctBy(s => (s.Index, s.Address.AddressFamily)))
            .Concat(valid).Distinct().Take(MaxSources).ToArray();
    }

    internal void Refresh(bool invalidate = false)
    {
        lock (_refreshGate) RefreshCore(invalidate);
    }

    private void RefreshCore(bool invalidate)
    {
        IReadOnlyList<UdpInterfaceSource> desired;
        try { desired = Select(_sources()); }
        catch (Exception ex) when (ex is NetworkInformationException or PlatformNotSupportedException) { desired = []; }
        var retired = new List<Slot>(); var created = new List<Slot>();
        bool changed = false;
        lock (_gate)
        {
            if (_disposed) return;
            var next = new List<Slot>(MaxSources);
            foreach (UdpInterfaceSource source in desired)
            {
                Slot? retained = invalidate ? null : _slots.FirstOrDefault(s => s.Source == source);
                if (retained is not null) { next.Add(retained); continue; }
                try
                {
                    var slot = new Slot(this, source, _factory(new IPEndPoint(source.Address, 0)));
                    next.Add(slot); created.Add(slot);
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException or PlatformNotSupportedException) { }
            }
            retired.AddRange(_slots.Where(s => !next.Contains(s)));
            changed = created.Count != 0 || retired.Count != 0;
            Volatile.Write(ref _slots, next.ToArray());
        }
        foreach (Slot slot in retired) slot.Dispose();
        foreach (Slot slot in created) { slot.Start(); slot.ProbeSoon(); }
        if (changed) _changed(); // callbacks never run under the pool's lock
    }

    internal void Tick(long now)
    {
        if (_options.StunRefreshInterval <= TimeSpan.Zero || now < Interlocked.Read(ref _nextProbe)) return;
        Interlocked.Exchange(ref _nextProbe, now + (long)_options.StunRefreshInterval.TotalMilliseconds);
        foreach (Slot slot in Volatile.Read(ref _slots)) slot.ProbeSoon();
    }

    internal IReadOnlyList<PinholeInterfaceCandidates> Snapshot() => Volatile.Read(ref _slots).Select(s => s.Snapshot()).ToArray();
    internal bool Contains(IUdpSocket socket) => Volatile.Read(ref _slots).Any(s => ReferenceEquals(s.Socket, socket));

    internal void SendCandidates(ReadOnlySpan<byte> frame, IPEndPoint remote)
    {
        // Initial punches are bounded by the source pool. Ordinary application sends use
        // exactly the socket selected by an authenticated receive, never this fan-out.
        if (IPAddress.IsLoopback(remote.Address) || remote.Address.IsIPv6LinkLocal) return;
        AddressFamily family = remote.Address.IsIPv4MappedToIPv6 ? AddressFamily.InterNetwork : remote.AddressFamily;
        IPEndPoint mapped = family == AddressFamily.InterNetwork && !remote.Address.IsIPv4MappedToIPv6
            ? new(remote.Address.MapToIPv6(), remote.Port) : remote;
        SocketAddress target = mapped.Serialize();
        foreach (Slot slot in Volatile.Read(ref _slots))
        {
            if (slot.Source.Address.AddressFamily != family) continue;
            try { slot.Socket.SendTo(frame, target); }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException) { }
        }
    }

    private bool Current(Slot slot) => Volatile.Read(ref _slots).Contains(slot);

    private void Failed(Slot slot)
    {
        bool changed;
        lock (_gate)
        {
            changed = _slots.Contains(slot);
            if (changed) Volatile.Write(ref _slots, _slots.Where(s => !ReferenceEquals(s, slot)).ToArray());
        }
        slot.Dispose();
        if (changed && !_disposed) _changed();
    }

    private sealed class Slot : IDisposable
    {
        private readonly InterfaceUdpTransport _owner;
        internal readonly UdpInterfaceSource Source;
        internal readonly IUdpSocket Socket;
        private readonly IPEndPoint _local;
        private readonly CancellationTokenSource _stop = new();
        private sealed record Observation(IPEndPoint[] Endpoints, NatHint Hint, long At);
        private Observation _observation = new([], NatHint.Unknown, Environment.TickCount64);
        private int _probing, _disposed;
        internal Slot(InterfaceUdpTransport owner, UdpInterfaceSource source, IUdpSocket socket)
        {
            _owner = owner; Source = source; Socket = socket;
            IPEndPoint local = socket.LocalEndPoint;
            _local = new(local.Address.IsIPv4MappedToIPv6 ? local.Address.MapToIPv4() : local.Address, local.Port);
            if (!_local.Address.Equals(source.Address) || _local.Port == 0)
            {
                socket.Dispose();
                throw new SocketException((int)SocketError.AddressNotAvailable);
            }
        }

        internal void Start() => new Thread(ReceiveLoop) { IsBackground = true, Name = "pinhole-interface-recv" }.Start();
        private void ReceiveLoop()
        {
            byte[] buffer = new byte[8192]; var remote = new SocketAddress(AddressFamily.InterNetworkV6);
            int capacity = remote.Size;
            while (Volatile.Read(ref _disposed) == 0 && !_owner._stop.IsCancellationRequested)
            {
                try
                {
                    remote.Size = capacity;
                    int count = Socket.ReceiveFrom(buffer, remote);
                    if (count > 0 && _owner.Current(this)) _owner._received(Socket, buffer, count, remote);
                }
                catch (ObjectDisposedException) { return; }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut || ex.SocketErrorCode == SocketError.Interrupted) { }
                catch (SocketException) { _owner.Failed(this); return; }
                catch (Exception) { } // one malformed frame/user handler cannot terminate this listener
            }
        }

        internal void ProbeSoon()
        {
            if (Volatile.Read(ref _disposed) != 0 || Interlocked.CompareExchange(ref _probing, 1, 0) != 0) return;
            _ = ProbeAsync();
        }

        private async Task ProbeAsync()
        {
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token, _owner._stop.Token);
            stop.CancelAfter(_owner._options.BindProbeBudget);
            try
            {
                IReadOnlyList<IPEndPoint> servers = _owner._options.StunServers ?? _owner._options.ResolvedStun;
                Task<IPEndPoint?>[] probes = servers.Where(s => s.AddressFamily == Source.Address.AddressFamily)
                    .Take(8).Select(s => _owner._probe(Socket, s, stop.Token)).ToArray();
                IPEndPoint?[] replies = await Task.WhenAll(probes).ConfigureAwait(false);
                if (!_owner.Current(this) || Volatile.Read(ref _disposed) != 0) return;
                IPEndPoint[] observed = replies.OfType<IPEndPoint>().Distinct().ToArray();
                if (observed.Length > 0)
                {
                    Observation old = Volatile.Read(ref _observation);
                    NatType type = NatDetector.Classify(replies.OfType<IPEndPoint>().ToArray());
                    NatHint hint = type == NatType.Cone ? NatHint.Cone : type == NatType.Symmetric ? NatHint.Symmetric : NatHint.Unknown;
                    Volatile.Write(ref _observation, new(observed, hint, Environment.TickCount64));
                    if (!old.Endpoints.SequenceEqual(observed) || old.Hint != hint) _owner._changed();
                }
                else if (Expired(Volatile.Read(ref _observation)))
                { Volatile.Write(ref _observation, new([], NatHint.Unknown, Environment.TickCount64)); _owner._changed(); }
            }
            catch (Exception ex) when (ex is SocketException or ObjectDisposedException or OperationCanceledException or TimeoutException) { }
            finally { Volatile.Write(ref _probing, 0); }
        }

        private bool Expired(Observation observation) => _owner._options.StunRefreshInterval > TimeSpan.Zero
            && Environment.TickCount64 - observation.At
            > Math.Max(120_000, _owner._options.StunRefreshInterval.TotalMilliseconds * 2);
        internal PinholeInterfaceCandidates Snapshot()
        {
            Observation observation = Volatile.Read(ref _observation);
            bool expired = Expired(observation);
            IPEndPoint[] observed = expired ? [] : observation.Endpoints;
            return new(new(_local.Address, _local.Port), observed.Select(e => new IPEndPoint(e.Address, e.Port)).ToArray())
            { InterfaceIndex = Source.Index, MappingHint = expired ? NatHint.Unknown : observation.Hint };
        }
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            _stop.Cancel(); Socket.Dispose();
        }
    }

    public void Dispose()
    {
        Slot[] retired;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true; _stop.Cancel();
            retired = _slots; Volatile.Write(ref _slots, []);
        }
        foreach (Slot slot in retired) slot.Dispose();
    }
}
