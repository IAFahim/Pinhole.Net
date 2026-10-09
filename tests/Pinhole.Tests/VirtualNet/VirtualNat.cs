using System.Net;

namespace Pinhole.Tests;

/// <summary>The four classic NAT behaviors, with the RFC 4787 semantics that decide whether
/// a hole punch can succeed: mapping allocation (endpoint-independent for cones, per
/// destination for symmetric) and the inbound filter (any remote / same address /
/// same address+port / exactly the mapping's one remote). Public for the matrix theory's
/// parameter lists.</summary>
public enum VirtualNatKind
{
    FullCone,
    RestrictedCone,
    PortRestricted,
    Symmetric,
}

/// <summary>A NAT box in the <see cref="VirtualNetwork"/>. Sockets attach on the private
/// side (<see cref="Attach"/>); their outbound datagrams are translated to public mappings,
/// their inbound datagrams must pass the behavior's filter. Hairpinning works: two sockets
/// behind the same box can dial each other's public endpoints. Mapping state is exactly the
/// minimum a real NAT keeps — nothing is keyed on engine identity.</summary>
internal sealed class VirtualNat : IDisposable
{
    private readonly VirtualNetwork _net;
    private readonly IPAddress _publicAddress;
    private readonly byte[] _internalBase;
    private readonly int _internalPrefix;
    private readonly object _gate = new();
    private readonly Dictionary<IPEndPoint, Mapping> _byPublic = new();
    private readonly List<Mapping> _mappings = [];
    private int _nextInternalHost = 2; // .1 is the box itself
    private int _nextPublicPort = 49152;

    private sealed class Mapping(VirtualUdpSocket socket, IPEndPoint @public)
    {
        public readonly VirtualUdpSocket Socket = socket;
        public readonly IPEndPoint Public = @public;
        public HashSet<IPAddress> SentToAddresses { get; } = [];
        public HashSet<IPEndPoint> SentToEndpoints { get; } = [];
        public IPEndPoint? SoleRemote; // symmetric only: the one destination this mapping serves
        public bool Dead;
    }

    public VirtualNat(VirtualNetwork net, VirtualNatKind kind, IPAddress publicAddress, string internalCidr)
    {
        _net = net;
        Kind = kind;
        _publicAddress = publicAddress;
        Subnet internalSide = Subnet.Parse(internalCidr);
        _internalBase = internalSide.Base.GetAddressBytes();
        _internalPrefix = internalSide.PrefixLength;
        _net.Register(this);
    }

    public VirtualNatKind Kind { get; }

    /// <summary>The UDP-blocked hotel: set true and not one direct datagram leaves the
    /// private side (STUN, punches, everything) — only the separately configured relay
    /// path can carry the session.</summary>
    public bool BlockAllOutboundDirect { get; set; }

    // Independent allocation policy for tests of predictable versus randomized
    // symmetric NATs; it does not inspect Pinhole frames or connection identity.
    internal Func<int, int>? PortAllocator { get; set; }
    private int NextPort() => PortAllocator?.Invoke(_nextPublicPort++) ?? _nextPublicPort++;

    public long MappingsCreated;
    public long FilterDrops;
    public long ExpiredMappings;

    internal VirtualUdpSocket Attach()
    {
        lock (_gate)
        {
            byte[] host = (byte[])_internalBase.Clone();
            int hostOffset = _internalPrefix / 8 - 1;
            int candidate = _nextInternalHost++;
            host[hostOffset] = (byte)(_internalBase[hostOffset] + candidate);
            return new VirtualUdpSocket(_net, new IPEndPoint(new IPAddress(host), 40000 + candidate), nat: this);
        }
    }

    internal bool Owns(IPEndPoint endpoint) => endpoint.Address.Equals(_publicAddress);

    internal bool TryTranslateOutbound(VirtualUdpSocket sender, IPEndPoint dest, out IPEndPoint publicSource)
    {
        if (BlockAllOutboundDirect)
        {
            publicSource = dest;
            return false;
        }

        lock (_gate)
        {
            Mapping? mapping;
            if (Kind == VirtualNatKind.Symmetric)
            {
                mapping = _mappings.FirstOrDefault(m => !m.Dead
                    && m.Socket.Address.Equals(sender.Address) && m.SoleRemote is { } r && r.Equals(dest));
                if (mapping is null)
                {
                    mapping = new Mapping(sender, new IPEndPoint(_publicAddress, NextPort())) { SoleRemote = dest };
                    Adopt(mapping);
                }
            }
            else
            {
                mapping = _mappings.FirstOrDefault(m => !m.Dead && m.Socket.Address.Equals(sender.Address));
                if (mapping is null)
                {
                    mapping = new Mapping(sender, new IPEndPoint(_publicAddress, NextPort()));
                    Adopt(mapping);
                }
            }

            mapping.SentToAddresses.Add(dest.Address);
            mapping.SentToEndpoints.Add(dest);
            publicSource = mapping.Public;
        }

        return true;
    }

    private void Adopt(Mapping mapping)
    {
        _mappings.Add(mapping);
        _byPublic[mapping.Public] = mapping;
        Interlocked.Increment(ref MappingsCreated);
    }

    internal bool TryTranslateInbound(IPEndPoint publicDest, IPEndPoint source, out VirtualUdpSocket? socket)
    {
        lock (_gate)
        {
            socket = null;
            if (!_byPublic.TryGetValue(publicDest, out Mapping? mapping) || mapping.Dead)
            {
                return false;
            }

            bool allow = Kind switch
            {
                VirtualNatKind.FullCone => true,
                VirtualNatKind.RestrictedCone => mapping.SentToAddresses.Contains(source.Address),
                VirtualNatKind.PortRestricted => mapping.SentToEndpoints.Contains(source),
                VirtualNatKind.Symmetric => mapping.SoleRemote is { } r && r.Equals(source),
                _ => false,
            };
            if (!allow)
            {
                Interlocked.Increment(ref FilterDrops);
                return false;
            }

            socket = mapping.Socket;
            return true;
        }
    }

    /// <summary>Silent mapping expiry (the DHCP-renew/router-reboot case): every mapping
    /// dies. Subsequent outbound traffic allocates fresh public ports, exactly like the
    /// real thing, so recovery must come from the engine's re-punch machinery.</summary>
    public void ExpireMappings()
    {
        lock (_gate)
        {
            foreach (Mapping mapping in _mappings)
            {
                mapping.Dead = true;
            }

            _mappings.Clear();
            _byPublic.Clear();
            Interlocked.Increment(ref ExpiredMappings);
        }
    }

    public string Counters() =>
        $"nat({Kind}, mappings={Interlocked.Read(ref MappingsCreated)}, filterDrops={Interlocked.Read(ref FilterDrops)}, expired={Interlocked.Read(ref ExpiredMappings)})";

    public void Dispose()
    {
    }
}
