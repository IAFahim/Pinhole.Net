using System.Net;

namespace Pinhole.Sim;

public enum VirtualNatKind
{
    FullCone,
    RestrictedCone,
    PortRestricted,
    Symmetric,
}

internal sealed class VirtualNat : IDisposable
{
    private readonly IPAddress _publicAddress;
    private readonly byte[] _internalBase;
    private readonly int _internalPrefix;
    private readonly object _gate = new();
    private readonly Dictionary<IPEndPoint, Mapping> _byPublic = new();
    private readonly List<Mapping> _mappings = [];
    private int _nextInternalHost = 2;
    private int _nextPublicPort = 49152;

    private sealed class Mapping(IPEndPoint internalEndpoint, IPEndPoint @public)
    {
        public readonly IPEndPoint Internal = internalEndpoint;
        public readonly IPEndPoint Public = @public;
        public HashSet<IPAddress> SentToAddresses { get; } = [];
        public HashSet<IPEndPoint> SentToEndpoints { get; } = [];
        public IPEndPoint? SoleRemote;
        public bool Dead;
    }

    public VirtualNat(VirtualNatKind kind, IPAddress publicAddress, string internalCidr)
    {
        Kind = kind;
        _publicAddress = publicAddress;
        Subnet internalSide = Subnet.Parse(internalCidr);
        _internalBase = internalSide.Base.GetAddressBytes();
        _internalPrefix = internalSide.PrefixLength;
    }

    public VirtualNatKind Kind { get; }

    public bool BlockAllOutboundDirect { get; set; }

    internal Func<int, int>? PortAllocator { get; set; }
    private int NextPort() => PortAllocator?.Invoke(_nextPublicPort++) ?? _nextPublicPort++;

    public long MappingsCreated;
    public long FilterDrops;
    public long ExpiredMappings;

    public IPEndPoint AllocateInternalEndpoint()
    {
        lock (_gate)
        {
            byte[] host = (byte[])_internalBase.Clone();
            int hostOffset = _internalPrefix / 8 - 1;
            int candidate = _nextInternalHost++;
            host[hostOffset] = (byte)(_internalBase[hostOffset] + candidate);
            return new IPEndPoint(new IPAddress(host), 40000 + candidate);
        }
    }

    public bool Owns(IPEndPoint endpoint) => endpoint.Address.Equals(_publicAddress);

    public bool TryTranslateOutbound(IPEndPoint internalSource, IPEndPoint dest, out IPEndPoint publicSource)
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
                    && m.Internal.Equals(internalSource) && m.SoleRemote is { } r && r.Equals(dest));
                if (mapping is null)
                {
                    mapping = new Mapping(internalSource, new IPEndPoint(_publicAddress, NextPort())) { SoleRemote = dest };
                    Adopt(mapping);
                }
            }
            else
            {
                mapping = _mappings.FirstOrDefault(m => !m.Dead && m.Internal.Equals(internalSource));
                if (mapping is null)
                {
                    mapping = new Mapping(internalSource, new IPEndPoint(_publicAddress, NextPort()));
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

    public bool TryTranslateInbound(IPEndPoint publicDest, IPEndPoint source, out IPEndPoint? internalDest)
    {
        lock (_gate)
        {
            internalDest = null;
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

            internalDest = mapping.Internal;
            return true;
        }
    }

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
