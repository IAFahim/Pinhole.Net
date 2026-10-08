using System.Net;
using Pinhole;

namespace Pinhole.Tests;

/// <summary>Harness binding <see cref="PinholeNode"/>s into a <see cref="VirtualNetwork"/>:
/// virtual STUN resolvers, an optional real-loopback TURN relay (the relay path rides real
/// sockets on purpose — the engine's fallback orchestration is what the lab exercises,
/// while the direct path faces the virtual internet's NAT and loss physics). The address
/// plan is all documentation ranges, so nothing here can ever touch a real network.</summary>
internal sealed class VirtualLab : IDisposable
{
    public const string Hosts4 = "192.0.2.0/24";                 // internet-attached hosts + STUN
    public const string Hosts4SecondRegion = "198.51.100.0/24";  // a second v4 region (the v4↔v6 roam victim)
    public const string NatPublic = "203.0.113.0/24";            // NAT public sides
    public const string Hosts6 = "2001:db8::/48";

    private static int _nextHostPort = 30000;

    public readonly VirtualNetwork Net = new();
    private readonly List<VirtualStunServer> _stun = [];
    private readonly List<(FakeTurnServer Server, TurnServerConfig Config)> _turns = [];

    /// <summary>Convenience for the single-relay era: the first configured TURN server.</summary>
    public FakeTurnServer? Turn => _turns.Count > 0 ? _turns[0].Server : null;
    public TurnServerConfig? TurnConfig => _turns.Count > 0 ? _turns[0].Config : null;
    public IReadOnlyList<FakeTurnServer> Turns => _turns.Select(t => t.Server).ToArray();

    public VirtualLab(bool withTurn = false, bool withV6Stun = false, int turnPort = 0, int turnLifetimeSeconds = 600)
    {
        AddStun(new IPEndPoint(IPAddress.Parse("192.0.2.53"), 3478));
        AddStun(new IPEndPoint(IPAddress.Parse("192.0.2.54"), 3478));
        if (withV6Stun)
        {
            AddStun(new IPEndPoint(IPAddress.Parse("2001:db8::53"), 3478));
        }

        if (withTurn)
        {
            AddTurn(port: turnPort, lifetimeSeconds: turnLifetimeSeconds);
        }
    }

    private static int _nextRelayHost = 2; // 127.0.0.2, 127.0.0.3, ... — one IP per server

    /// <summary>Attaches another independently operated TURN server on its own loopback IP
    /// (mirroring real deployments where each relay is a distinct address) — every node's
    /// options carry every configured relay, which is exactly the multi-relay failover setup.
    /// Bind an explicit address only to restart a dead server's identity in place.</summary>
    public FakeTurnServer AddTurn(int port = 0, int lifetimeSeconds = 600, IPAddress? bindAddress = null)
    {
        IPAddress address = bindAddress ?? IPAddress.Parse($"127.0.0.{System.Threading.Interlocked.Increment(ref _nextRelayHost) - 1}");
        FakeTurnServer server = new(port: port, lifetimeSeconds: lifetimeSeconds, bindAddress: address);
        _turns.Add((server, new TurnServerConfig(server.Control, "user", "pass")));
        return server;
    }

    public IPAddress TurnAddress(int index) => _turns[index].Server.Control.Address;

    public IReadOnlyList<IPEndPoint> StunServers => _stun.Select(s => s.LocalEndPoint).ToArray();

    public VirtualNat Nat(VirtualNatKind kind, string publicAddress, string internalCidr) =>
        new(Net, kind, IPAddress.Parse(publicAddress), internalCidr);

    /// <summary>Options for a node in this lab, minus the socket factory — callers attach
    /// one (<see cref="BindNodeAsync"/>, or a custom factory for rebind-changing-address
    /// scenarios like the v4→v6 roam). The tweak is a transform: records are immutable, so
    /// return <c>o with { ... }</c>.</summary>
    public PinholeOptions BaseOptions(Func<PinholeOptions, PinholeOptions>? tweak = null)
    {
        PinholeOptions options = new()
        {
            StunServers = StunServers,
            Relays = [.. _turns.Select(t => t.Config)],
            IrohRelayUrls = [],
            PublishIrohAddress = false,
            EnableNetworkWatch = false,
            EnablePortMapping = false,
            EnableLanDiscovery = false,
        };
        return tweak is null ? options : tweak(options);
    }

    /// <summary>Binds a node behind <paramref name="nat"/> or, when null, directly at
    /// <paramref name="hostAddress"/> (its port is a hint; every attachment allocates a
    /// fresh one). Every rebind re-attaches — a fresh private address behind the NAT, or a
    /// fresh port on the host address — which is exactly what a real rebind means to the
    /// network.</summary>
    public async Task<PinholeNode> BindNodeAsync(VirtualNat? nat = null, IPEndPoint? hostAddress = null,
        Func<PinholeOptions, PinholeOptions>? tweak = null)
    {
        if (nat is null && hostAddress is null)
        {
            throw new ArgumentException("a node needs either a NAT or a host address");
        }

        return await PinholeNode.BindAsync(BaseOptions(tweak) with
        {
            UdpSocketFactory = _ => nat is not null
                ? Net.CreateBehindNat(nat)
                : Net.CreateHost(new IPEndPoint(hostAddress!.Address, Interlocked.Increment(ref _nextHostPort))),
        });
    }

    private IPEndPoint AddStun(IPEndPoint address)
    {
        _stun.Add(new VirtualStunServer(Net, address));
        return address;
    }

    public void Dispose()
    {
        foreach (VirtualStunServer stun in _stun)
        {
            stun.Dispose();
        }

        foreach ((FakeTurnServer server, _) in _turns)
        {
            server.Dispose();
        }

        Net.Dispose();
    }
}
