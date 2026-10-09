using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Pinhole;

/// <summary>NAT-PMP client (RFC 6886): two datagram exchanges with the default gateway —
/// its public address, then a UDP or TCP port mapping. Cheap, stateless, and present on most
/// Apple routers and a long tail of others; silent failure is the normal outcome on
/// networks without it.</summary>
internal static class NatPmpClient
{
    private static readonly int[] RetryDelaysMs = [0, 250, 500];

    /// <summary>Requests a mapping for <paramref name="internalPort"/> from the first
    /// gateway that answers. <paramref name="gatewayOverride"/> replaces OS gateway
    /// discovery (test seam).</summary>
    public static async Task<PmpMapping?> TryMapAsync(IReadOnlyList<IPEndPoint>? gatewayOverride,
        int internalPort, TimeSpan lease, CancellationToken ct, ProtocolType protocol = ProtocolType.Udp)
    {
        foreach (IPEndPoint gateway in (gatewayOverride ?? GatewayDiscovery.DefaultGateways())
            .Where(g => g.AddressFamily == AddressFamily.InterNetwork))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
                IPAddress? externalIp = await PublicAddressAsync(udp, gateway, ct).ConfigureAwait(false);
                if (externalIp is null) continue;
                byte[] request = BuildMapRequest(internalPort, lease, protocol: protocol);
                byte[]? response = await RoundTripAsync(udp, gateway, request, 16, ct).ConfigureAwait(false);
                if (TryParseMapResponse(response, request, out int mapped, out uint granted))
                {
                    return new PmpMapping(gateway, internalPort, mapped,
                        TimeSpan.FromSeconds(granted), new IPEndPoint(externalIp, mapped), protocol);
                }
            }
            catch (SocketException) { } // another gateway may still work
        }

        return null;
    }

    private static async Task<IPAddress?> PublicAddressAsync(UdpClient udp, IPEndPoint gateway, CancellationToken ct)
    {
        byte[]? response = await RoundTripAsync(udp, gateway, [0, 0], 12, ct).ConfigureAwait(false);
        return TryParsePublicAddress(response, out IPAddress? address) ? address : null;
    }

    internal static bool TryParsePublicAddress(byte[]? response, out IPAddress? address)
    {
        address = null;
        if (response is null || response.Length != 12 || response[0] != 0 || response[1] != 128
            || BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2)) != 0
            || response[8] == 0 || response[8] >= 224) return false;
        address = new IPAddress(response.AsSpan(8, 4));
        return true;
    }

    internal static byte[] BuildMapRequest(int internalPort, TimeSpan lease, int externalPort = 0,
        ProtocolType protocol = ProtocolType.Udp)
    {
        if (internalPort is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(internalPort));
        if (externalPort is < 0 or > 65535) throw new ArgumentOutOfRangeException(nameof(externalPort));
        if (protocol is not (ProtocolType.Udp or ProtocolType.Tcp)) throw new ArgumentOutOfRangeException(nameof(protocol));
        if (lease < TimeSpan.Zero || lease.TotalSeconds > uint.MaxValue) throw new ArgumentOutOfRangeException(nameof(lease));
        byte[] request = new byte[12];
        request[1] = protocol == ProtocolType.Tcp ? (byte)2 : (byte)1;
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(4), (ushort)internalPort);
        // RFC 6886 section 3.4: deletion MUST suggest external port zero.
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(6), lease == TimeSpan.Zero ? (ushort)0 : (ushort)externalPort);
        BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(8), (uint)lease.TotalSeconds);
        return request;
    }

    internal static bool TryParseMapResponse(byte[]? response, byte[] request, out int externalPort, out uint granted)
    {
        externalPort = 0;
        granted = 0;
        if (request.Length != 12 || response is null || response.Length != 16 || response[0] != 0
            || response[1] != (request[1] | 128) || BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2)) != 0
            || !response.AsSpan(8, 2).SequenceEqual(request.AsSpan(4, 2))) return false;
        int port = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(10));
        uint lifetime = BinaryPrimitives.ReadUInt32BigEndian(response.AsSpan(12));
        bool deletion = BinaryPrimitives.ReadUInt32BigEndian(request.AsSpan(8)) == 0;
        if (deletion ? port != 0 || lifetime != 0 : port == 0 || lifetime == 0) return false;
        externalPort = port;
        granted = lifetime;
        return true;
    }

    /// <summary>Send/retry/receive one PMP datagram exchange. Exactly one receive stays
    /// pending across retries — a second concurrent receive on the same socket is an error,
    /// and abandoning a timed-out one would trigger it.</summary>
    internal static async Task<byte[]?> RoundTripAsync(UdpClient udp, IPEndPoint gateway, byte[] request,
        int minLength, CancellationToken ct)
    {
        Task<UdpReceiveResult>? pending = null;
        try
        {
            // Connecting pins the responder as well as selecting the source route.
            if (!udp.Client.Connected) udp.Connect(gateway);
            else if (!gateway.Equals(udp.Client.RemoteEndPoint)) return null;
            foreach (int delay in RetryDelaysMs)
            {
                if (delay > 0)
                {
                    await Task.Delay(delay, ct).ConfigureAwait(false);
                }

                pending ??= udp.ReceiveAsync(ct).AsTask();
                await udp.SendAsync(request, ct).ConfigureAwait(false);
                Task timeout = Task.Delay(250, ct);
                while (!timeout.IsCompleted && await Task.WhenAny(pending, timeout).ConfigureAwait(false) == pending)
                {
                    UdpReceiveResult received = await pending.ConfigureAwait(false);
                    byte[] data = received.Buffer;
                    pending = null;
                    if (received.RemoteEndPoint.Equals(gateway) && data.Length == minLength && data[0] == request[0]
                        && data[1] == (byte)(request[1] | 128))
                    {
                        if (BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(2)) != 0) return null;
                        if (request.Length == 2 ? TryParsePublicAddress(data, out _) : TryParseMapResponse(data, request, out _, out _)) return data;
                    }
                    pending = udp.ReceiveAsync(ct).AsTask();
                }
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
        }

        return null;
    }

    /// <summary>A live NAT-PMP mapping plus the datagram handles to renew or release it.</summary>
    internal sealed class PmpMapping(IPEndPoint gateway, int internalPort, int externalPort,
        TimeSpan lifetime, IPEndPoint external, ProtocolType protocol = ProtocolType.Udp) : IPortMapLease
    {
        public IPEndPoint External { get; } = external;
        public TimeSpan Lifetime { get; private set; } = lifetime;

        public async Task<bool> RenewAsync(CancellationToken ct)
        {
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            byte[] request = BuildMapRequest(internalPort, Lifetime, externalPort, protocol);
            byte[]? response = await RoundTripAsync(udp, gateway, request, 16, ct).ConfigureAwait(false);
            if (!TryParseMapResponse(response, request, out int renewed, out uint granted)) return false;
            Lifetime = TimeSpan.FromSeconds(granted);
            return renewed == externalPort;
        }

        public async Task ReleaseAsync(CancellationToken ct)
        {
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            byte[] request = BuildMapRequest(internalPort, TimeSpan.Zero, protocol: protocol);
            _ = await RoundTripAsync(udp, gateway, request, 16, ct).ConfigureAwait(false);
        }

        public void Dispose()
        {
        }
    }
}

/// <summary>OS-level default-gateway discovery in pure BCL: the routing table's gateway
/// list per interface. NAT-PMP requests IPv4 only; PCP can also use IPv6 gateways.</summary>
internal static class GatewayDiscovery
{
    public static IReadOnlyList<IPEndPoint> DefaultGateways(bool includeIpv6 = false)
    {
        var gateways = new List<IPEndPoint>();
        try
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    continue;
                }

                IPInterfaceProperties properties = nic.GetIPProperties();
                foreach (GatewayIPAddressInformation gw in properties.GatewayAddresses)
                {
                    IPAddress address = gw.Address;
                    if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)
                        || (!includeIpv6 && address.AddressFamily != AddressFamily.InterNetwork))
                    {
                        continue;
                    }
                    if (address.IsIPv6LinkLocal && address.ScopeId == 0)
                    {
                        int scope = properties.GetIPv6Properties()?.Index ?? 0;
                        if (scope <= 0) continue;
                        address = new IPAddress(address.GetAddressBytes(), scope);
                    }
                    if (gateways.All(g => !g.Address.Equals(address)))
                    {
                        gateways.Add(new IPEndPoint(address, 5351));
                        if (gateways.Count >= 4)
                        {
                            return gateways;
                        }
                    }
                }
            }
        }
        catch (NetworkInformationException)
        {
        }

        return gateways;
    }
}
