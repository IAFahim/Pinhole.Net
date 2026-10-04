using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Pinhole;

/// <summary>NAT-PMP client (RFC 6886): two datagram exchanges with the default gateway —
/// its public address, then a UDP port mapping. Cheap, stateless, and present on most
/// Apple routers and a long tail of others; silent failure is the normal outcome on
/// networks without it.</summary>
internal static class NatPmpClient
{
    private static readonly int[] RetryDelaysMs = [0, 250, 500];

    /// <summary>Requests a UDP mapping for <paramref name="internalPort"/> from the first
    /// gateway that answers. <paramref name="gatewayOverride"/> replaces OS gateway
    /// discovery (test seam).</summary>
    public static async Task<PmpMapping?> TryMapAsync(IReadOnlyList<IPEndPoint>? gatewayOverride,
        int internalPort, TimeSpan lease, CancellationToken ct)
    {
        foreach (IPEndPoint gateway in gatewayOverride ?? GatewayDiscovery.DefaultGateways())
        {
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            IPAddress? externalIp = await PublicAddressAsync(udp, gateway, ct).ConfigureAwait(false);
            if (externalIp is null)
            {
                continue;
            }

            // [ver=0, op=1, reserved(2), internal port, suggested external port(0=any), lifetime]
            byte[] request = new byte[12];
            request[1] = 1;
            BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(4), (ushort)internalPort);
            BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(8), (uint)lease.TotalSeconds);
            byte[]? response = await RoundTripAsync(udp, gateway, request, 16, ct).ConfigureAwait(false);
            if (response is not null && response.Length >= 16 && response[0] == 0 && response[1] == 129
                && BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2)) == 0)
            {
                // Response: version, opcode, result, epoch, internal port, EXTERNAL port, lifetime.
                ushort mapped = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(10));
                uint granted = BinaryPrimitives.ReadUInt32BigEndian(response.AsSpan(12));
                if (mapped > 0 && granted > 0)
                {
                    return new PmpMapping(gateway, internalPort, mapped,
                        TimeSpan.FromSeconds(granted), new IPEndPoint(externalIp, mapped));
                }
            }
        }

        return null;
    }

    private static async Task<IPAddress?> PublicAddressAsync(UdpClient udp, IPEndPoint gateway, CancellationToken ct)
    {
        byte[]? response = await RoundTripAsync(udp, gateway, [0, 0], 12, ct).ConfigureAwait(false);
        return response is not null && response.Length >= 12 && response[0] == 0 && response[1] == 128
            && BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2)) == 0
                ? new IPAddress(response[8..12])
                : null;
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
            foreach (int delay in RetryDelaysMs)
            {
                if (delay > 0)
                {
                    await Task.Delay(delay, ct).ConfigureAwait(false);
                }

                pending ??= udp.ReceiveAsync(ct).AsTask();
                await udp.SendAsync(request, gateway, ct).ConfigureAwait(false);

                if (await Task.WhenAny(pending, Task.Delay(250, ct)).ConfigureAwait(false) != pending)
                {
                    continue; // this attempt's answer did not land; the receive stays pending for the retry
                }

                if (pending.IsFaulted)
                {
                    return null;
                }

                byte[] data = pending.Result.Buffer;
                pending = null;
                if (data.Length >= minLength && data[0] == request[0]
                    && data[1] == (byte)(request[1] | 0x80))
                {
                    return data;
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
        TimeSpan lifetime, IPEndPoint external) : IPortMapLease
    {
        public IPEndPoint External { get; } = external;
        public TimeSpan Lifetime { get; } = lifetime;

        public async Task<bool> RenewAsync(CancellationToken ct)
        {
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            byte[] request = new byte[12];
            request[1] = 1;
            BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(4), (ushort)internalPort);
            BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(6), (ushort)externalPort); // keep the port we were granted
            BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(8), (uint)Lifetime.TotalSeconds);
            byte[]? response = await RoundTripAsync(udp, gateway, request, 16, ct).ConfigureAwait(false);
            return response is not null && response.Length >= 16
                && BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(2)) == 0
                && BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(10)) == externalPort;
        }

        public async Task ReleaseAsync(CancellationToken ct)
        {
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            byte[] request = new byte[12];
            request[1] = 1;
            BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(4), (ushort)internalPort);
            BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(6), (ushort)externalPort);
            BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(8), 0); // lifetime zero removes the mapping
            _ = await RoundTripAsync(udp, gateway, request, 16, ct).ConfigureAwait(false);
        }

        public void Dispose()
        {
        }
    }
}

/// <summary>OS-level default-gateway discovery in pure BCL: the routing table's gateway
/// list per interface. Empty on hosts with no IPv4 default route.</summary>
internal static class GatewayDiscovery
{
    public static IReadOnlyList<IPEndPoint> DefaultGateways()
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

                foreach (GatewayIPAddressInformation gw in nic.GetIPProperties().GatewayAddresses)
                {
                    if (gw.Address.AddressFamily == AddressFamily.InterNetwork
                        && !gw.Address.Equals(IPAddress.Loopback)
                        && gateways.All(g => !g.Address.Equals(gw.Address)))
                    {
                        gateways.Add(new IPEndPoint(gw.Address, 5351));
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
