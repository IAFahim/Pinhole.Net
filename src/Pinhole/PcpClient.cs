using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Pinhole;

/// <summary>Port Control Protocol client (RFC 6887): the successor to NAT-PMP, same UDP
/// port, version 2 framing, nonce-guarded MAP requests. The nonce makes renewals
/// idempotent — re-sending the same nonce updates the existing mapping in place.</summary>
internal static class PcpClient
{
    private static readonly int[] RetryDelaysMs = [0, 250, 500];

    /// <summary>Requests a MAP for <paramref name="internalPort"/> from the first
    /// PCP-capable gateway. <paramref name="gatewayOverride"/> replaces OS gateway
    /// discovery (test seam).</summary>
    public static async Task<PcpMapping?> TryMapAsync(IReadOnlyList<IPEndPoint>? gatewayOverride,
        int internalPort, TimeSpan lease, CancellationToken ct, ProtocolType protocol = ProtocolType.Udp)
    {
        foreach (IPEndPoint gateway in gatewayOverride ?? GatewayDiscovery.DefaultGateways(includeIpv6: true))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                byte[] nonce = RandomNumberGenerator.GetBytes(12);
                using var udp = new UdpClient(gateway.AddressFamily);
                udp.Connect(gateway);
                // Connecting selects the actual source address and pins replies to this
                // gateway. RFC 6887 section 16.4 requires that source in the header.
                byte[] request = BuildMapRequest(nonce, ((IPEndPoint)udp.Client.LocalEndPoint!).Address, internalPort, lease, protocol: protocol);
                byte[]? response = await RoundTripAsync(udp, request, ct).ConfigureAwait(false);
                if (TryParseMapResponse(response, request, out IPEndPoint? external, out uint granted))
                {
                    return new PcpMapping(gateway, nonce, internalPort, external!, TimeSpan.FromSeconds(granted), protocol);
                }
            }
            catch (SocketException)
            {
                // An unavailable interface must not hide a mapping on another gateway.
            }
        }

        return null;
    }

    internal static byte[] BuildMapRequest(byte[] nonce, IPAddress clientAddress, int internalPort,
        TimeSpan lease, IPEndPoint? suggestedExternal = null, ProtocolType protocol = ProtocolType.Udp)
    {
        if (nonce.Length != 12) throw new ArgumentException("PCP nonce needs twelve bytes", nameof(nonce));
        if (internalPort is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(internalPort));
        if (protocol is not (ProtocolType.Udp or ProtocolType.Tcp)) throw new ArgumentOutOfRangeException(nameof(protocol));
        if (lease < TimeSpan.Zero || lease.TotalSeconds > uint.MaxValue) throw new ArgumentOutOfRangeException(nameof(lease));
        // RFC 6887 sections 7.1 and 11.1: 24-byte common header + 36-byte MAP
        // body. The two-byte result field from NAT-PMP is NOT part of PCP.
        byte[] request = new byte[60];
        request[0] = 2;
        request[1] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(4), (uint)lease.TotalSeconds);
        clientAddress.MapToIPv6().GetAddressBytes().CopyTo(request, 8);
        nonce.CopyTo(request, 24);
        request[36] = (byte)protocol; // IP protocol: TCP=6, UDP=17
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(40), (ushort)internalPort);
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(42), (ushort)(suggestedExternal?.Port ?? 0));
        IPAddress suggestedAddress = suggestedExternal?.Address
            ?? (clientAddress.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any);
        suggestedAddress.MapToIPv6().GetAddressBytes().CopyTo(request, 44);
        return request;
    }

    internal static bool TryParseMapResponse(byte[]? response, byte[] request, out IPEndPoint? external, out uint granted)
    {
        external = null;
        granted = 0;
        if (request.Length != 60 || response is null || response.Length is < 60 or > 1100 || response.Length % 4 != 0
            || response[0] != 2 || response[1] != 129 || response[3] != 0
            || !response.AsSpan(24, 12).SequenceEqual(request.AsSpan(24, 12))
            || response[36] != request[36]
            || !response.AsSpan(40, 2).SequenceEqual(request.AsSpan(40, 2)))
        {
            return false;
        }

        granted = BinaryPrimitives.ReadUInt32BigEndian(response.AsSpan(4));
        if (granted == 0 && BinaryPrimitives.ReadUInt32BigEndian(request.AsSpan(4)) != 0)
        {
            return false;
        }

        int externalPort = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(42));
        IPAddress parsed = new(response.AsSpan(44, 16));
        IPAddress unmapped = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
        if (externalPort == 0 || unmapped.Equals(IPAddress.Any) || unmapped.Equals(IPAddress.IPv6Any)
            || unmapped.IsIPv6Multicast || (unmapped.AddressFamily == AddressFamily.InterNetwork
                && unmapped.GetAddressBytes()[0] >= 224))
        {
            return false;
        }

        external = new IPEndPoint(unmapped, externalPort);
        return true;
    }

    private static async Task<byte[]?> RoundTripAsync(UdpClient udp, byte[] request, CancellationToken ct)
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
                await udp.SendAsync(request, ct).ConfigureAwait(false);
                Task timeout = Task.Delay(250, ct);
                while (!timeout.IsCompleted && await Task.WhenAny(pending, timeout).ConfigureAwait(false) == pending)
                {
                    byte[] data = (await pending.ConfigureAwait(false)).Buffer;
                    pending = null;
                    if (data.Length >= 24 && data[0] == 2 && data[1] == 129 && data[3] != 0)
                    {
                        return null; // a gateway error permits the next mapping protocol
                    }
                    if (TryParseMapResponse(data, request, out _, out _))
                    {
                        return data;
                    }
                    // Ignore unrelated/malformed replies without abandoning this attempt.
                    pending = udp.ReceiveAsync(ct).AsTask();
                }
            }
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException or ObjectDisposedException)
        {
        }

        return null;
    }

    /// <summary>A live PCP mapping; renewals reuse the nonce so the gateway updates this
    /// mapping instead of allocating a second one.</summary>
    internal sealed class PcpMapping(IPEndPoint gateway, byte[] nonce, int internalPort,
        IPEndPoint external, TimeSpan lifetime, ProtocolType protocol = ProtocolType.Udp) : IPortMapLease
    {
        public IPEndPoint External { get; } = external;
        public TimeSpan Lifetime { get; private set; } = lifetime;

        public async Task<bool> RenewAsync(CancellationToken ct)
        {
            using var udp = new UdpClient(gateway.AddressFamily);
            udp.Connect(gateway);
            byte[] request = BuildMapRequest(nonce, ((IPEndPoint)udp.Client.LocalEndPoint!).Address, internalPort, Lifetime, External, protocol);
            byte[]? response = await RoundTripAsync(udp, request, ct).ConfigureAwait(false);
            if (!TryParseMapResponse(response, request, out IPEndPoint? renewed, out uint granted))
            {
                return false;
            }

            Lifetime = TimeSpan.FromSeconds(granted);
            return renewed!.Equals(External);
        }

        public async Task ReleaseAsync(CancellationToken ct)
        {
            using var udp = new UdpClient(gateway.AddressFamily);
            udp.Connect(gateway);
            byte[] request = BuildMapRequest(nonce, ((IPEndPoint)udp.Client.LocalEndPoint!).Address, internalPort, TimeSpan.Zero, External, protocol);
            _ = await RoundTripAsync(udp, request, ct).ConfigureAwait(false);
        }

        public void Dispose()
        {
        }
    }
}
