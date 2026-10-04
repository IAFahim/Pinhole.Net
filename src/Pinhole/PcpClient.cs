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

    /// <summary>Requests a UDP MAP for <paramref name="internalPort"/> from the first
    /// PCP-capable gateway. <paramref name="gatewayOverride"/> replaces OS gateway
    /// discovery (test seam).</summary>
    public static async Task<PcpMapping?> TryMapAsync(IReadOnlyList<IPEndPoint>? gatewayOverride,
        int internalPort, TimeSpan lease, CancellationToken ct)
    {
        foreach (IPEndPoint gateway in gatewayOverride ?? GatewayDiscovery.DefaultGateways())
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] request = BuildMapRequest(nonce, internalPort, lease);
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            byte[]? response = await RoundTripAsync(udp, gateway, request, 50, ct).ConfigureAwait(false);
            if (TryParseMapResponse(response, nonce, out IPEndPoint? external, out uint granted))
            {
                return new PcpMapping(gateway, nonce, internalPort, external!,
                    TimeSpan.FromSeconds(Math.Max(1, granted)));
            }
        }

        return null;
    }

    private static byte[] BuildMapRequest(byte[] nonce, int internalPort, TimeSpan lease)
    {
        // Common header (version, opcode MAP, reserved, lifetime) + MAP body: nonce,
        // protocol UDP, reserved, internal port, external port 0 = "assign any",
        // unspecified external address.
        byte[] request = new byte[44];
        request[0] = 2;
        request[1] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(request.AsSpan(4), (uint)lease.TotalSeconds);
        nonce.CopyTo(request, 8);
        request[20] = 17; // UDP
        BinaryPrimitives.WriteUInt16BigEndian(request.AsSpan(24), (ushort)internalPort);
        return request;
    }

    private static bool TryParseMapResponse(byte[]? response, byte[] nonce, out IPEndPoint? external, out uint granted)
    {
        external = null;
        granted = 0;
        if (response is null || response.Length < 50 || response[0] != 2 || response[1] != 129)
        {
            return false;
        }

        uint result = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(12));
        if (result != 0)
        {
            return false;
        }

        granted = BinaryPrimitives.ReadUInt32BigEndian(response.AsSpan(4));
        if (granted == 0)
        {
            return false;
        }

        if (!nonce.AsSpan().SequenceEqual(response.AsSpan(14, 12)))
        {
            return false; // a reply to someone else's request (or a broken gateway)
        }

        int externalPort = BinaryPrimitives.ReadUInt16BigEndian(response.AsSpan(32));
        byte[] externalAddress = response[34..50];

        // The gateway reports the mapped address as 16 bytes: an IPv4 mapping arrives as
        // ::ffff:a.b.c.d; a non-v4-mapped address cannot be advertised as a v4 candidate.
        IPAddress? parsed = new IPAddress(externalAddress);
        IPAddress unmapped = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
        if (externalPort == 0 || unmapped.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        external = new IPEndPoint(unmapped, externalPort);
        return true;
    }

    private static async Task<byte[]?> RoundTripAsync(UdpClient udp, IPEndPoint gateway, byte[] request,
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
                    continue;
                }

                if (pending.IsFaulted)
                {
                    return null;
                }

                byte[] data = pending.Result.Buffer;
                pending = null;
                if (data.Length >= minLength && data[0] == request[0] && data[1] == (byte)(request[1] | 0x80))
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

    /// <summary>A live PCP mapping; renewals reuse the nonce so the gateway updates this
    /// mapping instead of allocating a second one.</summary>
    internal sealed class PcpMapping(IPEndPoint gateway, byte[] nonce, int internalPort,
        IPEndPoint external, TimeSpan lifetime) : IPortMapLease
    {
        public IPEndPoint External { get; } = external;
        public TimeSpan Lifetime { get; private set; } = lifetime;

        public async Task<bool> RenewAsync(CancellationToken ct)
        {
            byte[] request = BuildMapRequest(nonce, internalPort, Lifetime);
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            byte[]? response = await RoundTripAsync(udp, gateway, request, 50, ct).ConfigureAwait(false);
            if (!TryParseMapResponse(response, nonce, out IPEndPoint? renewed, out uint granted))
            {
                return false;
            }

            Lifetime = TimeSpan.FromSeconds(granted);
            return renewed!.Port == External.Port;
        }

        public async Task ReleaseAsync(CancellationToken ct)
        {
            byte[] request = BuildMapRequest(nonce, internalPort, TimeSpan.Zero);
            using var udp = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
            _ = await RoundTripAsync(udp, gateway, request, 50, ct).ConfigureAwait(false);
        }

        public void Dispose()
        {
        }
    }
}
