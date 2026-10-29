using System.Net;
using System.Net.Sockets;

namespace Pinhole.Tests;

internal static class SidecarSockets
{
    public static IPEndPoint ProbeDualStackEndpoint(IPAddress address)
    {
        const int maximumAttempts = 128;
        SocketException? lastFailure = null;
        for (int attempt = 0; attempt < maximumAttempts; attempt++)
        {
            using var udp = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            udp.Bind(new IPEndPoint(address, 0));
            int port = ((IPEndPoint)udp.LocalEndPoint!).Port;
            try
            {
                using var tcp = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                if (address.AddressFamily == AddressFamily.InterNetworkV6) tcp.DualMode = true;
                if (OperatingSystem.IsWindows()) tcp.ExclusiveAddressUse = true;
                tcp.Bind(new IPEndPoint(address, port));
                return new IPEndPoint(address, port);
            }
            catch (SocketException ex)
            {

                lastFailure = ex;
            }
        }
        throw new InvalidOperationException(
            $"Could not find a port accepting both UDP and TCP after {maximumAttempts} attempts.", lastFailure);
    }

    public static async Task<PinholeNode> BindWithSidecarAsync(
        IPAddress address, Func<IPEndPoint, PinholeOptions> options, IPEndPoint? bind = null)
    {
        for (int attempt = 0; ; attempt++)
        {
            PinholeNode node;
            try
            {
                node = await PinholeNode.BindAsync(options(bind ?? ProbeDualStackEndpoint(address)));
            }
            catch (SocketException) when (attempt < 7)
            {
                await Task.Delay(150);
                continue;
            }
            if (node.TcpListeningPort is not null || attempt >= 7)
            {
                return node;
            }
            await node.DisposeAsync();
            await Task.Delay(150);
        }
    }
}
