using System.Net;
using System.Net.Sockets;

namespace Pinhole.Tests;

/// <summary>Windows reserves excluded TCP port ranges (Hyper-V/WSL blocks), so a
/// UDP-chosen ephemeral number is frequently unbindable for the TCP sidecar; the
/// engine legitimately leaves TcpListeningPort null and socket-level tests cannot
/// run. Blind ephemeral retries keep landing in the same excluded blocks — probe
/// for a number both stacks accept BEFORE binding the node, then still assert the
/// sidecar so a genuine transport failure cannot hide.</summary>
internal static class SidecarSockets
{
    public static IPEndPoint ProbeDualStackEndpoint(IPAddress address)
    {
        while (true)
        {
            int port;
            using (var udp = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
            {
                udp.Bind(new IPEndPoint(address, 0));
                port = ((IPEndPoint)udp.LocalEndPoint!).Port;
            }
            try
            {
                using var tcp = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                tcp.Bind(new IPEndPoint(address, port));
                return new IPEndPoint(address, port);
            }
            catch (SocketException)
            {
                // The number sits in an excluded TCP range; draw another one.
            }
        }
    }

    /// <summary>Binds a node whose TCP sidecar must be listening. A rare
    /// probe-to-bind port collision retries on a fresh port; the caller still
    /// asserts TcpListeningPort.</summary>
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
                await Task.Delay(150); // a busy runner's port pressure is transient
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
