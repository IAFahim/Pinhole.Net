using System.Net;
using System.Net.Sockets;

namespace Pinhole.Providers;

/// <summary>Tolerant resolution of the free infrastructure: one dead provider costs its own
/// candidates, never the whole list.</summary>
public static class Resolver
{
    /// <summary>All free STUN servers, best-effort resolved.</summary>
    public static async Task<IPEndPoint[]> FreeStunAsync(CancellationToken ct = default)
    {
        (string host, int port)[] sources =
        [
            ("stun.l.google.com", 19302),
            ("stun.cloudflare.com", 3478),
            ("openrelay.metered.ca", 80),
            ("stun.relay.metered.ca", 80),
            ("global.stun.twilio.com", 3478),
        ];

        Task<IPEndPoint[]>[] tasks = sources.Select(s => TryResolve(s.host, s.port, ct)).ToArray();
        IPEndPoint[][] results = await Task.WhenAll(tasks).ConfigureAwait(false);
        return results.SelectMany(r => r).ToArray();
    }

    /// <summary>Every server a stranger's relayed traffic could arrive from when both sides
    /// stick to the free defaults — used to pre-open TURN permissions for unknown dialers.</summary>
    public static async Task<IPEndPoint[]> FreeRelayServersAsync(CancellationToken ct = default)
    {
        (string host, int port)[] sources =
        [
            ("openrelay.metered.ca", 80),
            ("turn.relay.metered.ca", 80),
            ("turn.cloudflare.com", 3478),
            ("global.turn.twilio.com", 3478),
        ];

        Task<IPEndPoint[]>[] tasks = sources.Select(s => TryResolve(s.host, s.port, ct)).ToArray();
        IPEndPoint[][] results = await Task.WhenAll(tasks).ConfigureAwait(false);
        return results.SelectMany(r => r).ToArray();
    }

    private static async Task<IPEndPoint[]> TryResolve(string host, int port, CancellationToken ct)
    {
        try
        {
            IPAddress[] addrs = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
            return addrs.Select(ip => new IPEndPoint(ip, port)).ToArray();
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            return Array.Empty<IPEndPoint>();
        }
    }
}
