using System.Net;

namespace Pinhole.Providers;

public sealed record TurnServer(string Host, int Port, string? Username = null, string? Credential = null)
{
    public async Task<IPEndPoint[]> ResolveAsync(CancellationToken ct = default)
    {
        IPAddress[] addrs = await Dns.GetHostAddressesAsync(Host, ct).ConfigureAwait(false);
        return addrs.Select(ip => new IPEndPoint(ip, Port)).ToArray();
    }
}

public static class StunServers
{
    public static Task<IPEndPoint[]> GoogleAsync(CancellationToken ct = default) => Resolve("stun.l.google.com", 19302, ct);
    public static Task<IPEndPoint[]> CloudflareAsync(CancellationToken ct = default) => Resolve("stun.cloudflare.com", 3478, ct);
    public static Task<IPEndPoint[]> OpenRelayAsync(CancellationToken ct = default) => Resolve("openrelay.metered.ca", 80, ct);
    public static Task<IPEndPoint[]> MeteredAsync(CancellationToken ct = default) => Resolve("stun.relay.metered.ca", 80, ct);
    public static Task<IPEndPoint[]> TwilioAsync(CancellationToken ct = default) => Resolve("global.stun.twilio.com", 3478, ct);

    public static async Task<IPEndPoint[]> AllAsync(CancellationToken ct = default)
    {
        Task<IPEndPoint[]>[] all = [GoogleAsync(ct), CloudflareAsync(ct), OpenRelayAsync(ct), MeteredAsync(ct), TwilioAsync(ct)];
        IPEndPoint[][] results = await Task.WhenAll(all).ConfigureAwait(false);
        return results.SelectMany(x => x).ToArray();
    }

    private static async Task<IPEndPoint[]> Resolve(string host, int port, CancellationToken ct)
    {
        IPAddress[] addrs = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
        return addrs.Select(ip => new IPEndPoint(ip, port)).ToArray();
    }
}

public static class TurnServers
{
    public static TurnServer OpenRelay => new("openrelay.metered.ca", 80, "openrelayproject", "openrelayproject");
    public static TurnServer Cloudflare(string username, string credential) => new("turn.cloudflare.com", 3478, username, credential);
    public static TurnServer Metered(string username, string credential) => new("turn.relay.metered.ca", 80, username, credential);
    public static TurnServer Twilio(string username, string credential) => new("global.turn.twilio.com", 3478, username, credential);
}
