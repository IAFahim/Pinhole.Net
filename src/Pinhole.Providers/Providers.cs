using System.Net;

namespace Pinhole.Providers;

/// <summary>A TURN endpoint preset: hostname, port, and the credentials its operator requires.
/// Resolve the hostname with <see cref="ResolveAsync"/>.</summary>
/// <param name="Host">TURN hostname; paired with every address <see cref="ResolveAsync"/> resolves.</param>
/// <param name="Port">TURN port.</param>
/// <param name="Username">Long-term-mechanism username; null when the preset carries none.</param>
/// <param name="Credential">Secret paired with <see cref="Username"/>; null when the preset carries none.</param>
public sealed record TurnServer(string Host, int Port, string? Username = null, string? Credential = null)
{
    /// <summary>Resolves <see cref="Host"/> via DNS and pairs each returned address with <see cref="Port"/>.
    /// No dead-server tolerance: a failed lookup propagates to the caller — see <see cref="Resolver"/>
    /// for lookups that must survive dead providers.</summary>
    public async Task<IPEndPoint[]> ResolveAsync(CancellationToken ct = default)
    {
        IPAddress[] addrs = await Dns.GetHostAddressesAsync(Host, ct).ConfigureAwait(false);
        return addrs.Select(ip => new IPEndPoint(ip, Port)).ToArray();
    }
}

/// <summary>Free public STUN endpoints, one resolver per operator. STUN authenticates nobody,
/// so nothing here takes credentials.</summary>
public static class StunServers
{
    /// <summary>Google's public STUN (stun.l.google.com:19302), resolved to IPEndPoints.</summary>
    public static Task<IPEndPoint[]> GoogleAsync(CancellationToken ct = default) => Resolve("stun.l.google.com", 19302, ct);
    /// <summary>Cloudflare's public STUN (stun.cloudflare.com:3478), resolved to IPEndPoints.</summary>
    public static Task<IPEndPoint[]> CloudflareAsync(CancellationToken ct = default) => Resolve("stun.cloudflare.com", 3478, ct);
    /// <summary>OpenRelay's free STUN (openrelay.metered.ca:80), resolved to IPEndPoints.</summary>
    public static Task<IPEndPoint[]> OpenRelayAsync(CancellationToken ct = default) => Resolve("openrelay.metered.ca", 80, ct);
    /// <summary>Metered.ca's free STUN (stun.relay.metered.ca:80), resolved to IPEndPoints.</summary>
    public static Task<IPEndPoint[]> MeteredAsync(CancellationToken ct = default) => Resolve("stun.relay.metered.ca", 80, ct);
    /// <summary>Twilio's global STUN (global.stun.twilio.com:3478), resolved to IPEndPoints.</summary>
    public static Task<IPEndPoint[]> TwilioAsync(CancellationToken ct = default) => Resolve("global.stun.twilio.com", 3478, ct);

    /// <summary>All five presets resolved and flattened. All-or-nothing: the await rethrows the
    /// first DNS failure, so one dead operator sinks the batch — <see cref="Resolver.FreeStunAsync"/>
    /// tolerates dead servers instead.</summary>
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

/// <summary>TURN presets. TURN always authenticates: only OpenRelay publishes free test
/// credentials; every other preset takes yours.</summary>
public static class TurnServers
{
    /// <summary>OpenRelay's free TURN (openrelay.metered.ca:80) preloaded with the operator's
    /// published test pair openrelayproject/openrelayproject — shared free tier, subject to
    /// throttling, change, or withdrawal by the operator.</summary>
    public static TurnServer OpenRelay => new("openrelay.metered.ca", 80, "openrelayproject", "openrelayproject");
    /// <summary>Cloudflare TURN (turn.cloudflare.com:3478); pass the username and credential
    /// issued by your own Cloudflare account.</summary>
    public static TurnServer Cloudflare(string username, string credential) => new("turn.cloudflare.com", 3478, username, credential);
    /// <summary>Metered.ca TURN (turn.relay.metered.ca:80); pass the username and credential
    /// issued by your own Metered.ca account.</summary>
    public static TurnServer Metered(string username, string credential) => new("turn.relay.metered.ca", 80, username, credential);
    /// <summary>Twilio TURN (global.turn.twilio.com:3478); pass the username and credential
    /// issued by your own Twilio account.</summary>
    public static TurnServer Twilio(string username, string credential) => new("global.turn.twilio.com", 3478, username, credential);
}
