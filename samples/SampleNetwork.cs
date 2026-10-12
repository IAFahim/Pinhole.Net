using System.Net;
using Pinhole;

// Auto uses the SDK defaults. Other modes prove which transport actually works
// and let CI run the real samples without contacting public infrastructure.
internal static class SampleNetwork
{
    internal static PinholeOptions Options(int receiveBufferCapacity = 64)
    {
        var options = new PinholeOptions
        {
            ReceiveBufferCapacity = receiveBufferCapacity,
            KeepaliveInterval = TimeSpan.FromSeconds(10),
        };
        string mode = Environment.GetEnvironmentVariable("PINHOLE_SAMPLE_NETWORK")?.Trim().ToLowerInvariant() ?? "auto";
        if (mode == "auto") return options;
        options = options with
        {
            StunServers = [], Relays = [], IrohRelayUrls = [], DerpRelayUrls = [],
            PublishIrohAddress = false, EnableLanDiscovery = false,
            EnablePortMapping = false, EnableInterfaceCandidates = false,
            EnableNetworkWatch = false,
        };
        return mode switch
        {
            "loopback" => options with { Bind = new IPEndPoint(IPAddress.Loopback, 0) },
            "tcp" => options with { EnableDirectUdp = false },
            "iroh" => options with { EnableDirectUdp = false, EnableTcpTransport = false,
                IrohRelayUrls = [.. PublicIrohRelays] },
            "derp" => options with { EnableDirectUdp = false, EnableTcpTransport = false,
                DerpRelayUrls = [.. PublicDerpRelays] },
            _ => throw new ArgumentException("PINHOLE_SAMPLE_NETWORK must be auto, loopback, tcp, iroh, or derp."),
        };
    }

    // Explicit lists also work for coordinator sessions, which normally use the
    // coordinator's TURN fleet when IrohRelayUrls is null.
    private static readonly Uri[] PublicIrohRelays =
    [
        new("https://aps1-1.relay.n0.iroh.link/"), new("https://euc1-1.relay.n0.iroh.link/"),
        new("https://use1-1.relay.n0.iroh.link/"), new("https://usw1-1.relay.n0.iroh.link/"),
    ];
    private static readonly Uri[] PublicDerpRelays =
    [
        new("https://tc304a.ipn.dev/"), new("https://tc303a.ipn.dev/"),
        new("https://tc301a.ipn.dev/"), new("https://tc302a.ipn.dev/"),
    ];

    internal static string NormalizeInvitation(string text) =>
        text.Trim().Trim('"', '\'', '`').Trim().Replace('+', '-').Replace('/', '_');

    internal static string ShareInvitation(string text) => text.Replace('-', '+').Replace('_', '/');

    internal static string Describe(PinholeConnection peer) => peer.Path.Kind == PathKind.Relay
        ? $"Relay {peer.Path.RelayUrl?.Host ?? "TURN"}" : $"{peer.Path.Kind} {peer.Path.Transport}";
}
