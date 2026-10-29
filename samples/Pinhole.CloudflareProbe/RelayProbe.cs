using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Channels;
using Pinhole.Turn;

namespace Pinhole.CloudflareProbe;

internal sealed record RelayResult(int RawRoundTrips, int RoundTripsEachDirection, int SendAttempts);

internal static class RelayProbe
{
    public static async Task<RelayResult> RunAsync(CloudflareCredentials aCredentials,
        CloudflareCredentials bCredentials, Action<string> stage, CancellationToken ct)
    {
        stage("cloudflare_dns");
        IPAddress ip = (await Dns.GetHostAddressesAsync("turn.cloudflare.com", ct))
            .FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork)
            ?? throw new ProbeFailure("FAIL", "NO_CLOUDFLARE_IPV4_ADDRESS");
        var aServer = new IPEndPoint(ip, aCredentials.Port);
        var bServer = new IPEndPoint(ip, bCredentials.Port);

        stage("turn_allocation");
        await using var rawA = await TurnClient.AllocateAsync(aServer, aCredentials.Username, aCredentials.Credential, ct);
        await using var rawB = await TurnClient.AllocateAsync(bServer, bCredentials.Username, bCredentials.Credential, ct);
        if (Environment.GetEnvironmentVariable("PINHOLE_CLOUDFLARE_DIAGNOSTICS") == "1")
            Console.Error.WriteLine($"TURN address topology: controlMatchesRelayA={ip.Equals(rawA.RelayedAddress!.Address)}, " +
                $"controlMatchesRelayB={ip.Equals(rawB.RelayedAddress!.Address)}, " +
                $"sameRelayAddress={rawA.RelayedAddress.Address.Equals(rawB.RelayedAddress.Address)}");
        stage("turn_permissions");
        await Task.WhenAll(rawA.CreatePermissionAsync(rawB.RelayedAddress!.Address, ct),
            rawB.CreatePermissionAsync(rawA.RelayedAddress!.Address, ct));
        var inboxA = Channel.CreateBounded<byte[]>(16);
        var inboxB = Channel.CreateBounded<byte[]>(16);
        rawA.Received += (peer, data) => { if (peer.Equals(rawB.RelayedAddress)) inboxA.Writer.TryWrite(data); };
        rawB.Received += (peer, data) => { if (peer.Equals(rawA.RelayedAddress)) inboxB.Writer.TryWrite(data); };
        stage("turn_datagrams");
        int sendAttempts = 0;
        for (int i = 0; i < 4; i++)
        {
            byte[] payload = RandomNumberGenerator.GetBytes(128);
            await RoundTripAsync(payload,
                data => rawA.SendAsync(data, rawB.RelayedAddress!, ct),
                token => ReadChannelAsync(inboxB.Reader, payload, token),
                data => rawB.SendAsync(data, rawA.RelayedAddress!, ct),
                token => ReadChannelAsync(inboxA.Reader, payload, token), () => sendAttempts++, ct);
        }

        stage("pinhole_allocation");
        await using var a = await PinholeNode.BindAsync(Options(aServer, aCredentials), ct);
        await using var b = await PinholeNode.BindAsync(Options(bServer, bCredentials), ct);
        string bTicket = RelayTicket(b, bServer);
        string aTicket = RelayTicket(a, aServer);
        if (Environment.GetEnvironmentVariable("PINHOLE_CLOUDFLARE_DIAGNOSTICS") == "1")
        {
            var relayA = ConnectionString.Parse(a.ConnectionString).Candidates.First(c => c.Kind == CandidateKind.Relay).Address;
            var relayB = ConnectionString.Parse(b.ConnectionString).Candidates.First(c => c.Kind == CandidateKind.Relay).Address;
            Console.Error.WriteLine($"TURN node topology: sameRelayAddress={relayA.Address.Equals(relayB.Address)}, " +
                $"rawMatchesNodeA={rawA.RelayedAddress!.Address.Equals(relayA.Address)}, " +
                $"rawMatchesNodeB={rawB.RelayedAddress!.Address.Equals(relayB.Address)}");
        }
        stage("encrypted_handshake");

        var connected = await Task.WhenAll(a.ConnectAsync(bTicket, ct), b.ConnectAsync(aTicket, ct));
        await using var atA = connected[0];
        await using var atB = connected[1];
        RequireEncryptedRelay(atA, atB);

        stage("encrypted_datagrams");
        for (int direction = 0; direction < 2; direction++)
        {
            var sender = direction == 0 ? atA : atB;
            var receiver = direction == 0 ? atB : atA;
            for (int i = 0; i < 48; i++)
            {
                byte[] payload = RandomNumberGenerator.GetBytes(256);
                await RoundTripAsync(payload,
                    data => { RequireEncryptedRelay(atA, atB); sender.Send(data); return Task.CompletedTask; },
                    token => ReadConnectionAsync(receiver, payload, token),
                    data => { RequireEncryptedRelay(atA, atB); receiver.Send(data); return Task.CompletedTask; },
                    token => ReadConnectionAsync(sender, payload, token), () => sendAttempts++, ct);
            }
        }
        RequireEncryptedRelay(atA, atB);
        return new(4, 48, sendAttempts);
    }

    private static PinholeOptions Options(IPEndPoint server, CloudflareCredentials credentials) => new()
    {
        Bind = new IPEndPoint(IPAddress.Any, 0),
        Relays = [new TurnServerConfig(server, credentials.Username, credentials.Credential)],
        StunServers = [], IrohRelayUrls = [], DerpRelayUrls = [], RendezvousEndpoints = [], LookupProviders = [],
        PublishIrohAddress = false, EnableDirectUdp = false, EnableTcpTransport = false,
        EnableInterfaceCandidates = false, EnablePortMapping = false, EnablePortPrediction = false,
        AdvertiseLinkLocal = false, EnableNetworkWatch = false, EnableLanDiscovery = false,
        EnablePmtud = false, StunRefreshInterval = TimeSpan.Zero,
        Encryption = PinholeEncryption.Required, ReceiveBufferCapacity = 32,
        BindProbeBudget = TimeSpan.FromSeconds(20), ConnectTimeout = TimeSpan.FromSeconds(20)
    };

    private static string RelayTicket(PinholeNode node, IPEndPoint server)
    {
        var parsed = ConnectionString.Parse(node.ConnectionString);
        var relays = parsed.Candidates.Where(c => c.Kind == CandidateKind.Relay && server.Equals(c.RelayServer)).ToArray();
        if (relays.Length == 0) throw new ProbeFailure("FAIL", "NO_CLOUDFLARE_RELAY_CANDIDATE");
        return new ConnectionString(parsed.PeerId, relays, parsed.NatHint, parsed.StaticKey, parsed.EndpointKey, parsed.Knock).ToString();
    }

    private static void RequireEncryptedRelay(PinholeConnection a, PinholeConnection b)
    {
        if (!a.IsEncrypted || !b.IsEncrypted || a.Path.Kind != PathKind.Relay || b.Path.Kind != PathKind.Relay
            || a.Path.RelayUrl is not null || b.Path.RelayUrl is not null)
            throw new ProbeFailure("FAIL", "EXPECTED_ENCRYPTED_TURN_PATH");
    }

    private static async Task RoundTripAsync(byte[] payload, Func<byte[], Task> send,
        Func<CancellationToken, Task> receive, Func<byte[], Task> reply,
        Func<CancellationToken, Task> receiveReply, Action onSend, CancellationToken ct)
    {
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            using var packetDeadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            packetDeadline.CancelAfter(TimeSpan.FromSeconds(3));
            onSend();
            await send(payload);
            try
            {
                await receive(packetDeadline.Token);
                onSend();
                await reply(payload);
                await receiveReply(packetDeadline.Token);
                return;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
        }
        throw new ProbeFailure("FAIL", "ECHO_DEADLINE_EXCEEDED");
    }

    private static async Task ReadChannelAsync(ChannelReader<byte[]> reader, byte[] expected, CancellationToken ct)
    {
        while (true)
            if ((await reader.ReadAsync(ct)).AsSpan().SequenceEqual(expected)) return;
    }

    private static async Task ReadConnectionAsync(PinholeConnection connection, byte[] expected, CancellationToken ct)
    {
        while (true)
        {
            var data = await connection.ReceiveAsync(ct);
            if (data is null) throw new ProbeFailure("FAIL", "EARLY_CONNECTION_CLOSE");
            if (data.Value.Span.SequenceEqual(expected)) return;
        }
    }
}
