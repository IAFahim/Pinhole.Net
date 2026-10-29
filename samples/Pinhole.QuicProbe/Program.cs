using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

return await Probe.RunAsync(args);

internal static partial class Probe
{
    private const int Rounds = 100;
    private const int PayloadBytes = 64;
    private static readonly SslApplicationProtocol Protocol = new("pinhole-quic-probe/1");

    public static async Task<int> RunAsync(string[] args)
    {
        bool check = args.Length == 1 && args[0] == "--check";
        bool rust = args.Length is 2 or 3 && args[0] == "--rust-server"
            && (args.Length == 2 || args[2] == "--wrong-server-pin");
        if (args.Length != 0 && !check && !rust)
        {
            Console.Error.WriteLine("Usage: Pinhole.QuicProbe [--check | --rust-server <executable> [--wrong-server-pin]]");
            return 1;
        }

        var report = new Report();
        if (rust)
            report.Scope = "C# client and independent Rust Quinn server; mutual certificate authentication; reliable stream; no NAT or relay test";
        try
        {
            if (!(OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS()))
            {
                report.Status = "BLOCKED";
                report.Reason = "This desktop probe uses the public API's Windows, Linux and macOS platform surface.";
                return 2;
            }

            report.UnreliableDatagramApi = typeof(QuicConnection).GetMembers()
                .Any(member => member.Name.Contains("Datagram", StringComparison.OrdinalIgnoreCase));
            report.ConnectionSupported = QuicConnection.IsSupported;
            report.ListenerSupported = QuicListener.IsSupported;
            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
                report.UdpLoopbackAvailable = true;
            }
            catch (SocketException error)
            {
                report.UdpError = $"{error.SocketErrorCode} (native {error.NativeErrorCode})";
            }

            if (!report.ConnectionSupported || !report.ListenerSupported || !report.UdpLoopbackAvailable)
            {
                report.Status = "BLOCKED";
                report.Reason = "QUIC runtime support and permission to bind UDP are both required. " +
                    "On Linux, check libmsquic and TLS 1.3 support; IsSupported=false alone does not identify the cause.";
                return 2;
            }

            if (check)
            {
                report.Status = "READY";
                report.Reason = "Prerequisites passed; encrypted echo has not run.";
                return 0;
            }

            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            if (rust)
            {
                RustResult result = await RunRustEchoAsync(args[1], args.Length == 3, deadline.Token);
                report.Measurements = result.Measurements;
                report.Status = result.PinRejected ? "EXPECTED_REJECTION" : "PASS";
                report.Reason = result.PinRejected
                    ? "The TLS certificate callback rejected the deliberately incorrect server pin; no application traffic was sent."
                    : "C# and Rust independently verified the authenticated echo and EOF checks.";
                return 0;
            }
            report.Measurements = await RunEchoAsync(deadline.Token);
            report.Status = "PASS";
            report.Reason = "Both peers authenticated; all payloads matched; both stream halves reached EOF.";
            return 0;
        }
        catch (Exception error)
        {
            report.Status = "FAIL";
            report.Reason = $"{error.GetType().Name}: {error.Message}";
            return 1;
        }
        finally
        {
            Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
        }
    }

    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("osx")]
    private static async Task<Measurements> RunEchoAsync(CancellationToken cancellationToken)
    {
        using var serverIdentity = CreateIdentity("quic-probe-server");
        using var clientIdentity = CreateIdentity("quic-probe-client");
        byte[] serverPin = serverIdentity.GetCertHash(HashAlgorithmName.SHA256);
        byte[] clientPin = clientIdentity.GetCertHash(HashAlgorithmName.SHA256);

        await using var listener = await QuicListener.ListenAsync(new QuicListenerOptions
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
            ApplicationProtocols = [Protocol],
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions
            {
                DefaultCloseErrorCode = 0,
                DefaultStreamErrorCode = 1,
                MaxInboundBidirectionalStreams = 1,
                ServerAuthenticationOptions = new SslServerAuthenticationOptions
                {
                    ApplicationProtocols = [Protocol],
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13,
                    ServerCertificate = serverIdentity,
                    ClientCertificateRequired = true,
                    RemoteCertificateValidationCallback = (_, certificate, _, _) => MatchesPin(certificate, clientPin),
                },
            }),
        }, cancellationToken);

        var connectWatch = Stopwatch.StartNew();
        await using var client = await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
        {
            RemoteEndPoint = listener.LocalEndPoint,
            DefaultCloseErrorCode = 0,
            DefaultStreamErrorCode = 1,
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                ApplicationProtocols = [Protocol],
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13,
                TargetHost = "quic-probe-server",
                ClientCertificates = new X509CertificateCollection { clientIdentity },
                RemoteCertificateValidationCallback = (_, certificate, _, _) => MatchesPin(certificate, serverPin),
            },
        }, cancellationToken);
        await using var server = await listener.AcceptConnectionAsync(cancellationToken);

        if (client.NegotiatedApplicationProtocol != Protocol || server.NegotiatedApplicationProtocol != Protocol)
            throw new InvalidOperationException("Expected the probe ALPN on both peers.");
#if NET9_0_OR_GREATER
        if (client.SslProtocol != System.Security.Authentication.SslProtocols.Tls13
            || server.SslProtocol != System.Security.Authentication.SslProtocols.Tls13)
            throw new InvalidOperationException("Expected TLS 1.3 on both peers.");
#endif

        await using var outgoing = await client.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken);
        Task echo = EchoAsync(server, cancellationToken);
        Task<Measurements> measure = MeasureAsync(outgoing, connectWatch, cancellationToken);

        await Task.WhenAll(echo, measure);
        Measurements measurements = await measure;
        await client.CloseAsync(0, cancellationToken);
        return measurements;
    }

    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("osx")]
    private static async Task EchoAsync(QuicConnection connection, CancellationToken cancellationToken)
    {
        await using var stream = await connection.AcceptInboundStreamAsync(cancellationToken);
        byte[] buffer = new byte[PayloadBytes];
        for (int i = 0; i <= Rounds; i++)
        {
            await stream.ReadExactlyAsync(buffer, cancellationToken);
            await stream.WriteAsync(buffer, cancellationToken);
        }
        if (await stream.ReadAsync(buffer.AsMemory(0, 1), cancellationToken) != 0)
            throw new InvalidOperationException("Unexpected trailing request data.");
        stream.CompleteWrites();
    }

    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("osx")]
    private static async Task<Measurements> MeasureAsync(QuicStream stream, Stopwatch connectWatch,
        CancellationToken cancellationToken)
    {
        byte[] payload = RandomNumberGenerator.GetBytes(PayloadBytes);
        byte[] received = new byte[PayloadBytes];
        double[] rtts = new double[Rounds];
        double firstEchoMs = 0;
        for (int i = 0; i <= Rounds; i++)
        {
            BinaryPrimitives.WriteInt32LittleEndian(payload, i);
            long start = Stopwatch.GetTimestamp();
            await stream.WriteAsync(payload, cancellationToken);
            await stream.ReadExactlyAsync(received, cancellationToken);
            double elapsedUs = Stopwatch.GetElapsedTime(start).TotalMicroseconds;
            if (!payload.AsSpan().SequenceEqual(received))
                throw new InvalidOperationException($"Echo {i} did not match the sent payload.");
            if (i == 0) firstEchoMs = connectWatch.Elapsed.TotalMilliseconds;
            else rtts[i - 1] = elapsedUs;
        }
        stream.CompleteWrites();
        if (await stream.ReadAsync(received.AsMemory(0, 1), cancellationToken) != 0)
            throw new InvalidOperationException("Unexpected trailing echo data.");
        Array.Sort(rtts);
        return new Measurements(Rounds + 1, PayloadBytes, firstEchoMs,
            rtts[(int)Math.Ceiling(Rounds * 0.50) - 1], rtts[(int)Math.Ceiling(Rounds * 0.95) - 1]);
    }

    private static bool MatchesPin(X509Certificate? certificate, byte[] expected) => certificate is not null
        && CryptographicOperations.FixedTimeEquals(certificate.GetCertHash(HashAlgorithmName.SHA256), expected);

    private static X509Certificate2 CreateIdentity(string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        if (!OperatingSystem.IsWindows())
            return certificate;

        byte[] pfx = certificate.Export(X509ContentType.Pfx);
        certificate.Dispose();
        var storage = X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable;
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(pfx, (string?)null, storage, null);
#else
        return new X509Certificate2(pfx, (string?)null, storage);
#endif
    }

    private sealed class Report
    {
        public string Status { get; set; } = "FAIL";
        public string? Reason { get; set; }
        public string Framework { get; } = RuntimeInformation.FrameworkDescription;
        public string Os { get; } = RuntimeInformation.OSDescription;
        public string Transport { get; } = "System.Net.Quic / native MsQuic";
        public string Scope { get; set; } = "Two local peers; mutually pinned certificates; reliable ordered stream; no NAT or relay test";
        public bool ConnectionSupported { get; set; }
        public bool ListenerSupported { get; set; }
        public bool UnreliableDatagramApi { get; set; }
        public bool UdpLoopbackAvailable { get; set; }
        public string? UdpError { get; set; }
        public Measurements? Measurements { get; set; }
    }

    private sealed record Measurements(int VerifiedEchoes, int PayloadBytes, double ConnectToFirstEchoMs,
        double RttP50Us, double RttP95Us);
}
