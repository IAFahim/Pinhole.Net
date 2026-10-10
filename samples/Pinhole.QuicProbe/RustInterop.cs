using System.Diagnostics;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

internal static partial class Probe
{
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    [SupportedOSPlatform("osx")]
    private static async Task<RustResult> RunRustEchoAsync(string executable, bool wrongServerPin,
        CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(executable);
        if (!File.Exists(fullPath)) throw new FileNotFoundException("Build the independent Rust fixture first.", fullPath);
        using var clientIdentity = CreateIdentity("quic-probe-client");
        string directory = Directory.CreateTempSubdirectory("pinhole-quic-interop-").FullName;
        string clientCertificate = Path.Combine(directory, "client.der");
        using var server = new Process
        {
            StartInfo = new ProcessStartInfo(fullPath)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                ArgumentList = { clientCertificate },
            },
        };
        Task<string>? stderr = null;
        Task<string>? stdout = null;
        try
        {
            await File.WriteAllBytesAsync(clientCertificate, clientIdentity.RawData, cancellationToken);
            if (!server.Start()) throw new InvalidOperationException("Rust fixture did not start.");
            stderr = server.StandardError.ReadToEndAsync();
            string? line = await server.StandardOutput.ReadLineAsync(cancellationToken);
            if (line is null)
                throw new InvalidOperationException($"Rust fixture exited before readiness: {await stderr.WaitAsync(cancellationToken)}");
            if (line.Length > 8192) throw new InvalidOperationException("Oversized Rust readiness record.");
            using var readiness = JsonDocument.Parse(line);
            JsonElement ready = readiness.RootElement;
            if (ready.GetProperty("status").GetString() != "READY")
                throw new InvalidOperationException("Rust fixture was not ready.");
            IPEndPoint endpoint = IPEndPoint.Parse(ready.GetProperty("endpoint").GetString()!);
            if (!IPAddress.IsLoopback(endpoint.Address)) throw new InvalidOperationException("The fixture must listen on loopback.");
            byte[] serverCertificate = Convert.FromBase64String(ready.GetProperty("certificate").GetString()!);
            byte[] serverPin = SHA256.HashData(serverCertificate);
            if (wrongServerPin) serverPin[0] ^= 1;
            stdout = server.StandardOutput.ReadToEndAsync();
            int pinRejected = 0;
            var connectWatch = Stopwatch.StartNew();
            try
            {
                await using var client = await QuicConnection.ConnectAsync(new QuicClientConnectionOptions
                {
                    RemoteEndPoint = endpoint,
                    DefaultCloseErrorCode = 0,
                    DefaultStreamErrorCode = 1,
                    ClientAuthenticationOptions = new SslClientAuthenticationOptions
                    {
                        ApplicationProtocols = [Protocol],
                        EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13,
                        TargetHost = "quic-probe-server",
                        ClientCertificates = new X509CertificateCollection { clientIdentity },
                        RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                        {
                            bool matches = MatchesPin(certificate, serverPin);
                            if (!matches) Interlocked.Exchange(ref pinRejected, 1);
                            return matches;
                        },
                    },
                }, cancellationToken);
                if (wrongServerPin) throw new InvalidOperationException("Connection succeeded with an incorrect server pin.");
                if (client.NegotiatedApplicationProtocol != Protocol)
                    throw new InvalidOperationException("Unexpected ALPN from Rust peer.");
                await using var stream = await client.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken);
                Measurements measurements = await MeasureAsync(stream, connectWatch, cancellationToken);
                await client.CloseAsync(0, cancellationToken);
                await server.WaitForExitAsync(cancellationToken);
                using var verdict = JsonDocument.Parse(await stdout.WaitAsync(cancellationToken));
                JsonElement result = verdict.RootElement;
                if (server.ExitCode != 0 || result.GetProperty("status").GetString() != "PASS"
                    || result.GetProperty("verifiedEchoes").GetInt32() != Rounds + 1
                    || !result.GetProperty("clientCertificateVerified").GetBoolean())
                    throw new InvalidOperationException($"Rust fixture failed verification: {await stderr.WaitAsync(cancellationToken)}");
                return new RustResult(measurements, false);
            }
            catch (Exception error) when (wrongServerPin && Volatile.Read(ref pinRejected) == 1
                && error is QuicException or System.Security.Authentication.AuthenticationException)
            {
                return new RustResult(null, true);
            }
        }
        finally
        {
            // Only this owned child is retired; no process-name matching or stale tickets.
            try
            {
                if (server.Id != 0 && !server.HasExited) server.Kill(entireProcessTree: true);
                await server.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
                if (stderr is not null) await stderr.WaitAsync(TimeSpan.FromSeconds(5));
                if (stdout is not null) await stdout.WaitAsync(TimeSpan.FromSeconds(5));
            }
            catch (InvalidOperationException) { /* Process.Start may have failed. */ }
            Directory.Delete(directory, recursive: true);
        }
    }

    private sealed record RustResult(Measurements? Measurements, bool PinRejected);
}
