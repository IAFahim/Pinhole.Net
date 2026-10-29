using System.ComponentModel;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

internal static class TlsDiagnostics
{
    internal static async Task<int> RunAsync(IEnumerable<Uri> relays, string? output)
    {
        List<object> results = [];
        foreach (Uri relay in relays.Distinct().Append(new Uri("https://github.com/")))
        foreach (SslProtocols protocols in new[] { SslProtocols.None, SslProtocols.Tls12, SslProtocols.Tls13 })
        foreach (bool alpn in new[] { false, true })
        {
            bool validated = false;
            string? policyErrors = null;
            object[]? certificates = null;
            string[]? chainStatus = null;
            string? negotiated = null, cipher = null, remote = null;
            object[]? errors = null;
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            using var tcp = new TcpClient();
            try
            {
                await tcp.ConnectAsync(relay.Host, relay.Port, deadline.Token);
                remote = tcp.Client.RemoteEndPoint?.ToString();
                using var tls = new SslStream(tcp.GetStream(), false, (_, certificate, chain, validationErrors) =>
                {
                    validated = true;
                    policyErrors = validationErrors.ToString();
                    certificates = chain?.ChainElements.Cast<X509ChainElement>().Select(element => (object)new
                    {
                        subject = element.Certificate.Subject,
                        issuer = element.Certificate.Issuer,
                        signatureAlgorithm = element.Certificate.SignatureAlgorithm.Value,
                        publicKeyAlgorithm = element.Certificate.PublicKey.Oid.Value,
                        sha256 = element.Certificate.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256),
                    }).ToArray();
                    chainStatus = chain?.ChainStatus.Select(status => status.Status.ToString()).ToArray();
                    return validationErrors == SslPolicyErrors.None;
                });
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = relay.Host,
                    EnabledSslProtocols = protocols,
                    ApplicationProtocols = alpn ? [SslApplicationProtocol.Http11] : null,
                }, deadline.Token);
                negotiated = tls.SslProtocol.ToString();
                cipher = tls.NegotiatedCipherSuite.ToString();
            }
            catch (Exception error)
            {
                List<object> causes = [];
                for (Exception? current = error; current is not null; current = current.InnerException)
                    causes.Add(new
                    {
                        type = current.GetType().Name, message = current.Message,
                        hresult = $"0x{current.HResult:X8}",
                        nativeError = current is Win32Exception native ? $"0x{native.NativeErrorCode:X8}" : null,
                    });
                errors = causes.ToArray();
            }
            results.Add(new
            {
                host = relay.Host, requestedProtocols = protocols.ToString(), alpn = alpn ? "http/1.1" : "none",
                status = errors is null ? "PASS" : "FAIL", remote, negotiated, cipher,
                certificateValidationReached = validated, policyErrors, certificates, chainStatus, errors,
            });
            Console.WriteLine($"TLS {(errors is null ? "PASS" : "FAIL")} {relay.Host} {protocols} ALPN={(alpn ? "http/1.1" : "none")} certificateValidation={validated}");
        }
        string report = JsonSerializer.Serialize(new
        {
            capturedAtUtc = DateTimeOffset.UtcNow, framework = RuntimeInformation.FrameworkDescription,
            os = RuntimeInformation.OSDescription,
            scope = "OS TLS only; normal certificate and hostname validation; no WebSocket/DERP authentication or peer connection",
            results,
        }, new JsonSerializerOptions { WriteIndented = true });
        if (output is null) Console.WriteLine(report);
        else
        {
            string path = Path.GetFullPath(output);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllTextAsync(path, report + Environment.NewLine);
        }
        return 0;
    }
}
