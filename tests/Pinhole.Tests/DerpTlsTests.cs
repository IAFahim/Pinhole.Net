using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Xunit;
using CertificateRequest = System.Security.Cryptography.X509Certificates.CertificateRequest;

namespace Pinhole.Tests;

public sealed class DerpTlsTests
{
    [Fact]
    public void MetadataCertificate_IsNotATrustAnchor_AndDoesNotSkipHostnameOrUsageChecks()
    {
        using var authority = new Authority();
        using var leaf = authority.Leaf();
        using var wrongUsage = authority.Leaf(serverUsage: false);
        var crypto = new BcTlsCrypto(new SecureRandom());
        TlsCertificate[] Chain(X509Certificate2 certificate) =>
        [
            crypto.CreateCertificate(certificate.RawData), crypto.CreateCertificate(authority.Root.RawData),
            crypto.CreateCertificate(Metadata()),
        ];

        using (var trusted = authority.Trust())
            DerpTls.ValidateCertificates("localhost", Chain(leaf), trusted);
        using (var trusted = authority.Trust())
            Assert.Throws<AuthenticationException>(() => DerpTls.ValidateCertificates("other.example", Chain(leaf), trusted));
        using (var trusted = authority.Trust())
            Assert.Throws<AuthenticationException>(() => DerpTls.ValidateCertificates("localhost", Chain(wrongUsage), trusted));
        Assert.Throws<AuthenticationException>(() => DerpTls.ValidateCertificates("localhost", Chain(leaf)));
        Assert.Throws<AuthenticationException>(() => DerpTls.ValidateCertificates("localhost", []));
    }

    [Theory]
    [MemberData(nameof(NativeServerProtocols))]
    public async Task ManagedTls_ConcurrentReadAndWrite_HandlesRecordsAndCanceledReads(SslProtocols version)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var authority = new Authority();
        using var leaf = authority.Leaf();
        using var trusted = authority.Trust();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        byte[] request = "request while the other side is reading"u8.ToArray();
        byte[] response = RandomNumberGenerator.GetBytes(32768);
        Task server = Task.Run(async () =>
        {
            using TcpClient socket = await listener.AcceptTcpClientAsync(deadline.Token);
            using var tls = new SslStream(socket.GetStream());
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = leaf, EnabledSslProtocols = version,
            }, deadline.Token);
            byte[] received = new byte[request.Length];
            await tls.ReadExactlyAsync(received, deadline.Token);
            Assert.Equal(request, received);
            await tls.WriteAsync(response, deadline.Token);
            await tls.ReadExactlyAsync(received, deadline.Token);
            Assert.Equal(request, received);
            await tls.WriteAsync(response.AsMemory(0, 1), deadline.Token);
        }, deadline.Token);

        Stream connection;
        try
        {
            connection = await DerpTls.ConnectAsync("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port,
                deadline.Token, trusted);
        }
        catch
        {

            await server;
            throw;
        }
        await using Stream client = connection;
        byte[] received = new byte[response.Length];
        Task pendingRead = client.ReadExactlyAsync(received, deadline.Token).AsTask();
        await client.WriteAsync(request, deadline.Token);
        await pendingRead;
        Assert.Equal(response, received);

        using (var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(100)))
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ReadAsync(received, cancel.Token).AsTask());
        await client.WriteAsync(request, deadline.Token);
        await client.ReadExactlyAsync(received.AsMemory(0, 1), deadline.Token);
        Assert.Equal(response[0], received[0]);
        await server;
    }

    public static IEnumerable<object[]> NativeServerProtocols
    {
        get
        {
            yield return [SslProtocols.Tls12];

            if (!OperatingSystem.IsMacOS()) yield return [SslProtocols.Tls13];
        }
    }

    private static byte[] Metadata()
    {
        var key = new Ed25519PrivateKeyParameters(new SecureRandom());
        var name = new X509Name("CN=derpkey0123456789abcdef");
        var certificate = new Org.BouncyCastle.X509.X509V3CertificateGenerator();
        certificate.SetSerialNumber(BigInteger.Two);
        certificate.SetIssuerDN(name);
        certificate.SetSubjectDN(name);
        certificate.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certificate.SetNotAfter(DateTime.UtcNow.AddDays(1));
        certificate.SetPublicKey(key.GeneratePublicKey());
        certificate.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        return certificate.Generate(new Asn1SignatureFactory("Ed25519", key)).GetEncoded();
    }

    private sealed class Authority : IDisposable
    {
        private readonly RSA _rootKey = RSA.Create(2048);
        internal X509Certificate2 Root { get; }

        internal Authority()
        {
            var request = new CertificateRequest("CN=Pinhole test authority", _rootKey,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            Root = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        }

        internal X509Certificate2 Leaf(bool serverUsage = true)
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("localhost");
            names.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(names.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid(serverUsage ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2") }, true));
            using var publicLeaf = request.Create(Root, DateTimeOffset.UtcNow.AddHours(-1),
                DateTimeOffset.UtcNow.AddHours(1), RandomNumberGenerator.GetBytes(16));
            using var withKey = publicLeaf.CopyWithPrivateKey(key);

            byte[] encoded = withKey.Export(X509ContentType.Pkcs12);
            try
            {
#if NET9_0_OR_GREATER
                return X509CertificateLoader.LoadPkcs12(encoded, null);
#else
                return new X509Certificate2(encoded);
#endif
            }
            finally { CryptographicOperations.ZeroMemory(encoded); }
        }

        internal X509Chain Trust()
        {
            var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(Root);
            chain.ChainPolicy.DisableCertificateDownloads = true;
            return chain;
        }

        public void Dispose() { Root.Dispose(); _rootKey.Dispose(); }
    }
}
