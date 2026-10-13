using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Pinhole;

// Windows SslStream can reject DERP's extra metadata certificate before exposing
// the normal HTTPS certificate for validation. Use the existing managed crypto
// dependency for the TLS record layer, retaining OS trust and hostname checks.
internal static class DerpTls
{
    internal static readonly HttpMessageInvoker Http = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseProxy = false,
        ConnectCallback = (context, ct) => ConnectAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port, ct),
    });

    internal static async ValueTask<Stream> ConnectAsync(string host, int port, CancellationToken ct,
        X509Chain? testChain = null)
    {
        var tcp = new TcpClient();
        try
        {
            await tcp.ConnectAsync(host, port, ct).ConfigureAwait(false);
            tcp.NoDelay = true;
            var protocol = new TlsClientProtocol(); // nonblocking TLS records
            protocol.Connect(new Client(host, testChain));
            var stream = new OwnedStream(protocol, tcp);
            await stream.HandshakeAsync(ct).ConfigureAwait(false);
            return stream;
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    internal static void ValidateCertificates(string host, TlsCertificate[] certificates, X509Chain? testChain = null)
    {
        if (certificates.Length == 0) throw new AuthenticationException("DERP TLS did not provide an HTTPS certificate");
        List<X509Certificate2> loaded = [];
        using var systemChain = testChain is null ? new X509Chain() : null;
        X509Chain chain = testChain ?? systemChain!;
        try
        {
            X509Certificate2 leaf = Load(certificates[0].GetEncoded());
            loaded.Add(leaf);
            if (!leaf.MatchesHostname(host, allowWildcards: true, allowCommonName: true))
                throw new AuthenticationException("DERP TLS HTTPS certificate does not match the relay hostname");
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1")); // TLS server authentication
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // matches ClientWebSocket's default
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
            // Only CA certificates help build the HTTPS chain. DERP appends an
            // unrelated self-signed Ed25519 non-CA certificate for key metadata;
            // it participates in the TLS transcript, never in the trust decision.
            var parser = new Org.BouncyCastle.X509.X509CertificateParser();
            foreach (TlsCertificate certificate in certificates.Skip(1))
            {
                byte[] encoded = certificate.GetEncoded();
                if (parser.ReadCertificate(encoded).GetBasicConstraints() < 0) continue;
                X509Certificate2 ca = Load(encoded);
                loaded.Add(ca);
                chain.ChainPolicy.ExtraStore.Add(ca);
            }
            if (!chain.Build(leaf))
                throw new AuthenticationException("DERP TLS HTTPS certificate chain is not trusted: "
                    + string.Join(", ", chain.ChainStatus.Select(status => status.Status.ToString())));
        }
        finally
        {
            foreach (X509Certificate2 certificate in loaded)
            {
                if (chain.ChainPolicy.ExtraStore.Contains(certificate)) chain.ChainPolicy.ExtraStore.Remove(certificate);
                certificate.Dispose();
            }
        }
    }

    private static X509Certificate2 Load(byte[] encoded) =>
        X509Certificate2.CreateFromPem(PemEncoding.WriteString("CERTIFICATE", encoded));

    private sealed class Client(string host, X509Chain? testChain) : DefaultTlsClient(new BcTlsCrypto(new SecureRandom())), TlsAuthentication
    {
        protected override ProtocolVersion[] GetSupportedVersions() => [ProtocolVersion.TLSv13, ProtocolVersion.TLSv12];
        protected override int[] GetSupportedCipherSuites() =>
        [
            CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ];
        protected override IList<ServerName> GetSniServerNames() => IPAddress.TryParse(host, out _)
            ? null! : [new ServerName(NameType.host_name, Encoding.ASCII.GetBytes(host))];
        public override TlsAuthentication GetAuthentication() => this;
        public void NotifyServerCertificate(TlsServerCertificate certificate) =>
            ValidateCertificates(host, certificate.Certificate.GetCertificateList(), testChain);
        public TlsCredentials? GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest request) => null;
    }

    // Feed the managed TLS record layer with async socket I/O. Idle relays do
    // not occupy worker threads. Serialize crypto state and output ordering,
    // while permitting one socket read and one write to run at the same time.
    private sealed class OwnedStream(TlsClientProtocol protocol, TcpClient tcp) : Stream
    {
        private readonly NetworkStream _network = tcp.GetStream();
        private readonly object _crypto = new();
        private readonly SemaphoreSlim _read = new(1, 1), _write = new(1, 1);
        private readonly byte[] _input = new byte[18432], _output = new byte[18432], _plaintext = new byte[16384];
        private int _disposed;
        public override bool CanRead => Volatile.Read(ref _disposed) == 0;
        public override bool CanWrite => CanRead;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => FlushAsync().GetAwaiter().GetResult();
        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
        public override void Write(byte[] buffer, int offset, int count) =>
            WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        internal async Task HandshakeAsync(CancellationToken ct)
        {
            await FlushAsync(ct).ConfigureAwait(false);
            while (!protocol.IsConnected)
            {
                if (!await ReadRecordsAsync(ct).ConfigureAwait(false))
                    throw new AuthenticationException("DERP TLS ended before authentication completed");
            }
        }

        private async Task<bool> ReadRecordsAsync(CancellationToken ct)
        {
            int count = await _network.ReadAsync(_input, ct).ConfigureAwait(false);
            lock (_crypto)
            {
                if (count == 0) protocol.CloseInput();
                else protocol.OfferInput(_input, 0, count);
            }
            await FlushAsync(ct).ConfigureAwait(false); // handshake replies, key updates, alerts
            return count != 0;
        }

        public override async Task FlushAsync(CancellationToken ct)
        {
            await _write.WaitAsync(ct).ConfigureAwait(false);
            try { await FlushRecordsAsync(ct).ConfigureAwait(false); }
            finally { _write.Release(); }
        }

        private async Task FlushRecordsAsync(CancellationToken ct)
        {
            while (true)
            {
                int count;
                lock (_crypto) count = protocol.ReadOutput(_output, 0, _output.Length);
                if (count == 0) return;
                await _network.WriteAsync(_output.AsMemory(0, count), ct).ConfigureAwait(false);
            }
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (buffer.Length == 0) return 0;
            await _read.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                while (true)
                {
                    lock (_crypto)
                    {
                        int count = protocol.ReadInput(_plaintext, 0, Math.Min(buffer.Length, _plaintext.Length));
                        if (count != 0)
                        {
                            _plaintext.AsMemory(0, count).CopyTo(buffer);
                            return count;
                        }
                        if (protocol.IsClosed) return 0;
                    }
                    if (!await ReadRecordsAsync(ct).ConfigureAwait(false)) return 0;
                }
            }
            finally { _read.Release(); }
        }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            await _write.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                // Bound the TLS output queue even when a caller supplies a large write.
                while (!buffer.IsEmpty)
                {
                    int count = Math.Min(buffer.Length, 16384);
                    lock (_crypto) protocol.WriteApplicationData(buffer.Span[..count]);
                    await FlushRecordsAsync(ct).ConfigureAwait(false);
                    buffer = buffer[count..];
                }
            }
            finally { _write.Release(); }
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing)
        {
            if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                tcp.Dispose();
                try { lock (_crypto) protocol.Close(); }
                catch (IOException) { }
                catch (ObjectDisposedException) { }
            }
            base.Dispose(disposing);
        }
    }
}
