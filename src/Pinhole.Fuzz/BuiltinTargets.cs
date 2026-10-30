using System.Net;
using System.Text;
using Pinhole.Blobs;
using Pinhole.Wire;

namespace Pinhole.Fuzz;

public static class BuiltinTargets
{
    private const int KeyBytes = 32;

    private const int MlKemKeyBytes = 1184;

    private static readonly IPEndPoint StunOrigin = new(IPAddress.Parse("203.0.113.7"), 3478);

    private static readonly byte[] StunTxid = Enumerable.Range(0, 12).Select(i => (byte)(17 * i + 3)).ToArray();

    public static void RegisterAll()
    {
        FuzzRegistry.Register(new FuzzTarget("address-record", AddressRecordSeeds, RunAddressRecord));
        FuzzRegistry.Register(new FuzzTarget("blob-frame", BlobFrameSeeds, RunBlobFrame));
        FuzzRegistry.Register(new FuzzTarget("blob-manifest", ManifestSeeds, RunManifest));
        FuzzRegistry.Register(new FuzzTarget("blob-ticket", BlobTicketSeeds, RunBlobTicket, ex => ex is FormatException));
        FuzzRegistry.Register(new FuzzTarget("blob-ticket-wire", WireBlobTicketSeeds, RunWireBlobTicket));
        FuzzRegistry.Register(new FuzzTarget("connection-string", ConnectionStringSeeds, RunConnectionString, ex => ex is FormatException));
        FuzzRegistry.Register(new FuzzTarget("dns-message", DnsSeeds, RunDns));
        FuzzRegistry.Register(new FuzzTarget("stun-binding", StunSeeds, RunStun));
        FuzzRegistry.Register(new FuzzTarget("wire-connection-string", WireConnectionStringSeeds, RunWireConnectionString));
    }

    private static byte[] Text(string value) => Encoding.ASCII.GetBytes(value);

    private static void RunConnectionString(byte[] input)
    {
        Pinhole.ConnectionString parsed = Pinhole.ConnectionString.Parse(Encoding.Latin1.GetString(input));
        _ = parsed.ToString();
    }

    private static IEnumerable<byte[]> ConnectionStringSeeds()
    {
        IPEndPoint lan = new(IPAddress.Parse("192.168.0.187"), 53317);
        IPEndPoint six = new(IPAddress.Parse("fd00:1111:2222:3333:4444:5555:6666:1"), 42424);
        IPEndPoint turnServer = new(IPAddress.Parse("203.0.113.9"), 3478);
        byte[] staticKey = new byte[KeyBytes];
        staticKey[0] = 9;
        byte[] endpointKey = new byte[KeyBytes];
        byte[] knock = new byte[16];
        byte[] mlKemKey = new byte[MlKemKeyBytes];
        PinholeCandidate direct = new(CandidateKind.Direct, lan);
        PinholeCandidate reflexive = new(CandidateKind.Reflexive, six);
        PinholeCandidate relay = new(CandidateKind.Relay, lan, turnServer, "pinhole", "turn-secret");
        PinholeCandidate iroh = new(CandidateKind.IrohRelay, lan, RelayUrl: new Uri("https://use1-1.relay.iroh.network"), RelayKey: new byte[KeyBytes]);
        yield return Text(new Pinhole.ConnectionString(0x5EEDUL, [direct]).ToString());
        yield return Text(new Pinhole.ConnectionString(77, [direct, reflexive], NatHint.Cone, staticKey).ToString());
        yield return Text(new Pinhole.ConnectionString(88, [direct, relay], NatHint.Symmetric, staticKey, endpointKey).ToString());
        yield return Text(new Pinhole.ConnectionString(99, [direct, iroh], NatHint.Unknown, staticKey, null, knock).ToString());
        yield return Text(new Pinhole.ConnectionString(111, [direct, reflexive, relay, iroh], NatHint.Cone, staticKey, endpointKey, knock, mlKemKey).ToString());
    }

    private static void RunWireConnectionString(byte[] input) => ConnectionStringCodec.TryRead(input, out _, out _);

    private static IEnumerable<byte[]> WireConnectionStringSeeds()
    {
        IPEndPoint lan = new(IPAddress.Parse("192.168.0.205"), 53317);
        IPEndPoint six = new(IPAddress.Parse("fd00::9"), 42424);
        CandidateData direct = new(WireCandidateKind.Direct, lan, null, null, null, null, null);
        CandidateData reflexive = new(WireCandidateKind.Reflexive, six, null, null, null, null, null);
        CandidateData relay = new(WireCandidateKind.Relay, lan, new IPEndPoint(IPAddress.Parse("203.0.113.9"), 3478), "pinhole", "turn-secret", null, null);
        CandidateData derp = new(WireCandidateKind.DerpRelay, lan, null, null, null, "https://derp.example.com", new byte[KeyBytes]);
        yield return Body(new ConnectionStringData(7, WireNatHint.Unknown, [direct], null, null, null));
        yield return Body(new ConnectionStringData(8, WireNatHint.Cone, [direct, reflexive], new byte[KeyBytes], null, null));
        yield return Body(new ConnectionStringData(9, WireNatHint.Symmetric, [direct, relay], new byte[KeyBytes], new byte[KeyBytes], null));
        yield return Body(new ConnectionStringData(10, WireNatHint.Unknown, [direct, derp], new byte[KeyBytes], null, new byte[8]));

        static byte[] Body(in ConnectionStringData value)
        {
            byte[] buffer = new byte[ConnectionStringCodec.MaxBodyLength];
            return buffer[..ConnectionStringCodec.Write(value, buffer)];
        }
    }

    private static void RunBlobTicket(byte[] input)
    {
        BlobTicket parsed = BlobTicket.Parse(Encoding.Latin1.GetString(input));
        _ = parsed.ToString();
    }

    private static IEnumerable<byte[]> BlobTicketSeeds()
    {
        string cs = new Pinhole.ConnectionString(5, [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Parse("192.168.0.187"), 53317))]).ToString();
        yield return Text(new BlobTicket { Kind = BlobKind.File, Root = new byte[KeyBytes], ConnectionString = cs, Name = "photo.bin" }.ToString());
        yield return Text(new BlobTicket
        {
            Kind = BlobKind.Directory,
            Root = new byte[KeyBytes],
            ConnectionString = cs,
            Name = "dossier-" + new string('x', 200),
            PreSharedKey = new byte[KeyBytes],
        }.ToString());
    }

    private static void RunWireBlobTicket(byte[] input)
    {
        if (!BlobTicketCodec.TryRead(input, out BlobTicketValue value))
        {
            return;
        }

        byte[] buffer = new byte[BlobTicketCodec.MaxBinaryLength];
        BlobTicketCodec.Write(buffer, in value);
    }

    private static IEnumerable<byte[]> WireBlobTicketSeeds()
    {
        yield return Payload(new BlobTicketValue(WireBlobKind.File, new byte[KeyBytes], "pinhole1:AAAA", "photo.bin", null));
        yield return Payload(new BlobTicketValue(WireBlobKind.Directory, new byte[KeyBytes], "pinhole1:BBBB", "dossier", new byte[KeyBytes]));

        static byte[] Payload(in BlobTicketValue value)
        {
            byte[] buffer = new byte[BlobTicketCodec.MaxBinaryLength];
            return buffer[..BlobTicketCodec.Write(buffer, in value)];
        }
    }

    private static void RunManifest(byte[] input)
    {
        if (!ManifestCodec.TryRead(input, out ManifestValue value))
        {
            return;
        }

        byte[] buffer = new byte[input.Length + 64];
        ManifestCodec.Write(buffer, in value);
    }

    private static IEnumerable<byte[]> ManifestSeeds()
    {
        byte[] root = new byte[KeyBytes];
        yield return Payload(new ManifestValue("transfer", [new ManifestEntry("a.bin", 1024, root)]));
        yield return Payload(new ManifestValue("répertoire", new[]
        {
            new ManifestEntry("dir/b.bin", 1L << 20, root),
            new ManifestEntry("dir/c.bin", 0, root),
            new ManifestEntry("空", long.MaxValue, root),
        }));

        static byte[] Payload(in ManifestValue value)
        {
            byte[] buffer = new byte[4096];
            return buffer[..ManifestCodec.Write(buffer, in value)];
        }
    }

    private static void RunBlobFrame(byte[] input)
    {
        if (!BlobFrameCodec.TryParse(input, out BlobFrameView view))
        {
            return;
        }

        _ = view.Type;
        _ = view.Stream;
        _ = view.Version;
        _ = view.TotalBytes;
        _ = view.TotalChunks;
        _ = view.StartChunk;
        _ = view.Count;
        _ = view.Index;
        _ = view.SessionId.ToArray();
        _ = view.ProviderNonce.ToArray();
        _ = view.SealedHead.ToArray();
        _ = view.ChunkCv.ToArray();
        _ = view.ChunkData.ToArray();
        _ = view.SiblingCvs.ToArray();
        if (view.Type == BlobFrameCodec.TypeProof)
        {
            for (int i = 0; i < view.Count; i++)
            {
                _ = view.Sibling(i).ToArray();
            }
        }
    }

    private static IEnumerable<byte[]> BlobFrameSeeds()
    {
        byte[] scratch = new byte[BlobFrameCodec.ChunkMaxLength];
        byte[] sessionId = new byte[BlobFrameCodec.SessionIdLength];
        sessionId[0] = 5;
        byte[] hello = Copy(scratch, BlobFrameCodec.WriteHello(scratch, 0xABCDUL, sessionId));
        yield return hello;
        yield return hello[..BlobFrameCodec.HelloV1Length];
        yield return hello[..BlobFrameCodec.HelloV2Length];
        yield return Copy(scratch, BlobFrameCodec.WriteHello(scratch, 7UL, sessionId, BlobFrameCodec.CurrentVersion));
        yield return Copy(scratch, BlobFrameCodec.WriteWelcome(scratch, 7UL, sessionId, sessionId, new byte[BlobFrameCodec.SealedHeadLength]));
        yield return Copy(scratch, BlobFrameCodec.WriteBye(scratch, 7UL));
        yield return Copy(scratch, BlobFrameCodec.WriteHead(scratch, 7UL, 4096, 4));
        yield return Copy(scratch, BlobFrameCodec.WriteRequest(scratch, 7UL, 3, 16));
        yield return Copy(scratch, BlobFrameCodec.WriteChunk(scratch, 7UL, 3, new byte[KeyBytes], new byte[100]));
        yield return Copy(scratch, BlobFrameCodec.WriteProof(scratch, 7UL, 2, new byte[64]));

        static byte[] Copy(byte[] scratch, int length) => scratch[..length];
    }

    private static void RunDns(byte[] input)
    {
        if (!DnsWireCodec.TryReadMessage(input, out DnsMessage? message))
        {
            return;
        }

        _ = DnsWireCodec.AsksForService(input, "_pinhole._udp.local");
        foreach (DnsResourceRecord record in message!.Records)
        {
            if (record.Type == DnsWireCodec.TypePtr)
            {
                DnsWireCodec.TryReadPtrTarget(input, record, out _);
            }

            if (record.Type == DnsWireCodec.TypeSrv)
            {
                DnsWireCodec.TryReadSrv(input, record, out _);
            }

            if (record.Type == DnsWireCodec.TypeTxt)
            {
                DnsWireCodec.TryReadTxtEntries(record.Rdata, out _);
                DnsWireCodec.TryReadTxtText(record.Rdata, out _);
            }
        }
    }

    private static IEnumerable<byte[]> DnsSeeds()
    {
        yield return Query();
        yield return Response();

        static byte[] Query()
        {
            byte[] buffer = new byte[512];
            int written = DnsWireCodec.WriteHeader(buffer, new DnsHeader(0, 0x0000, 1, 0, 0, 0));
            written += DnsWireCodec.WritePtrQuestion(buffer[written..], "_pinhole._udp.local");
            return buffer[..written];
        }

        static byte[] Response()
        {
            byte[] buffer = new byte[1024];
            int written = DnsWireCodec.WriteHeader(buffer, new DnsHeader(0, 0x8000, 0, 3, 0, 1));
            written += DnsWireCodec.WritePtrRecord(buffer[written..], "_pinhole._udp.local", "host1._pinhole._udp.local", 60);
            written += DnsWireCodec.WriteSrvRecord(buffer[written..], "_pinhole._udp.local", "host1", "desktop.local", 42424, 60);
            written += DnsWireCodec.WriteTxtRecord(buffer[written..], "_pinhole._udp.local", "host1", [("v", "1"), ("pinhole", "wire")], 60);
            written += DnsWireCodec.WriteAddressRecord(buffer[written..], "host1._pinhole._udp.local", IPAddress.Loopback, 60);
            return buffer[..written];
        }
    }

    private static void RunStun(byte[] input)
    {
        StunCodec.TryReadBindingRequest(input, out _, out _);
        StunCodec.TryReadBindingResponse(input, StunOrigin, out _);
        if (StunCodec.TryReadMessage(input, out StunMessage? message))
        {
            foreach (StunAttribute attribute in message!.Attributes)
            {
                StunCodec.TryReadAddress(attribute.Value, message.TransactionId, xor: true, out _);
            }
        }
    }

    private static IEnumerable<byte[]> StunSeeds()
    {
        byte[] buffer = new byte[256];
        yield return Copy(buffer, StunCodec.WriteBindingRequest(buffer, StunTxid));
        yield return Copy(buffer, StunCodec.WriteBindingRequest(buffer, StunTxid, 2));
        yield return Copy(buffer, StunCodec.WriteBindingResponse(buffer, StunTxid,
            new IPEndPoint(IPAddress.Parse("192.168.0.205"), 51234), StunOrigin,
            new IPEndPoint(IPAddress.Parse("203.0.113.7"), 3479)));

        static byte[] Copy(byte[] buffer, int length) => buffer[..length];
    }

    private static void RunAddressRecord(byte[] input)
    {
        if (AddressRecordCodec.TryReadBody(input, out AddressRecordBody body, out _))
        {
            byte[] buffer = new byte[AddressRecordCodec.MaxEncodedLength];
            AddressRecordCodec.WriteBody(body, buffer);
        }

        AddressRecordCodec.TryReadSigned(input, out _, out _);
    }

    private static IEnumerable<byte[]> AddressRecordSeeds()
    {
        AddressRecordBody v1 = new(0x1234UL, new byte[KeyBytes], 7, 1_900_000_000L,
            [new IPEndPoint(IPAddress.Parse("192.168.0.205"), 53317), new IPEndPoint(IPAddress.Parse("fd00::9"), 42424)], []);
        AddressRecordBody v2 = v1 with
        {
            RelayedEndpoints = [new IPEndPoint(IPAddress.Parse("203.0.113.20"), 443)],
        };
        byte[] body = new byte[AddressRecordCodec.MaxEncodedLength];
        int written = AddressRecordCodec.WriteBody(v2, body);
        yield return body[..AddressRecordCodec.WriteBody(v1, body)];
        byte[] signed = new byte[written + AddressRecordCodec.SignatureLength];
        body.AsSpan(0, written).CopyTo(signed);
        for (int i = 0; i < AddressRecordCodec.SignatureLength; i++)
        {
            signed[written + i] = (byte)(i * 11);
        }

        yield return signed;
    }
}
