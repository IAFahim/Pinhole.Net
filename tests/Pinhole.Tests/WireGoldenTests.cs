using System.Net;
using Pinhole;
using Pinhole.Blobs;
using Xunit;

namespace Pinhole.Tests;

public sealed class WireGoldenTests
{
    private static byte[] Root(int start) => Enumerable.Range(start, 32).Select(i => (byte)i).ToArray();

    [Fact]
    public void Manifest_Encode_ExactLittleEndianBytes()
    {
        byte[] manifest = Manifest.Encode("pkg",
        [
            new Manifest.Entry("a.bin", 0x11223344, Root(0)),
            new Manifest.Entry("empty", 0, Root(0xE0)),
        ]);

        byte[] expected =
        [
            0x03, 0x00, (byte)'p', (byte)'k', (byte)'g',
            0x02, 0x00, 0x00, 0x00,
            0x05, 0x00, (byte)'a', (byte)'.', (byte)'b', (byte)'i', (byte)'n',
            0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00,
            .. Root(0),
            0x05, 0x00, (byte)'e', (byte)'m', (byte)'p', (byte)'t', (byte)'y',
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            .. Root(0xE0),
        ];
        Assert.Equal(expected, manifest);
    }

    [Fact]
    public void ConnectionString_Encode_PinsPeerIdLittleEndian()
    {
        var cs = new ConnectionString(0x1122334455667788,
            [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Parse("192.168.1.4"), 42123))],
            NatHint.Symmetric);

        Assert.Equal("pinhole1:AQCId2ZVRDMiEQIBBMCoAQSkiwE", cs.ToString());
    }

    [Fact]
    public void BlobTicket_Encode_GoldenString()
    {
        string csText = new ConnectionString(1,
            [new PinholeCandidate(CandidateKind.Direct, new IPEndPoint(IPAddress.Loopback, 5))]).ToString();
        var ticket = new BlobTicket
        {
            Kind = BlobKind.File,
            Root = Root(0),
            ConnectionString = csText,
            Name = "d",
            PreSharedKey = Root(0x40),
        };

        Assert.Equal(
            "pinholeblob1:AQIBZAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fQEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8kAHBpbmhvbGUxOkFRQUJBQUFBQUFBQUFBQUJCSDhBQUFFQUJRRQ",
            ticket.ToString());
    }

    [Fact]
    public void AddressRecord_EncodeSigned_GoldenBytes()
    {
        byte[] seed = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        RelayIdentity identity = new(EndpointIdentity.DeriveEndpointSeed(seed));
        var record = new AddressRecord
        {
            PeerId = 0x0102030405060708,
            EndpointKey = identity.PublicKey,
            Sequence = 0x8877665544332211,
            ExpiresAtUtc = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000),
            Endpoints = [new IPEndPoint(IPAddress.Parse("203.0.113.7"), 3478)],
        };

        Assert.Equal(
            "0108070605040302016106F86AA1C86018EB49133492B1E3B99FCCCF8CE782210631D35ED00462EDD8112233445566778800D2496B000000000104CB0071070D9658AF45AAF9905A1B79F91D6BFDF458F0D242195B253DA1122BE250F7FB720F03AC7A00A5B7E40B8073FBD2F049FB95764A5CCEFDEC23A053C2F679D512FB2A0D",
            Convert.ToHexString(record.EncodeSigned(identity)));
    }
}
