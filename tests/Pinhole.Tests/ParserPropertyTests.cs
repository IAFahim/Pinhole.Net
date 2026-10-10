using System.Net;
using System.Security.Cryptography;
using FsCheck;
using FsCheck.Xunit;
using Pinhole.Blobs;
using Xunit;

namespace Pinhole.Tests;

/// <summary>Byte-level property fuzzing for the untrusted-byte parsers (#34): arbitrary
/// inputs must never throw outside the documented exception contract, valid encodings
/// must round-trip, and decoded values must satisfy domain invariants. FsCheck shrinks
/// counterexamples automatically — a failure prints the minimal input to preserve as a
/// regression seed.</summary>
public sealed class ParserPropertyTests
{
    // ---------- BlobWire.Frame: provider-sent bytes, all hostile ----------

    /// <summary>The span parser must return false, never throw — every rejection path is
    /// a length check, so a crash here means a bounds bug a peer could weaponize.</summary>
    [Property(MaxTest = 500)]
    public void FrameTryParse_OnArbitraryBytes_NeverThrows(byte[]? data)
    {
        BlobWire.Frame.TryParse(data ?? [], out _);
    }

    [Property(MaxTest = 200)]
    public void FrameRoundTrip_Head(ulong stream, long totalBytes)
    {
        totalBytes &= long.MaxValue;
        long totalChunks = totalBytes / Blake3.ChunkSize + (totalBytes % Blake3.ChunkSize == 0 ? 0 : 1);
        Assert.True(BlobWire.Frame.TryParse(BlobWire.Head(stream, totalBytes, totalChunks), out BlobWire.Frame f));
        Assert.Equal(BlobWire.TypeHead, f.Type);
        Assert.Equal(stream, f.Stream);
        Assert.Equal(totalBytes, f.TotalBytes);
        Assert.Equal(totalChunks, f.TotalChunks);
    }

    [Property(MaxTest = 200)]
    public void HeadRejectsInconsistentChunkCounts(ulong stream, long totalBytes, long totalChunks)
    {
        totalBytes &= long.MaxValue;
        totalChunks &= long.MaxValue;
        long required = totalBytes / Blake3.ChunkSize + (totalBytes % Blake3.ChunkSize == 0 ? 0 : 1);
        if (totalChunks != required)
            Assert.False(BlobWire.Frame.TryParse(BlobWire.Head(stream, totalBytes, totalChunks), out _));
    }

    [Property(MaxTest = 200)]
    public void FrameRoundTrip_Request(ulong stream, long startChunk, int count)
    {
        startChunk &= long.MaxValue;
        count = 1 + Math.Abs(count) % BlobWire.MaxRequestCount;
        Assert.True(BlobWire.Frame.TryParse(BlobWire.Request(stream, startChunk, count), out BlobWire.Frame f));
        Assert.Equal(BlobWire.TypeReq, f.Type);
        Assert.Equal(startChunk, f.StartChunk);
        Assert.Equal(count, f.Count);
    }

    [Property(MaxTest = 100)]
    public void FrameRoundTrip_Chunk(ulong stream, long index, byte[]? data)
    {
        index &= long.MaxValue;
        byte[] payload = (data ?? []).Length is > 0 and var n ? (data!)[..Math.Min(n, 1024)] : [1];
        byte[] cv = new byte[32];
        Array.Copy(payload, cv, Math.Min(payload.Length, 32));
        Assert.True(BlobWire.Frame.TryParse(BlobWire.Chunk(stream, index, cv, payload), out BlobWire.Frame f));
        Assert.Equal(BlobWire.TypeChunk, f.Type);
        Assert.Equal(index, f.Index);
        Assert.Equal(payload, f.ChunkData);
        Assert.Equal(cv, f.ChunkCv);
    }

    [Property(MaxTest = 200)]
    public void FrameRoundTrip_Hello(ulong stream)
    {
        byte[] session = RandomNumberGenerator.GetBytes(BlobWire.SessionIdLength);
        Assert.True(BlobWire.Frame.TryParse(BlobWire.Hello(stream, session), out BlobWire.Frame f));
        Assert.Equal(BlobWire.TypeHello, f.Type);
        Assert.Equal(session, f.SessionId);
        Assert.Equal(BlobWire.ProtocolVersion, f.Version);
    }

    // ---------- Manifest: the directory manifest is provider-sent bytes ----------

    /// <summary>The decode contract is FormatException-or-success — nothing else may
    /// escape, including on truncated mid-entry input.</summary>
    [Property(MaxTest = 500)]
    public void ManifestDecode_OnArbitraryBytes_OnlyFormatException(byte[]? data)
    {
        try
        {
            Manifest.Decode(data ?? []);
        }
        catch (FormatException)
        {
        }
    }

    /// <summary>Mutate a VALID manifest's size field to a negative value: the decoder
    /// must refuse it, not hand the client a negative total to sum.</summary>
    [Fact]
    public void ManifestDecode_NegativeSize_IsRejected()
    {
        var entries = new List<Manifest.Entry> { new("a.bin", 5, new byte[32]) };
        byte[] good = Manifest.Encode("d", entries);
        // Layout: u16 name-len, name, u32 count, then per entry: u16 path-len, path, i64 size.
        int sizeOffset = 2 + 1 + 4 + 2 + 5; // name="d"(1B), path="a.bin"(5B)
        BitConverter.TryWriteBytes(good.AsSpan(sizeOffset), -1L);
        Assert.Throws<FormatException>(() => Manifest.Decode(good));
    }

    /// <summary>Valid manifests always come back identical — entries, sizes, roots.</summary>
    [Property(MaxTest = 100)]
    public void ManifestEncode_ThenDecode_RoundTrips(int seed, int entryCount)
    {
        var rng = new Random(seed);
        var entries = new List<Manifest.Entry>();
        for (int i = 0, n = Math.Abs(entryCount) % 16; i < n; i++)
        {
            byte[] root = new byte[32];
            rng.NextBytes(root);
            entries.Add(new Manifest.Entry($"sub{i}/file{i}.bin", rng.NextInt64(long.MaxValue), root));
        }

        string name = "tree" + rng.Next(1000);
        (string decodedName, List<Manifest.Entry> decoded) = Manifest.Decode(Manifest.Encode(name, entries));
        Assert.Equal(name, decodedName);
        Assert.Equal(entries.Count, decoded.Count);
        for (int i = 0; i < entries.Count; i++)
        {
            Assert.Equal(entries[i].Path, decoded[i].Path);
            Assert.Equal(entries[i].Size, decoded[i].Size);
            Assert.Equal(entries[i].Root, decoded[i].Root);
            Assert.True(decoded[i].Size >= 0);
        }
    }

    // ---------- Tickets and connection strings: user-supplied text ----------

    /// <summary>TryParse is the no-throw contract — any exception here is a bug by
    /// definition (the strict Parse may only throw FormatException).</summary>
    [Property(MaxTest = 500)]
    public void BlobTicketTryParse_OnArbitraryStrings_NeverThrows(string? text)
    {
        BlobTicket.TryParse(text, out _);
    }

    [Property(MaxTest = 500)]
    public void ConnectionStringTryParse_OnArbitraryStrings_NeverThrows(string? text)
    {
        Pinhole.ConnectionString.TryParse(text ?? "", out _);
    }

    /// <summary>A valid ticket round-trips through text: parse(encode(t)) = t.</summary>
    [Property(MaxTest = 100)]
    public void BlobTicketRoundTrip_TextForm(int seed)
    {
        var rng = new Random(seed);
        var cs = new ConnectionString((ulong)rng.NextInt64(),
            [new PinholeCandidate(CandidateKind.Direct,
                new IPEndPoint(IPAddress.Loopback, rng.Next(1, 65535)))]);
        var ticket = new BlobTicket
        {
            Kind = BlobKind.File,
            Root = RandomNumberGenerator.GetBytes(32),
            ConnectionString = cs.ToString(),
            Name = "f.bin",
            PreSharedKey = RandomNumberGenerator.GetBytes(32),
        };
        string text = ticket.ToString();
        Assert.True(BlobTicket.TryParse(text, out BlobTicket? back));
        Assert.Equal(ticket.ToString(), back!.ToString());
    }
}
