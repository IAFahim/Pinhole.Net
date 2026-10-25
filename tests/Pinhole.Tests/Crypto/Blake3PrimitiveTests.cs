using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Pinhole.Crypto;
using Xunit;

namespace Pinhole.Tests.Crypto;

// R1 gates for the zero-allocation BLAKE3: the official vector suite (all three
// modes, both execution paths), differential against BouncyCastle, map/reduce
// agreement with the streaming core, and the 0-allocation-per-op property.
public sealed class Blake3PrimitiveTests
{
    private const string KeyString = "whats the Elvish word for friend";
    private const string ContextString = "BLAKE3 2019-12-27 16:29:52 test vectors context";

    private static readonly (int Length, string Hash, string Keyed, string Derived)[] OfficialTable =
    [
            (      0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26", "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"),
            (      1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213", "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b", "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"),
            (      2, "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63", "5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a", "1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6"),
            (      3, "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f", "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9", "440aba35cb006b61fc17c0529255de438efc06a8c9ebf3f2ddac3b5a86705797"),
            (      4, "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32", "7671dde590c95d5ac9616651ff5aa0a27bee5913a348e053b8aa9108917fe070", "f46085c8190d69022369ce1a18880e9b369c135eb93f3c63550d3e7630e91060"),
            (      5, "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2", "73ac69eecf286894d8102018a6fc729f4b1f4247d3703f69bdc6a5fe3e0c8461", "1f24eda69dbcb752847ec3ebb5dd42836d86e58500c7c98d906ecd82ed9ae47f"),
            (      6, "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844", "82d3199d0013035682cc7f2a399d4c212544376a839aa863a0f4c91220ca7a6d", "be96b30b37919fe4379dfbe752ae77b4f7e2ab92f7ff27435f76f2f065f6a5f4"),
            (      7, "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe", "af0a7ec382aedc0cfd626e49e7628bc7a353a4cb108855541a5651bf64fbb28a", "dc3b6485f9d94935329442916b0d059685ba815a1fa2a14107217453a7fc9f0e"),
            (      8, "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb", "be2f5495c61cba1bb348a34948c004045e3bd4dae8f0fe82bf44d0da245a0600", "2b166978cef14d9d438046c720519d8b1cad707e199746f1562d0c87fbd32940"),
            (     63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b", "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae", "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3"),
            (     64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98", "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6", "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e"),
            (     65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee", "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72", "51fd05c3c1cfbc8ed67d139ad76f5cf8236cd2acd26627a30c104dfd9d3ff8a8"),
            (    127, "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d", "c64200ae7dfaf35577ac5a9521c47863fb71514a3bcad18819218b818de85818", "c91c090ceee3a3ac81902da31838012625bbcd73fcb92e7d7e56f78deba4f0c3"),
            (    128, "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef", "b04fe15577457267ff3b6f3c947d93be581e7e3a4b018679125eaf86f6a628ec", "81720f34452f58a0120a58b6b4608384b5c51d11f39ce97161a0c0e442ca0225"),
            (    129, "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12", "d4a64dae6cdccbac1e5287f54f17c5f985105457c1a2ec1878ebd4b57e20d38f", "938d2d4435be30eafdbb2b7031f7857c98b04881227391dc40db3c7b21f41fc1"),
            (   1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11", "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e", "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5"),
            (   1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7", "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4", "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"),
            (   1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444", "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69", "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb"),
            (   2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a", "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd1", "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23"),
            (   2049, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030", "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5", "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf273"),
            (   3072, "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2", "044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df191770", "050df97f8c2ead654d9bb3ab8c9178edcd902a32f8495949feadcc1e0480c46b"),
            (   3073, "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3", "68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a", "72613c9ec9ff7e40f8f5c173784c532ad852e827dba2bf85b2ab4b76f7079081"),
            (   4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969", "befc660aea2f1718884cd8deb9902811d332f4fc4a38cf7c7300d597a081bfc0", "1e0d7f3db8c414c97c6307cbda6cd27ac3b030949da8e23be1a1a924ad2f25b9"),
            (   4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995", "00df940cd36bb9fa7cbbc3556744e0dbc8191401afe70520ba292ee3ca80abbc", "aca51029626b55fda7117b42a7c211f8c6e9ba4fe5b7a8ca922f34299500ead8"),
            (   5120, "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833", "2c493e48e9b9bf31e0553a22b23503c0a3388f035cece68eb438d22fa1943e20", "7a7acac8a02adcf3038d74cdd1d34527de8a0fcc0ee3399d1262397ce5817f60"),
            (   5121, "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff", "6ccf1c34753e7a044db80798ecd0782a8f76f33563accaddbfbb2e0ea4b2d024", "b07f01e518e702f7ccb44a267e9e112d403a7b3f4883a47ffbed4b48339b3c34"),
            (   6144, "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205", "3d6b6d21281d0ade5b2b016ae4034c5dec10ca7e475f90f76eac7138e9bc8f1d", "2a95beae63ddce523762355cf4b9c1d8f131465780a391286a5d01abb5683a15"),
            (   6145, "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f", "9ac301e9e39e45e3250a7e3b3df701aa0fb6889fbd80eeecf28dbc6300fbc539", "379bcc61d0051dd489f686c13de00d5b14c505245103dc040d9e4dd1facab8e5"),
            (   7168, "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a", "b42835e40e9d4a7f42ad8cc04f85a963a76e18198377ed84adddeaecacc6f3fc", "11c37a112765370c94a51415d0d651190c288566e295d505defdad895dae2237"),
            (   7169, "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e7817", "ed9b1a922c046fdb3d423ae34e143b05ca1bf28b710432857bf738bcedbfa511", "554b0a5efea9ef183f2f9b931b7497995d9eb26f5c5c6dad2b97d62fc5ac31d9"),
            (   8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63", "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a", "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d"),
            (   8193, "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b", "954a2a75420c8d6547e3ba5b98d963e6fa6491addc8c023189cc519821b4a1f5", "af1e0346e389b17c23200270a64aa4e1ead98c61695d917de7d5b00491c9b0f1"),
            (  16384, "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4", "9e9fc4eb7cf081ea7c47d1807790ed211bfec56aa25bb7037784c13c4b707b0d", "160e18b5878cd0df1c3af85eb25a0db5344d43a6fbd7a8ef4ed98d0714c3f7e1"),
            (  31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47", "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a419", "39772aef80e0ebe60596361e45b061e8f417429d529171b6764468c22928e28e"),
            ( 102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085", "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7", "4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6"),
    ];

    private static byte[] PatternInput(int length)
    {
        byte[] data = new byte[length];
        for (int i = 0; i < data.Length; i++)
        {
            data[i] = (byte)(i % 251);
        }

        return data;
    }

    [Fact]
    public void OfficialVectors_AllThreeModes_PassOnScalarAndVectorPaths()
    {
        byte[] key = Encoding.ASCII.GetBytes(KeyString);
        byte[] context = Encoding.ASCII.GetBytes(ContextString);
        foreach ((int length, string hash, string keyed, string derived) in OfficialTable)
        {
            byte[] data = PatternInput(length);
            foreach (bool bypass in new[] { true, false })
            {
                Blake3.SimdBypass = bypass;
                try
                {
                    byte[] digest = new byte[32];
                    Blake3.Hash(data, digest);
                    Assert.True(Convert.ToHexString(digest).Equals(hash, StringComparison.OrdinalIgnoreCase),
                        $"plain len={length} path={(bypass ? "scalar" : "simd")}");

                    Blake3.HashKeyed(key, data, digest);
                    Assert.True(Convert.ToHexString(digest).Equals(keyed, StringComparison.OrdinalIgnoreCase),
                        $"keyed len={length} path={(bypass ? "scalar" : "simd")}");

                    Blake3.HashDeriveKey(context, data, digest);
                    Assert.True(Convert.ToHexString(digest).Equals(derived, StringComparison.OrdinalIgnoreCase),
                        $"derive len={length} path={(bypass ? "scalar" : "simd")}");
                }
                finally
                {
                    Blake3.SimdBypass = false;
                }
            }
        }
    }

    [Fact]
    public void StreamingHasher_MatchesVectors_ForEveryModeAndBothPaths()
    {
        byte[] key = Encoding.ASCII.GetBytes(KeyString);
        byte[] context = Encoding.ASCII.GetBytes(ContextString);
        foreach ((int length, string hash, string keyed, string _) in OfficialTable)
        {
            if (length > 200_000)
            {
                continue;
            }

            byte[] data = PatternInput(length);
            foreach (bool bypass in new[] { true, false })
            {
                Blake3.SimdBypass = bypass;
                try
                {
                    var plain = new Blake3Hasher();
                    plain.Update(data);
                    Assert.True(Convert.ToHexString(plain.Finish()).Equals(hash, StringComparison.OrdinalIgnoreCase),
                        $"stream plain len={length} path={(bypass ? "scalar" : "simd")}");

                    var keyedHasher = new Blake3Hasher(key);
                    // feed in odd pieces to cross chunk and block boundaries
                    int pos = 0;
                    var rng = new Random(length);
                    while (pos < data.Length)
                    {
                        int take = Math.Min(rng.Next(1, 1500), data.Length - pos);
                        keyedHasher.Update(data.AsSpan(pos, take));
                        pos += take;
                    }

                    Assert.True(Convert.ToHexString(keyedHasher.Finish()).Equals(keyed, StringComparison.OrdinalIgnoreCase),
                        $"stream keyed len={length} path={(bypass ? "scalar" : "simd")}");

                    var derived = Blake3Hasher.ForDeriveKey(context);
                    derived.Update(data);
                    Assert.Equal(Blake3.HashDeriveKey(context, data), derived.Finish());
                }
                finally
                {
                    Blake3.SimdBypass = false;
                }
            }
        }
    }

    public static IEnumerable<object[]> BatchSpanningLengths() => new[]
    {
        0, 1, 63, 64, 65, 1023, 1024, 1025, 2048, 4095, 4096, 4097,
        65_535, 65_536, 65_537, 66_560, 66_561, 131_072, 131_073, 132_096, 197_121,
    }.Select(length => new object[] { length });

    [Theory]
    [MemberData(nameof(BatchSpanningLengths))]
    public void StreamingSplits_AcrossBatchAndChunkBoundaries_MatchOneShot(int length)
    {
        byte[] data = RandomNumberGenerator.GetBytes(length);
        byte[] expected = Blake3.Hash(data);
        var rng = new Random(length);

        foreach (bool bypass in new[] { true, false })
        {
            Blake3.SimdBypass = bypass;
            try
            {
                var hasher = new Blake3Hasher();
                int pos = 0;
                while (pos < data.Length)
                {
                    // piece sizes straddle blocks (64), chunks (1024) and batches (64 KiB)
                    int take = Math.Min((int)(rng.NextInt64(1, 90_000)), data.Length - pos);
                    hasher.Update(data.AsSpan(pos, take));
                    pos += take;
                }

                Assert.Equal(expected, hasher.Finish());
                Assert.Equal(length, hasher.TotalBytes);
            }
            finally
            {
                Blake3.SimdBypass = false;
            }
        }
    }

    [Fact]
    public void ManySmallUpdates_MatchOneShot()
    {
        byte[] data = RandomNumberGenerator.GetBytes(150_000);
        var hasher = new Blake3Hasher();
        for (int i = 0; i < data.Length; i += 97)
        {
            hasher.Update(data.AsSpan(i, Math.Min(97, data.Length - i)));
        }

        Assert.Equal(Blake3.Hash(data), hasher.Finish());
    }

    [Fact]
    public void MapReduce_RootMatchesOneShot_ForEveryChunkCountShape()
    {
        int[] chunkCounts = [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65,
            96, 127, 128, 129, 200, 255, 256, 257, 511, 512, 513];
        int[] tails = [0, 1, 1023];
        foreach (bool bypass in new[] { true, false })
        {
            Blake3.SimdBypass = bypass;
            try
            {
                foreach (int chunks in chunkCounts)
                {
                    foreach (int tail in tails)
                    {
                        if (chunks == 1 && tail == 0)
                        {
                            continue; // empty input covered by the vectors
                        }

                        byte[] data = RandomNumberGenerator.GetBytes(chunks * 1024 + tail);
                        byte[] expected = Blake3.Hash(data);

                        uint[] cvs = new uint[(chunks + (tail > 0 ? 1 : 0)) * 8];
                        int full = Blake3.HashChunks(data, 0, cvs);
                        Assert.Equal(chunks, full);
                        int nodes = full;
                        if (tail > 0)
                        {
                            Blake3.HashChunk(data.AsSpan(chunks * 1024, tail), (ulong)chunks, root: false, cvs.AsSpan(full * 8));
                            nodes++;
                        }

                        while (nodes > 2)
                        {
                            nodes = Blake3.ReduceLevel(cvs, nodes);
                        }

                        // nodes >= 2 always holds here: single-chunk inputs were skipped
                        // above and any fuller input leaves at least the top pair.
                        Assert.True(nodes >= 2);
                        byte[] digest = new byte[32];
                        Blake3.RootFromTopPair(cvs.AsSpan(0, 8), cvs.AsSpan(8, 8), digest);

                        Assert.True(digest.AsSpan().SequenceEqual(expected),
                            $"map/reduce chunks={chunks} tail={tail} path={(bypass ? "scalar" : "simd")}");
                    }
                }
            }
            finally
            {
                Blake3.SimdBypass = false;
            }
        }
    }

    [Fact]
    public void HashChunks_IsSliceable_AndRespectsCapacity()
    {
        byte[] data = RandomNumberGenerator.GetBytes(300 * 1024 + 5);
        uint[] whole = new uint[300 * 8];
        Assert.Equal(300, Blake3.HashChunks(data, 0, whole));

        // slice the map step at an arbitrary offset: the counter is the chunk index
        uint[] secondHalf = new uint[149 * 8];
        Assert.Equal(149, Blake3.HashChunks(data.AsSpan(151 * 1024), 151, secondHalf));
        Assert.True(whole.AsSpan(151 * 8, 149 * 8).SequenceEqual(secondHalf));

        uint[] tiny = new uint[3 * 8];
        Assert.Equal(3, Blake3.HashChunks(data, 0, tiny)); // capacity-bound
    }

    [Fact]
    public void DifferentialAgainstBouncyCastle_AllModes_ManyLengths()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] context = RandomNumberGenerator.GetBytes(40);
        var lengths = new List<int>();
        for (int i = 0; i <= 2600; i += 37)
        {
            lengths.Add(i);
        }

        lengths.AddRange([1000, 1023, 1024, 1025, 2048, 4096, 4097, 8192, 16_384, 65_536, 131_073, 200_000]);
        foreach (int length in lengths)
        {
            byte[] data = RandomNumberGenerator.GetBytes(length);

            var plain = new Blake3Digest();
            plain.BlockUpdate(data, 0, data.Length);
            byte[] expected = new byte[32];
            plain.DoFinal(expected, 0);
            Assert.True(Blake3.Hash(data).AsSpan().SequenceEqual(expected), $"plain len={length}");

            var keyed = new Blake3Digest();
            keyed.Init(Blake3Parameters.Key(key));
            keyed.BlockUpdate(data, 0, data.Length);
            keyed.DoFinal(expected, 0);
            Assert.True(Blake3.HashKeyed(key, data).AsSpan().SequenceEqual(expected), $"keyed len={length}");

            var derived = new Blake3Digest();
            derived.Init(Blake3Parameters.Context(context));
            derived.BlockUpdate(data, 0, data.Length);
            derived.DoFinal(expected, 0);
            Assert.True(Blake3.HashDeriveKey(context, data).AsSpan().SequenceEqual(expected), $"derived len={length}");
        }
    }

    [Fact]
    public void ZeroAllocations_PerOp()
    {
        byte[] big = RandomNumberGenerator.GetBytes(256 * 1024);
        byte[] small = RandomNumberGenerator.GetBytes(999);
        byte[] digest = new byte[32];
        uint[] cvs = new uint[64 * 8];
        var hasher = new Blake3Hasher();
        Span<uint> block = stackalloc uint[16];
        Span<uint> output = stackalloc uint[16];
        Span<uint> cv = stackalloc uint[8];
        block.Fill(0x5A5A5A5Au);

        // warm every code path so tiering and first-touch costs are outside the window
        for (int i = 0; i < 3; i++)
        {
            Blake3.Hash(big, digest);
            Blake3.Hash(small, digest);
            Blake3.HashChunks(big, 0, cvs);
            Blake3.HashChunk(small, 0, false, cv);
            Blake3.Compress(cv, block, 7, 64, 0, output);
            hasher.Update(big);
            hasher.Finish(digest);
        }

        var fresh = new Blake3Hasher(); // construction cost is by design; ops below must be free
        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 5; i++)
        {
            Blake3.Hash(big, digest);
            Blake3.Hash(small, digest);
            Blake3.HashChunks(big, 0, cvs);
            Blake3.HashChunk(small, 0, false, cv);
            Blake3.Compress(cv, block, 7, 64, 0, output);
        }

        fresh.Update(big);
        fresh.Update(small);
        fresh.Finish(digest);
        long after = GC.GetAllocatedBytesForCurrentThread();
        Assert.Equal(before, after);
    }
}
