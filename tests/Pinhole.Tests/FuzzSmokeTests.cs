using System.Net;
using Pinhole.Fuzz;
using Xunit;

namespace Pinhole.Tests;

public sealed class FuzzSmokeTests
{
    private const ulong FixedSeed = 0x5EEDUL;

    private const int IterationsPerTarget = 3000;

    private static int registered;

    public static TheoryData<string> TargetNames()
    {
        EnsureRegistered();
        TheoryData<string> names = [];
        foreach (string name in FuzzRegistry.Names)
        {
            names.Add(name);
        }

        return names;
    }

    [Theory]
    [MemberData(nameof(TargetNames))]
    public void FixedSeedCampaignAcrossEveryTarget_FindsNothing(string targetName)
    {
        EnsureRegistered();
        FuzzTarget target = FuzzRegistry.Get(targetName);
        IReadOnlyList<FuzzFinding> findings = FuzzRunner.Run(target, new FuzzRunOptions(Seed: FixedSeed, Iterations: IterationsPerTarget));
        Assert.True(findings.Count == 0, string.Join(Environment.NewLine, findings.Select(Format)));
    }

    [Fact]
    public void PlantedCrash_IsDetected_AndReproducesFromPrintedHex()
    {
        EnsureRegistered();
        FuzzTarget canary = new("canary", () => [[1, 2, 3]], input => throw new IndexOutOfRangeException("planted"));
        IReadOnlyList<FuzzFinding> findings = FuzzRunner.Run(canary, new FuzzRunOptions(Seed: 1, Iterations: 25, MaxFindings: 1));
        FuzzFinding finding = Assert.Single(findings);
        Assert.Contains("IndexOutOfRangeException", finding.Detail);
        Assert.NotEmpty(finding.InputHex);
        Assert.NotEmpty(FuzzRunner.Replay(canary, finding.InputHex));
    }

    private static string Format(FuzzFinding finding) =>
        $"{finding.Target} iteration={finding.Iteration} lineage={finding.Lineage} input={finding.InputHex} detail={finding.Detail}";

    private static void EnsureRegistered()
    {
        if (Interlocked.Exchange(ref registered, 1) == 0)
        {
            BuiltinTargets.RegisterAll();
            FuzzRegistry.Register(IrohDiscoveryTarget());
            FuzzRegistry.Register(TcpFrameTarget());
        }
    }

    private static FuzzTarget IrohDiscoveryTarget()
    {
        RelayIdentity identity = new(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray());
        IrohAddress address = new(
            Convert.ToHexString(identity.PublicKey),
            [new IPEndPoint(IPAddress.Parse("192.168.0.205"), 53317), new IPEndPoint(IPAddress.Parse("fd00::9"), 42424)],
            PinholeOptions.PublicIrohRelays)
        { UserData = "pinhole1:smoke" };
        byte[] payload = IrohDiscovery.CreatePayload(address, identity, 1_790_000_000UL);
        return new FuzzTarget(
            "iroh-discovery",
            () => [payload],
            input => IrohDiscovery.ParsePayload(identity.PublicKey, input, out _),
            ex => ex is InvalidDataException);
    }

    private static FuzzTarget TcpFrameTarget()
    {
        return new FuzzTarget("tcp-frame", TcpFrameSeeds, RunTcpFrame, ex => ex is IOException);
    }

    private static IEnumerable<byte[]> TcpFrameSeeds()
    {
        byte[] body = new byte[32];
        new Random(2024).NextBytes(body);
        byte[] packet = new byte[2 + body.Length];
        packet[1] = (byte)body.Length;
        body.CopyTo(packet, 2);
        byte[] minimal = new byte[15];
        minimal[1] = 13;
        return [packet, minimal];
    }

    private static void RunTcpFrame(byte[] input)
    {
        using MemoryStream stream = new(input);
        byte[] header = new byte[2];
        byte[] buffer = new byte[TcpTransport.MaxFrame];
        TcpFrameCodec.ReadAsync(stream, header, buffer, TimeSpan.FromSeconds(5), CancellationToken.None).AsTask().GetAwaiter().GetResult();
    }
}
