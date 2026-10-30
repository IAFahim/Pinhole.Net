namespace Pinhole.Fuzz;

public sealed record FuzzFinding(string Target, ulong Seed, int Iteration, string Lineage, string InputHex, string Detail);

public sealed class FuzzTarget
{
    public string Name { get; }

    public Func<IEnumerable<byte[]>> SeedCorpus { get; }

    public Action<byte[]> Invoke { get; }

    public Func<Exception, bool>? Tolerated { get; }

    public FuzzTarget(string name, Func<IEnumerable<byte[]>> seedCorpus, Action<byte[]> invoke, Func<Exception, bool>? tolerated = null)
    {
        Name = name;
        SeedCorpus = seedCorpus;
        Invoke = invoke;
        Tolerated = tolerated;
    }
}

public static class FuzzRegistry
{
    private static readonly Dictionary<string, FuzzTarget> Targets = new(StringComparer.Ordinal);

    public static void Register(FuzzTarget target) => Targets[target.Name] = target;

    public static FuzzTarget Get(string name) =>
        Targets.TryGetValue(name, out FuzzTarget? target)
            ? target
            : throw new ArgumentException($"unknown fuzz target '{name}'", nameof(name));

    public static IReadOnlyList<string> Names => Targets.Keys.OrderBy(name => name, StringComparer.Ordinal).ToArray();
}
