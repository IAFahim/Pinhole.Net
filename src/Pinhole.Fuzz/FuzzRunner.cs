using System.Diagnostics;
using System.Text;

namespace Pinhole.Fuzz;

public sealed record FuzzRunOptions(
    ulong Seed = 0,
    int Iterations = 50_000,
    int MaxInputBytes = 16_384,
    TimeSpan PerInputTimeout = default,
    TimeSpan TimeBudget = default,
    int MaxFindings = 8)
{
    public TimeSpan EffectiveTimeout => PerInputTimeout <= TimeSpan.Zero ? TimeSpan.FromSeconds(2) : PerInputTimeout;

    public bool HasBudget => TimeBudget > TimeSpan.Zero;
}

public static class FuzzRunner
{
    public static IReadOnlyList<FuzzFinding> Run(FuzzTarget target, FuzzRunOptions options)
    {
        byte[][] corpus = target.SeedCorpus().ToArray();
        if (corpus.Length == 0)
        {
            throw new InvalidOperationException($"target '{target.Name}' produced an empty seed corpus");
        }

        FuzzRng rng = new(options.Seed ^ Stamp(target.Name));
        Mutator mutator = new(rng);
        List<FuzzFinding> findings = [];
        Stopwatch watch = Stopwatch.StartNew();
        for (int iteration = 1; iteration <= options.Iterations && findings.Count < options.MaxFindings; iteration++)
        {
            if (options.HasBudget && watch.Elapsed >= options.TimeBudget)
            {
                break;
            }

            int corpusIndex = rng.NextInt(corpus.Length);
            byte[] current = (byte[])corpus[corpusIndex].Clone();
            StringBuilder lineage = new($"corpus#{corpusIndex}");
            int depth = 1 + rng.NextInt(4);
            for (int step = 0; step < depth; step++)
            {
                current = mutator.Apply(current, corpus, out string op);
                lineage.Append(" > ").Append(op);
            }

            if (current.Length > options.MaxInputBytes)
            {
                lineage.Append(" > clamp").Append(options.MaxInputBytes);
                current = current[..options.MaxInputBytes];
            }

            FuzzFinding? finding = TryInvoke(target, current, options, iteration, lineage.ToString());
            if (finding is not null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }

    public static IReadOnlyList<FuzzFinding> RunAll(FuzzRunOptions options, Action<string>? progress = null)
    {
        List<FuzzFinding> findings = [];
        foreach (string name in FuzzRegistry.Names)
        {
            progress?.Invoke(name);
            findings.AddRange(Run(FuzzRegistry.Get(name), options));
        }

        return findings;
    }

    public static IReadOnlyList<FuzzFinding> Replay(FuzzTarget target, string hex)
    {
        byte[] input = Convert.FromHexString(hex);
        try
        {
            target.Invoke(input);
            return [];
        }
        catch (Exception cause)
        {
            if (target.Tolerated?.Invoke(cause) == true)
            {
                return [];
            }

            return [new FuzzFinding(target.Name, 0, 0, "replay", hex, Describe(cause))];
        }
    }

    private static FuzzFinding? TryInvoke(FuzzTarget target, byte[] input, FuzzRunOptions options, int iteration, string lineage)
    {
        Task work = Task.Run(() => target.Invoke(input));
        try
        {
            if (!work.Wait(options.EffectiveTimeout))
            {
                return new FuzzFinding(target.Name, options.Seed, iteration, lineage, Convert.ToHexString(input),
                    $"per-input timeout after {options.EffectiveTimeout.TotalMilliseconds:F0}ms");
            }

            return null;
        }
        catch (AggregateException aggregate)
        {
            Exception cause = aggregate.InnerException!;
            if (target.Tolerated?.Invoke(cause) == true)
            {
                return null;
            }

            return new FuzzFinding(target.Name, options.Seed, iteration, lineage, Convert.ToHexString(input), Describe(cause));
        }
    }

    private static string Describe(Exception cause) =>
        $"{cause.GetType().FullName}: {cause.Message}\n{cause.StackTrace}";

    private static ulong Stamp(string name)
    {
        ulong hash = 14695981039346656037UL;
        foreach (char c in name)
        {
            hash ^= c;
            hash *= 1099511628211UL;
        }

        return hash;
    }
}
