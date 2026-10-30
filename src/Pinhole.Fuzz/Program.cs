namespace Pinhole.Fuzz;

public static class Program
{
    public static int Main(string[] args)
    {
        string targetName = "all";
        ulong seed = 0;
        long iterations = 50_000;
        int seconds = 0;
        int maxInput = 16_384;
        string? hex = null;
        bool list = false;
        for (int i = 0; i < args.Length; i++)
        {
            string flag = args[i];
            try
            {
                switch (flag)
                {
                    case "--target":
                        targetName = Value(args, ref i);
                        break;
                    case "--seed":
                        seed = ulong.Parse(Value(args, ref i));
                        break;
                    case "--iterations":
                        iterations = long.Parse(Value(args, ref i));
                        break;
                    case "--seconds":
                        seconds = int.Parse(Value(args, ref i));
                        break;
                    case "--max-input":
                        maxInput = int.Parse(Value(args, ref i));
                        break;
                    case "--hex":
                        hex = Value(args, ref i);
                        break;
                    case "--list":
                        list = true;
                        break;
                    default:
                        return Usage($"unknown argument '{flag}'");
                }
            }
            catch (Exception ex) when (ex is FormatException or IndexOutOfRangeException or OverflowException)
            {
                return Usage($"bad value for '{flag}'");
            }
        }

        BuiltinTargets.RegisterAll();
        if (list)
        {
            foreach (string name in FuzzRegistry.Names)
            {
                Console.WriteLine(name);
            }

            return 0;
        }

        try
        {
            if (hex is not null)
            {
                return Replay(targetName, hex);
            }

            return Campaign(targetName, seed, iterations, seconds, maxInput);
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 2;
        }
    }

    private static int Campaign(string targetName, ulong seed, long iterations, int seconds, int maxInput)
    {
        FuzzRunOptions options = new(
            Seed: seed,
            Iterations: (int)Math.Clamp(iterations, 1, int.MaxValue),
            MaxInputBytes: Math.Max(1, maxInput),
            TimeBudget: seconds > 0 ? TimeSpan.FromSeconds(seconds) : TimeSpan.Zero);
        IReadOnlyList<string> selected = targetName == "all" ? FuzzRegistry.Names : [targetName];
        List<FuzzFinding> findings = [];
        foreach (string name in selected)
        {
            Console.WriteLine($"== target={name} seed={seed} iterations={options.Iterations}");
            foreach (FuzzFinding finding in FuzzRunner.Run(FuzzRegistry.Get(name), options))
            {
                findings.Add(finding);
                Print(finding);
            }
        }

        Console.WriteLine(findings.Count == 0
            ? $"campaign clean: {selected.Count} target(s), findings=0"
            : $"campaign found {findings.Count} finding(s) across {selected.Count} target(s)");
        return findings.Count == 0 ? 0 : 1;
    }

    private static int Replay(string targetName, string hex)
    {
        if (targetName == "all")
        {
            return Usage("--hex needs an explicit --target");
        }

        IReadOnlyList<FuzzFinding> findings = FuzzRunner.Replay(FuzzRegistry.Get(targetName), hex);
        foreach (FuzzFinding finding in findings)
        {
            Print(finding);
        }

        Console.WriteLine(findings.Count == 0 ? $"CLEAN target={targetName}" : $"FINDING target={targetName}");
        return findings.Count == 0 ? 0 : 1;
    }

    private static void Print(FuzzFinding finding) =>
        Console.WriteLine(
            $"FINDING target={finding.Target} seed={finding.Seed} iteration={finding.Iteration}\n"
            + $"  lineage={finding.Lineage}\n"
            + $"  input={finding.InputHex}\n"
            + $"  detail={finding.Detail}");

    private static string Value(string[] args, ref int i)
    {
        i++;
        return args[i];
    }

    private static int Usage(string problem)
    {
        Console.Error.WriteLine(problem);
        Console.Error.WriteLine("usage: Pinhole.Fuzz [--target all|<name>] [--seconds N] [--iterations N] [--seed N] [--max-input N] [--hex <hex>] [--list]");
        return 2;
    }
}
