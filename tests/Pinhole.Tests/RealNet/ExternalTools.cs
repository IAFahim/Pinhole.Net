using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Xunit;

namespace Pinhole.Tests;

/// <summary>#26: launches REAL external network tools — the Patchbay CLI (a real iroh
/// relay + STUN server) and optionally a real TURN server (coturn) — and runs Pinhole's
/// production socket path against them on actual OS sockets. Tools are test-only
/// infrastructure, never production dependencies; public relay operators are never
/// touched. Binaries are found via the documented env vars (falling back to PATH); every
/// run writes a JSON report stating which socket implementation and relay protocol the
/// scenario exercised, and captured tool logs stay beside it as failure evidence.</summary>
internal static class ExternalTools
{
    public const string PatchbayEnv = "PATCHBAY_BIN";
    public const string CoturnEnv = "COTURN_BIN";

    /// <summary>An env-gated fact: runs when the tool is present, skips with instructions
    /// when it is not. xunit v2 has no runtime skip, so the Skip string is decided when
    /// the runner reflects over the attribute — honest in every runner UI either way.</summary>
    [AttributeUsage(AttributeTargets.Method)]
    public sealed class RealNetFactAttribute : FactAttribute
    {
        public RealNetFactAttribute(string envVar, string toolName)
        {
            if (FindTool(envVar, toolName) is null)
            {
                Skip = $"{toolName} not found: install it and/or set {envVar} to its path (docs/TESTING.md, issue #26)";
            }
        }
    }

    /// <summary>Env override first (an explicit path wins), then the bare name on PATH.</summary>
    public static string? FindTool(string envVar, string toolName)
    {
        string? env = Environment.GetEnvironmentVariable(envVar);
        if (!string.IsNullOrWhiteSpace(env) && File.Exists(env))
        {
            return env;
        }

        string? onPath = Environment.GetEnvironmentVariable("PATH")?
            .Split(Path.PathSeparator)
            .Select(Path.TrimEndingDirectorySeparator)
            .Select(dir => Path.Combine(dir, toolName))
            .FirstOrDefault(File.Exists);
        return onPath;
    }

    public static string Version(string bin)
    {
        using var probe = Process.Start(new ProcessStartInfo(bin, "--version")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        })!;
        string text = probe.StandardOutput.ReadToEnd() + probe.StandardError.ReadToEnd();
        probe.WaitForExit(TimeSpan.FromSeconds(10));
        return text.Split('\n', 2)[0].Trim();
    }

    /// <summary>One external process: stdout/stderr captured into the test's log directory
    /// (the failure evidence #26 requires), a readiness await on its TCP listener, and a
    /// whole-tree kill on dispose.</summary>
    public sealed class ExternalProcess : IAsyncDisposable
    {
        private readonly string _name;
        private readonly string _logDir;
        private Process? _proc;

        public ExternalProcess(string name, string logDir)
        {
            _name = name;
            _logDir = logDir;
        }

        public async Task StartAsync(string bin, string args, int? expectTcpPort, CancellationToken ct)
        {
            Directory.CreateDirectory(_logDir);
            string logPath = Path.Combine(_logDir, $"{_name}.log");
            _proc = Process.Start(new ProcessStartInfo(bin, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            }) ?? throw new InvalidOperationException($"could not start {bin}");
            _proc.OutputDataReceived += (_, e) => { if (e.Data is not null) File.AppendAllText(logPath, e.Data + "\n"); };
            _proc.ErrorDataReceived += (_, e) => { if (e.Data is not null) File.AppendAllText(logPath, e.Data + "\n"); };
            _proc.BeginOutputReadLine();
            _proc.BeginErrorReadLine();

            if (expectTcpPort is { } port)
            {
                await WaitPortAsync(port, ct);
            }
        }

        /// <summary>The port accepts a TCP connection — the tool's HTTP/WebSocket listener is up.</summary>
        private async Task WaitPortAsync(int port, CancellationToken ct)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(TimeSpan.FromSeconds(15));
            while (!deadline.Token.IsCancellationRequested)
            {
                try
                {
                    using var tcp = new TcpClient();
                    await tcp.ConnectAsync(IPAddress.Loopback, port, deadline.Token);
                    return;
                }
                catch (SocketException)
                {
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                await Task.Delay(150, deadline.Token);
            }

            throw new TimeoutException($"{_name} did not open port {port} within 15s; see {_logDir}");
        }

        public bool HasExited => _proc is null || _proc.HasExited;

        public void Kill()
        {
            try
            {
                _proc?.Kill(entireProcessTree: true);
            }
            catch (InvalidOperationException)
            {
            }
        }

        public ValueTask DisposeAsync()
        {
            Kill();
            _proc?.Dispose();
            return ValueTask.CompletedTask;
        }
    }

    public static async Task<ExternalProcess> StartAsync(
        string bin, string args, string logDir, string name, int? expectTcpPort, CancellationToken ct)
    {
        var handle = new ExternalProcess(name, logDir);
        try
        {
            await handle.StartAsync(bin, args, expectTcpPort, ct);
        }
        catch
        {
            await handle.DisposeAsync();
            throw;
        }

        return handle;
    }

    /// <summary>The reusable JSON run report: which tool and version served which scenario,
    /// over which socket implementation and relay protocol, and how long it took. One file
    /// per test, in the test's log directory under the system temp root.</summary>
    public static string LogDirFor(string scenario) =>
        Path.Combine(Path.GetTempPath(), "pinhole-realnet", scenario + "-" + Guid.NewGuid().ToString("N")[..8]);

    public static void WriteReport(string logDir, string scenario, string tool, string version,
        string socketImplementation, string relayProtocol, bool passed, double seconds, string? note = null)
    {
        Directory.CreateDirectory(logDir);
        var report = new Dictionary<string, object?>
        {
            ["scenario"] = scenario,
            ["tool"] = tool,
            ["toolVersion"] = version,
            ["socketImplementation"] = socketImplementation,
            ["relayProtocol"] = relayProtocol,
            ["result"] = passed ? "pass" : "fail",
            ["durationSeconds"] = Math.Round(seconds, 3),
            ["note"] = note,
            ["timestampUtc"] = DateTimeOffset.UtcNow,
        };
        File.WriteAllText(Path.Combine(logDir, "report.json"),
            JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
    }
}
