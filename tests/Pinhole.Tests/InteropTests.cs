using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using Pinhole;
using Pinhole.Blobs;
using Xunit;
using Xunit.Abstractions;

namespace Pinhole.Tests;

/// <summary>Issue #35: automated current-vs-previous-version wire interop. The last
/// release commit is checked out into a git worktree, the checked-in InteropHost
/// (tests/Pinhole.Tests/Interop/) is compiled against that tree, and the two trees
/// then meet over real loopback UDP — no test doubles, the actual old build.
///
/// What the wire claims today (docs/RELIABILITY.md):
///   - A v3 (endpoint-keyed) connection string is produced by ≥1.10 and refused by
///     anything older — old parsers reject the unknown flag explicitly.
///   - A v2 connection string (1.9.0's format) is still dialed by current nodes.
///   - Blob wire is v3 on both sides of this pair, so a current downloader against a
///     1.9.0 provider is expected to complete a verified transfer.
///
/// Auto-skips when the release commit is not reachable (shallow clones; CI should
/// fetch-depth:0 to run these) or git/dotnet is unavailable.</summary>
public sealed class InteropTests
{
    /// <summary>The previous release under test: "Release 1.9.0" (blob wire v3,
    /// connection strings v2). Bump to each release tag/commit as they land.</summary>
    private const string ReleaseRef = "3ef16ea";
    private const string ReleaseName = "1.9.0";

    private static readonly TimeSpan Budget = TimeSpan.FromMinutes(2);
    private readonly ITestOutputHelper _output;

    public InteropTests(ITestOutputHelper output) => _output = output;

    // ------------------------------------------------------------------ tests

    [InteropFact]
    public async Task CurrentDownloader_OldProvider_CompletesVerifiedTransfer()
    {
        string host = EnsureReleaseHost();
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-interop-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        Process? proc = null;
        try
        {
            string src = Path.Combine(dir, "asset.bin");
            byte[] expected = RandomNumberGenerator.GetBytes(300 * 1024);
            await File.WriteAllBytesAsync(src, expected);

            proc = StartHost(host, $"serve \"{src}\"");
            BlobTicket ticket = await ReadTicketAsync(proc);

            BlobDownloadResult result = await BlobClient.DownloadAsync(ticket,
                Path.Combine(dir, "out"),
                options: new BlobDownloadOptions { NodeOptions = OfflineLoopback() })
                .WaitAsync(Budget);

            byte[] actual = await File.ReadAllBytesAsync(result.Path);
            Assert.Equal(expected, actual);
        }
        finally
        {
            KillQuietly(proc);
            Directory.Delete(dir, true);
        }
    }

    [InteropFact]
    public async Task OldDownloader_CurrentProvider_V2Ticket_CompletesVerifiedTransfer()
    {
        // A current node with no endpoint identity (no seed, relays, or publication) still
        // produces v2 connection strings — which old clients consume. The whole stack
        // is then compatible: v2 conn string, node handshake pinned to the static key,
        // blob wire v3 on both sides.
        string host = EnsureReleaseHost();
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-interop-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        Process? proc = null;
        try
        {
            string src = Path.Combine(dir, "asset.bin");
            byte[] expected = RandomNumberGenerator.GetBytes(192 * 1024);
            await File.WriteAllBytesAsync(src, expected);

            await using BlobServer server = await BlobServer.ServeAsync(src,
                new BlobServeOptions { NodeOptions = OfflineLoopback() });

            proc = StartHost(host, $"download \"{server.Ticket}\" \"{Path.Combine(dir, "out")}\"");
            string stderr = await proc.StandardError.ReadToEndAsync().WaitAsync(Budget); // drain the pipe
            await proc.WaitForExitAsync().WaitAsync(Budget);
            _output.WriteLine("old host exit " + proc.ExitCode + ", stderr:\n" + stderr);

            Assert.Equal(0, proc.ExitCode);
            byte[] actual = await File.ReadAllBytesAsync(
                Path.Combine(dir, "out", Path.GetFileName(src)));
            Assert.Equal(expected, actual);
        }
        finally
        {
            KillQuietly(proc);
            Directory.Delete(dir, true);
        }
    }

    [InteropFact]
    public async Task OldDownloader_CurrentProvider_V3Ticket_RefusedCleanly()
    {
        // The intentional break: seeding the provider's identity produces a v3
        // (endpoint-keyed) connection string that the 1.9.0 parser rejects. Interop
        // here means the refusal is a clean parse failure, never a crash or silent
        // accept of a key the old peer cannot authenticate.
        string host = EnsureReleaseHost();
        string dir = Path.Combine(Path.GetTempPath(), "pinhole-interop-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        Process? proc = null;
        try
        {
            string src = Path.Combine(dir, "asset.bin");
            await File.WriteAllBytesAsync(src, RandomNumberGenerator.GetBytes(64 * 1024));

            await using BlobServer server = await BlobServer.ServeAsync(src,
                new BlobServeOptions
                {
                    NodeOptions = OfflineLoopback() with
                    {
                        IdentityKeySeed = RandomNumberGenerator.GetBytes(32),
                    },
                });

            proc = StartHost(host, $"download \"{server.Ticket}\" \"{Path.Combine(dir, "out")}\"");
            string stderr = await proc.StandardError.ReadToEndAsync().WaitAsync(Budget);
            await proc.WaitForExitAsync().WaitAsync(Budget);
            _output.WriteLine("old host exit " + proc.ExitCode + ", stderr:\n" + stderr);

            Assert.NotEqual(0, proc.ExitCode);
            Assert.Contains("FormatException", stderr);
        }
        finally
        {
            KillQuietly(proc);
            Directory.Delete(dir, true);
        }
    }

    // ------------------------------------------------------------------ worktree + build

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, ".git")))
        {
            dir = dir.Parent;
        }
        return dir?.FullName ?? throw new InvalidOperationException("repo root not found");
    }

    private static void Git(string args, string workdir, TimeSpan? budget = null)
    {
        using var p = Process.Start(new ProcessStartInfo("git", args)
        {
            WorkingDirectory = workdir,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        })!;
        p.WaitForExit(budget ?? TimeSpan.FromMinutes(1));
        if (p.ExitCode != 0)
        {
            throw new InvalidOperationException($"git {args}: {p.StandardError.ReadToEnd()}");
        }
    }

    /// <summary>Builds the release worktree + host once per machine; subsequent runs
    /// reuse <c>$TMPDIR/pinhole-interop/&lt;sha&gt;</c> via a marker file. Returns the
    /// host dll path.</summary>
    private static string EnsureReleaseHost()
    {
        string root = RepoRoot();
        string worktree = Path.Combine(Path.GetTempPath(), "pinhole-interop", ReleaseRef);
        string dll = Path.Combine(worktree, "bin", "Release", "net10.0", "InteropHost.dll");
        string marker = dll + ".built";
        if (File.Exists(marker))
        {
            return dll;
        }

        // Stale registrations from interrupted runs are harmless but noisy; prune first.
        Git("worktree prune", root);
        if (!Directory.Exists(Path.Combine(worktree, "src")))
        {
            Git($"worktree add --force \"{worktree}\" {ReleaseRef}", root, TimeSpan.FromMinutes(2));
        }

        string hostSrc = Path.Combine(root, "tests", "Pinhole.Tests", "Interop");
        File.Copy(Path.Combine(hostSrc, "InteropHost.cs"), Path.Combine(worktree, "InteropHost.cs"), true);
        File.Copy(Path.Combine(hostSrc, "InteropHost.csproj"), Path.Combine(worktree, "InteropHost.csproj"), true);

        using var build = Process.Start(new ProcessStartInfo("dotnet", $"build InteropHost.csproj -c Release")
        {
            WorkingDirectory = worktree,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        })!;
        if (!build.WaitForExit(TimeSpan.FromMinutes(5)) || build.ExitCode != 0)
        {
            throw new InvalidOperationException("release host build failed: " + build.StandardError.ReadToEnd());
        }
        File.WriteAllText(marker, ReleaseName);
        return dll;
    }

    // ------------------------------------------------------------------ process plumbing

    private Process StartHost(string dll, string args)
    {
        var p = Process.Start(new ProcessStartInfo("dotnet", $"\"{dll}\" {args}")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        })!;
        return p;
    }

    private async Task<BlobTicket> ReadTicketAsync(Process proc)
    {
        using var cts = new CancellationTokenSource(Budget);
        while (await proc.StandardOutput.ReadLineAsync(cts.Token) is { } line)
        {
            _output.WriteLine("host: " + line);
            if (line.StartsWith("TICKET ", StringComparison.Ordinal))
            {
                return BlobTicket.Parse(line[7..]);
            }
        }
        throw new InvalidOperationException("host exited before printing a ticket: "
            + await proc.StandardError.ReadToEndAsync(cts.Token));
    }

    private static PinholeOptions OfflineLoopback() => new()
    {
        Bind = new IPEndPoint(IPAddress.Loopback, 0),
        StunServers = [],
        Relays = [],
        IrohRelayUrls = [],
        PublishIrohAddress = false,
        EnableNetworkWatch = false,
        EnablePortMapping = false,
        EnableLanDiscovery = false,
        EnablePathValidation = false,
    };

    private static void KillQuietly(Process? p)
    {
        try { p?.Kill(entireProcessTree: true); } catch { }
    }

    /// <summary>Skips unless the release commit is reachable and git/dotnet exist —
    /// decided at discovery like SoakFact, so runners show a real Skip reason.</summary>
    private sealed class InteropFactAttribute : FactAttribute
    {
        public InteropFactAttribute()
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo("git", $"cat-file -e {ReleaseRef}^{{commit}}")
                {
                    WorkingDirectory = RepoRoot(),
                    RedirectStandardError = true,
                })!;
                if (!p.WaitForExit(TimeSpan.FromSeconds(10)) || p.ExitCode != 0)
                {
                    Skip = $"release commit {ReleaseRef} not reachable — run with full history (fetch-depth:0)";
                }
            }
            catch (Exception e)
            {
                Skip = "interop prerequisites unavailable: " + e.Message;
            }
        }
    }
}
