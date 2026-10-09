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
        EnableEngineTrace(dir);
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
            DumpEngineTrace(_output);
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
        EnableEngineTrace(dir);
        Process? proc = null;
        try
        {
            string src = Path.Combine(dir, "asset.bin");
            byte[] expected = RandomNumberGenerator.GetBytes(192 * 1024);
            await File.WriteAllBytesAsync(src, expected);

            await using BlobServer server = await BlobServer.ServeAsync(src,
                new BlobServeOptions { NodeOptions = OfflineLoopback() });
            _output.WriteLine("current provider ticket: " + server.Ticket);

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
            DumpEngineTrace(_output);
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
        PatchReleaseHostRecvLoop(worktree);
        PatchReleaseHostSocket(worktree);
        PatchReleaseHostDispatchDiagnostics(worktree);

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

    /// <summary>The release host predates two .NET 10 macOS behaviors on dual-mode
    /// sockets. First: the runtime may hand back a native IPv4 sockaddr and shrink the
    /// reusable SocketAddress's Size, after which every later receive throws
    /// ArgumentOutOfRangeException. Second: because that sockaddr carries the IPv4
    /// family, every inline reply SendTo from the dual-mode IPv6 socket fails, so the
    /// host hears its peer but can never answer — Linux reports v4 senders already
    /// mapped, which is why only macOS interop dies. The shipped engine grew
    /// NormalizeReceivedAddress for exactly this. These patches restore capacity and the
    /// mapped form into the worktree copy — runtime-compatibility shims only: no wire
    /// byte, timing, or behavior of the release under test changes.</summary>
    private static void PatchReleaseHostRecvLoop(string worktree)
    {
        string path = Path.Combine(worktree, "src", "Pinhole", "NodeEngine.cs");
        PatchIfNeeded(path,
            marker: "addressCapacity",
            (text) =>
            {
                const string declaration = "var remote = new SocketAddress(AddressFamily.InterNetworkV6);";
                const string receive = "n = _udp.ReceiveFrom(buf, remote);";
                if (!text.Contains(declaration, StringComparison.Ordinal)
                    || !text.Contains(receive, StringComparison.Ordinal))
                {
                    return text;
                }
                text = text.Replace(declaration,
                    declaration + "\n        int addressCapacity = remote.Size; // interop shim: see InteropTests", StringComparison.Ordinal);
                text = text.Replace(receive,
                    "remote.Size = addressCapacity; // interop shim: restore capacity shrunk by a native v4 sockaddr\n                " + receive,
                    StringComparison.Ordinal);
                return text;
            });
    }

    /// <summary>Ships the mapped-sockaddr normalization (see above) into the worktree's
    /// socket wrapper, which is where every receive funnels. Idempotent and silently
    /// absent from trees whose anchor text moved.</summary>
    private static void PatchReleaseHostSocket(string worktree)
    {
        string path = Path.Combine(worktree, "src", "Pinhole", "UdpSocket.cs");
        PatchIfNeeded(path,
            marker: "NormalizeInteropRecv",
            (text) =>
            {
                const string anchor = "public int ReceiveFrom(Span<byte> buffer, SocketAddress from) => _udp.ReceiveFrom(buffer, SocketFlags.None, from);";
                if (!text.Contains(anchor, StringComparison.Ordinal))
                {
                    return text;
                }
                string shim = """
                    public int ReceiveFrom(Span<byte> buffer, SocketAddress from)
                    {
                        // interop shim NormalizeInteropRecv: see InteropTests. BSD may report a native
                        // IPv4 sockaddr (and shrink the buffer) on a dual-mode socket; the engine's
                        // reply path requires the v4-mapped form, as shipped NormalizeReceivedAddress.
                        int n = _udp.ReceiveFrom(buffer, SocketFlags.None, from);
                        if (from.Family == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            Span<byte> bytes = from.Buffer.Span;
                            ushort port = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]);
                            uint address = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]);
                            new System.Net.IPEndPoint(System.Net.IPAddress.Any.MapToIPv6(), 0).Serialize().Buffer.Span.CopyTo(bytes);
                            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(bytes[2..], port);
                            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes[20..], address);
                        }
                        return n;
                    }
                    """;
                return text.Replace(anchor, shim, StringComparison.Ordinal);
            });
    }

    /// <summary>The release's receive loop swallows every dispatch exception silently — a
    /// macOS-only reply failure would leave no trace at all. The shim prints the swallowed
    /// exception to stderr and still swallows it: identical behavior, one observable.</summary>
    private static void PatchReleaseHostDispatchDiagnostics(string worktree)
    {
        string path = Path.Combine(worktree, "src", "Pinhole", "NodeEngine.cs");
        PatchIfNeeded(path,
            marker: "interop dispatch swallowed",
            (text) =>
            {
                const string indent = "                ";
                const string block = indent + "try\n" + indent + "{\n"
                    + indent + "    Dispatch(buf.AsSpan(0, n), new Arrival(remote));\n"
                    + indent + "}\n"
                    + indent + "catch (Exception)\n"
                    + indent + "{\n"
                    + indent + "    // A malformed frame or a throwing user handler must not deafen the socket.\n"
                    + indent + "}";
                const string replaced = indent + "try\n" + indent + "{\n"
                    + indent + "    Dispatch(buf.AsSpan(0, n), new Arrival(remote));\n"
                    + indent + "}\n"
                    + indent + "catch (Exception dispatchEx) // interop shim: see InteropTests\n"
                    + indent + "{\n"
                    + indent + "    Console.Error.WriteLine(\"interop dispatch swallowed: \" + dispatchEx.GetType().Name + \": \" + dispatchEx.Message);\n"
                    + indent + "    // A malformed frame or a throwing user handler must not deafen the socket.\n"
                    + indent + "}";
                return text.Contains(block, StringComparison.Ordinal)
                    ? text.Replace(block, replaced, StringComparison.Ordinal)
                    : text;
            });
    }

    private static void PatchIfNeeded(string path, string marker, Func<string, string> apply)
    {
        if (!File.Exists(path)) return;
        string text = File.ReadAllText(path);
        if (text.Contains(marker, StringComparison.Ordinal)) return; // already patched
        File.WriteAllText(path, apply(text));
    }

    // ------------------------------------------------------------------ process plumbing

    /// <summary>The interop step runs these tests in a process of their own, so setting the
    /// engine's trace file here scopes tracing to exactly the connection under test and
    /// lands before the engine's static trace switch is first read. Without it a
    /// macOS-only silent stall has no observable side at all.</summary>
    private static string? _tracePath;

    private static void EnableEngineTrace(string dir)
    {
        _tracePath = Path.Combine(dir, "engine-trace.log");
        Environment.SetEnvironmentVariable("PINHOLE_TRACE", "1");
        Environment.SetEnvironmentVariable("PINHOLE_TRACE_FILE", _tracePath);
    }

    private static void DumpEngineTrace(ITestOutputHelper output)
    {
        try
        {
            if (_tracePath is not null && File.Exists(_tracePath))
            {
                output.WriteLine("current-side engine trace:\n" + File.ReadAllText(_tracePath));
            }
        }
        catch (IOException)
        {
        }
    }

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
