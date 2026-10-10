using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
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
    // The release traces each packet. Exceed typical pipe capacities in both
    // directions so these transfers also guard against an undrained child pipe.
    private const int TransferBytes = 2 * 1024 * 1024;
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
        HostProcess? proc = null;
        try
        {
            string src = Path.Combine(dir, "asset.bin");
            byte[] expected = RandomNumberGenerator.GetBytes(TransferBytes);
            await File.WriteAllBytesAsync(src, expected);

            proc = StartHost(host, "serve", src);
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
            await StopHostAsync(proc);
            DumpEngineTrace(_output);
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
        HostProcess? proc = null;
        try
        {
            string src = Path.Combine(dir, "asset.bin");
            byte[] expected = RandomNumberGenerator.GetBytes(TransferBytes);
            await File.WriteAllBytesAsync(src, expected);

            await using BlobServer server = await BlobServer.ServeAsync(src,
                new BlobServeOptions { NodeOptions = OfflineLoopback() });
            _output.WriteLine("current provider ticket: " + server.Ticket);

            proc = StartHost(host, "download", server.Ticket.ToString(), Path.Combine(dir, "out"));
            await proc.Process.WaitForExitAsync().WaitAsync(Budget);
            string stderr = await proc.Error.WaitAsync(Budget);
            _output.WriteLine("old host exit " + proc.ExitCode + ", stderr:\n" + stderr);

            Assert.Equal(0, proc.ExitCode);
            byte[] actual = await File.ReadAllBytesAsync(
                Path.Combine(dir, "out", Path.GetFileName(src)));
            Assert.Equal(expected, actual);
        }
        finally
        {
            await StopHostAsync(proc);
            DumpEngineTrace(_output);
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
        HostProcess? proc = null;
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

            proc = StartHost(host, "download", server.Ticket.ToString(), Path.Combine(dir, "out"));
            await proc.Process.WaitForExitAsync().WaitAsync(Budget);
            string stderr = await proc.Error.WaitAsync(Budget);
            _output.WriteLine("old host exit " + proc.ExitCode + ", stderr:\n" + stderr);

            Assert.NotEqual(0, proc.ExitCode);
            Assert.Contains("FormatException", stderr);
        }
        finally
        {
            await StopHostAsync(proc);
            DumpEngineTrace(_output);
            Directory.Delete(dir, true);
        }
    }

    // ------------------------------------------------------------------ datagram interop

    /// <summary>#43: the current tree (TCP sidecar on by default) still speaks plain
    /// direct UDP datagrams with a 1.9.0 peer in both dial directions — the new
    /// transport changed nothing on the old wire, and old peers never see a TCP
    /// frame they cannot parse. Payloads stay within 1.9.0's 1176-byte send ceiling:
    /// the current tree's 1200-byte guarantee is a same-version property, and the
    /// old peer's Send API refuses anything larger even though its wire carries it.</summary>
    [InteropFact]
    public async Task CurrentDialer_OldEchoServer_ExchangesUdpDatagrams()
    {
        string host = EnsureReleaseHost();
        HostProcess? proc = null;
        try
        {
            proc = StartHost(host, "echo");
            string ticket = await proc.Ticket.WaitAsync(Budget)
                ?? throw new InvalidOperationException("echo host exited before printing a ticket");
            await using var dialer = await PinholeNode.BindAsync(OfflineLoopback());
            await using var conn = await dialer.ConnectAsync(ticket).WaitAsync(Budget);

            Assert.True(conn.IsEncrypted, "v2 pinned-key handshake must encrypt against a 1.9.0 peer");

            foreach (int size in new[] { 1, 64, 1176 })
            {
                byte[] payload = RandomNumberGenerator.GetBytes(size);
                conn.Send(payload);
                ReadOnlyMemory<byte>? echo = await conn.ReceiveAsync().AsTask().WaitAsync(Budget);
                Assert.NotNull(echo);
                Assert.Equal(payload, echo.Value.ToArray());
            }
            Assert.Equal(3, conn.Stats.DatagramsSent);
            // Path labels follow confirmed traffic; after real datagrams crossed, the
            // route the current tree selected must be direct UDP — not TCP, not relay.
            Assert.Equal(PathKind.Direct, conn.Path.Kind);
            Assert.Equal(DirectTransport.Udp, conn.Path.Transport);
        }
        finally
        {
            await StopHostAsync(proc);
        }
    }

    [InteropFact]
    public async Task OldDialer_CurrentEchoServer_ExchangesUdpDatagrams()
    {
        string host = EnsureReleaseHost();
        HostProcess? proc = null;
        try
        {
            await using var listener = await PinholeNode.BindAsync(OfflineLoopback());
            Task<PinholeConnection> accepted = listener.AcceptAsync();
            proc = StartHost(host, "dial", listener.ConnectionString);

            await using var conn = await accepted.WaitAsync(Budget);
            Assert.True(conn.IsEncrypted);

            foreach (int size in new[] { 1, 64, 1176 })
            {
                byte[] payload = RandomNumberGenerator.GetBytes(size);
                conn.Send(payload);
                ReadOnlyMemory<byte>? echo = await conn.ReceiveAsync().AsTask().WaitAsync(Budget);
                Assert.NotNull(echo);
                Assert.Equal(payload, echo.Value.ToArray());
            }
            Assert.Equal(PathKind.Direct, conn.Path.Kind);
            Assert.Equal(DirectTransport.Udp, conn.Path.Transport);
        }
        finally
        {
            await StopHostAsync(proc);
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

    private static string Git(string args, string workdir, TimeSpan? budget = null)
    {
        using var p = Process.Start(new ProcessStartInfo("git", args)
        {
            WorkingDirectory = workdir,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        })!;
        Task<string> stdout = p.StandardOutput.ReadToEndAsync();
        Task<string> stderr = p.StandardError.ReadToEndAsync();
        if (!p.WaitForExit(budget ?? TimeSpan.FromMinutes(1)))
        {
            KillQuietly(p);
            throw new TimeoutException($"git {args} did not finish within its budget");
        }
        if (p.ExitCode != 0)
        {
            throw new InvalidOperationException($"git {args}: {stderr.GetAwaiter().GetResult()}");
        }
        return stdout.GetAwaiter().GetResult();
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
        string hostSrc = Path.Combine(root, "tests", "Pinhole.Tests", "Interop");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(File.ReadAllBytes(Path.Combine(hostSrc, "InteropHost.cs")));
        hash.AppendData(File.ReadAllBytes(Path.Combine(hostSrc, "InteropHost.csproj")));
        hash.AppendData(File.ReadAllBytes(typeof(InteropTests).Assembly.Location));
        string fingerprint = ReleaseName + ":" + Convert.ToHexString(hash.GetHashAndReset());
        if (File.Exists(dll) && File.Exists(marker) && File.ReadAllText(marker) == fingerprint)
        {
            return dll;
        }

        if (!Directory.Exists(Path.Combine(worktree, "src")))
        {
            // Prune only when registering a new tree; cached trees need no git writes.
            Git("worktree prune", root);
            Git($"worktree add --force \"{worktree}\" {ReleaseRef}", root, TimeSpan.FromMinutes(2));
        }

        File.Copy(Path.Combine(hostSrc, "InteropHost.cs"), Path.Combine(worktree, "InteropHost.cs"), true);
        File.Copy(Path.Combine(hostSrc, "InteropHost.csproj"), Path.Combine(worktree, "InteropHost.csproj"), true);
        // Regenerate shims from the immutable release, rather than retaining an older
        // patch merely because its marker still appears in a cached source file.
        foreach (string file in new[] { "NodeEngine.cs", "UdpSocket.cs" })
            File.WriteAllText(Path.Combine(worktree, "src", "Pinhole", file),
                Git($"show {ReleaseRef}:src/Pinhole/{file}", root));
        PatchReleaseHostRecvLoop(worktree);
        PatchReleaseHostSocket(worktree);
        PatchReleaseHostDispatchDiagnostics(worktree);

        using var build = Process.Start(new ProcessStartInfo("dotnet", $"build InteropHost.csproj -c Release")
        {
            WorkingDirectory = worktree,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        })!;
        Task<string> buildOutput = build.StandardOutput.ReadToEndAsync();
        Task<string> buildError = build.StandardError.ReadToEndAsync();
        if (!build.WaitForExit(TimeSpan.FromMinutes(5)))
        {
            KillQuietly(build);
            throw new TimeoutException("release host build did not finish within five minutes");
        }
        if (build.ExitCode != 0)
            throw new InvalidOperationException("release host build failed: "
                + buildOutput.GetAwaiter().GetResult() + buildError.GetAwaiter().GetResult());
        File.WriteAllText(marker, fingerprint);
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
                            var template = new System.Net.IPEndPoint(System.Net.IPAddress.Any.MapToIPv6(), 0).Serialize();
                            template.Buffer.Span.CopyTo(bytes);
                            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(bytes[2..], port);
                            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(bytes[20..], address);
                            from.Size = template.Size;
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

    private static HostProcess StartHost(string dll, params string[] args)
    {
        var start = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add(dll);
        foreach (string arg in args) start.ArgumentList.Add(arg);
        return new HostProcess(Process.Start(start)!);
    }

    private async Task<BlobTicket> ReadTicketAsync(HostProcess proc)
    {
        if (await proc.Ticket.WaitAsync(Budget) is { } ticket)
        {
            _output.WriteLine("host: TICKET " + ticket);
            return BlobTicket.Parse(ticket);
        }
        throw new InvalidOperationException("host exited before printing a ticket: "
            + await proc.Error.WaitAsync(Budget));
    }

    private async Task StopHostAsync(HostProcess? proc)
    {
        if (proc is null) return;
        try
        {
            KillQuietly(proc.Process);
            await proc.Process.WaitForExitAsync().WaitAsync(TestBudget.Teardown);
            await Task.WhenAll(proc.Output, proc.Error).WaitAsync(TestBudget.Teardown);
            _output.WriteLine("old host stdout:\n" + await proc.Output);
            _output.WriteLine("old host stderr:\n" + await proc.Error);
        }
        finally
        {
            proc.Process.Dispose();
        }
    }

    // Both pipes must be consumed from launch until exit. The release logs each
    // received packet: an unread stdout fills the smaller Windows/BSD pipes and
    // blocks its receive thread, manufacturing an interoperability failure.
    private sealed class HostProcess
    {
        private const int CaptureLimit = 64 * 1024;
        private readonly TaskCompletionSource<string?> _ticket = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Process Process { get; }
        public int ExitCode => Process.ExitCode;
        public Task<string> Output { get; }
        public Task<string> Error { get; }
        public Task<string?> Ticket => _ticket.Task;

        public HostProcess(Process process)
        {
            Process = process;
            Output = DrainAsync(process.StandardOutput, captureTicket: true);
            Error = DrainAsync(process.StandardError, captureTicket: false);
        }

        private async Task<string> DrainAsync(StreamReader reader, bool captureTicket)
        {
            var captured = new StringBuilder();
            while (await reader.ReadLineAsync() is { } line)
            {
                if (captureTicket && line.StartsWith("TICKET ", StringComparison.Ordinal))
                    _ticket.TrySetResult(line[7..]);
                if (captured.Length < CaptureLimit)
                {
                    int count = Math.Min(line.Length, CaptureLimit - captured.Length);
                    captured.Append(line.AsSpan(0, count));
                    if (captured.Length < CaptureLimit) captured.AppendLine();
                }
            }
            if (captureTicket) _ticket.TrySetResult(null);
            if (captured.Length >= CaptureLimit) captured.AppendLine("\n[remaining output drained without capture]");
            return captured.ToString();
        }
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
        ReceiveBufferCapacity = 16, // the datagram interop cases use ReceiveAsync
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
