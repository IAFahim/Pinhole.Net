using System.Diagnostics;
using System.Net.Sockets;
using System.Text.Json;

namespace Pinhole.CloudflareProbe;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        string stage = "arguments";
        var watch = Stopwatch.StartNew();
        try
        {
            if (args is ["--help"])
            {
                Console.WriteLine("Cloudflare UDP relay probe (.NET 8/10)\n" +
                    "  no arguments: use Wrangler login and a temporary TURN key\n" +
                    "  --ice-servers FILE: use Cloudflare's credential response\n" +
                    "  --turn-key FILE: use a private {keyId,keyToken} JSON file\n" +
                    "  --validate-ice FILE: validate that response without network access\n" +
                    "  --auth-check: check Wrangler account access only\n" +
                    "  --worker URL [--direct|--tcp|--relay]: pair by code through a deployed Worker\n" +
                    "Environment: WRANGLER_BIN, CLOUDFLARE_ACCOUNT_ID, or TURN_KEY_ID + TURN_KEY_API_TOKEN");
                return 0;
            }

            bool validate = args is ["--validate-ice", _];
            bool fromFile = validate || args is ["--ice-servers", _];
            bool fromKeyFile = args is ["--turn-key", _];
            bool authCheck = args is ["--auth-check"];
            bool workerProbe = args is ["--worker", _] or ["--worker", _, "--direct"] or ["--worker", _, "--tcp"] or ["--worker", _, "--relay"];
            if (args.Length != 0 && !fromFile && !fromKeyFile && !authCheck && !workerProbe)
                throw new ProbeFailure("FAIL", "INVALID_ARGUMENTS");

            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(120));
            void SetStage(string value)
            {
                stage = value;
                if (Environment.GetEnvironmentVariable("PINHOLE_CLOUDFLARE_DIAGNOSTICS") == "1")
                    Console.Error.WriteLine($"Cloudflare probe stage: {value}");
            }
            if (workerProbe)
            {
                string mode = args.Length == 3 ? args[2][2..] : "auto";
                var paired = await WorkerProbe.RunAsync(new Uri(args[1]), mode, SetStage, deadline.Token);
                Write(new { status = "PASS", stage = "worker_host_join", coordinator = args[1], mode,
                    paired.Encrypted, paired.Path, paired.Transport, paired.InvitationHash,
                    paired.HostReadyMs, paired.JoinAndHandshakeMs, paired.RoundTripsEachDirection,
                    paired.SendAttempts, paired.RttP50Ms, paired.RttP95Ms, elapsedMs = watch.ElapsedMilliseconds });
                return 0;
            }
            if (authCheck)
            {
                await CloudflareAccount.CheckLoginAsync(SetStage, deadline.Token);
                Write(new { status = "PASS", stage = "account_access", relayTested = false });
                return 0;
            }

            CloudflareCredentials? credentials = null;
            if (fromFile)
            {
                stage = "credential_file";
                credentials = CloudflareCredentials.Parse(
                    await File.ReadAllTextAsync(args[1], deadline.Token));
                if (validate)
                {
                    Write(new { status = "PASS", stage = "credential_validation", relayTested = false,
                        host = "turn.cloudflare.com", port = credentials.Port, transport = "udp" });
                    return 0;
                }
            }

            stage = "udp_socket";
            using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)) { }

            RelayResult result;
            if (credentials is not null)
            {
                result = await RelayProbe.RunAsync(credentials, credentials, SetStage, deadline.Token);
            }
            else
            {
                await using (var key = await CloudflareAccount.GetKeyAsync(SetStage, deadline.Token,
                    fromKeyFile ? args[1] : null))
                {
                    stage = "credential_issuance";
                    var pairs = await Task.WhenAll(key.IssueAsync(deadline.Token), key.IssueAsync(deadline.Token));
                    result = await RelayProbe.RunAsync(pairs[0], pairs[1], SetStage, deadline.Token);
                }
            }

            Write(new { status = "PASS", stage = "encrypted_relay", relayTested = true,
                encrypted = true, path = "Relay", provider = "Cloudflare", transport = "udp",
                result.RawRoundTrips, result.RoundTripsEachDirection, result.SendAttempts,
                elapsedMs = watch.ElapsedMilliseconds });
            return 0;
        }
        catch (Exception ex)
        {
            var socket = FindSocketException(ex);
            bool denied = socket is { NativeErrorCode: 1 or 13 } || socket?.SocketErrorCode == SocketError.AccessDenied;
            string status = ex is ProbeFailure failure ? failure.Status
                : denied || ex is HttpRequestException or UnauthorizedAccessException ? "BLOCKED" : "FAIL";
            string code = ex is ProbeFailure known ? known.Code
                : denied ? "NETWORK_PERMISSION_DENIED"
                : ex is JsonException ? stage == "turn_key_file" ? "INVALID_TURN_KEY_JSON" : "INVALID_CREDENTIAL_JSON"
                : ex is OperationCanceledException ? "DEADLINE_EXCEEDED" : ex.GetType().Name;
            Write(new { status, stage, code, relayTested = false,
                httpStatus = (ex as HttpRequestException)?.StatusCode is { } http ? (int?)http : null,
                nativeError = socket?.NativeErrorCode, elapsedMs = watch.ElapsedMilliseconds });
            return status == "BLOCKED" ? 3 : 1;
        }
    }

    private static SocketException? FindSocketException(Exception? error)
    {
        for (; error is not null; error = error.InnerException)
            if (error is SocketException socket) return socket;
        return null;
    }

    private static void Write(object value) => Console.WriteLine(JsonSerializer.Serialize(value,
        new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));
}

internal sealed class ProbeFailure(string status, string code) : Exception(code)
{
    public string Status { get; } = status;
    public string Code { get; } = code;
}
