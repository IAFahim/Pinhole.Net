using System.Diagnostics;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace Pinhole.CloudflareProbe;

internal sealed record CloudflareCredentials(string Username, string Credential, int Port)
{
    public static CloudflareCredentials Parse(string json)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object
            || !document.RootElement.TryGetProperty("iceServers", out var servers) || servers.ValueKind != JsonValueKind.Array)
            throw new ProbeFailure("FAIL", "MISSING_ICE_SERVERS");
        foreach (var server in servers.EnumerateArray())
        {
            if (server.ValueKind != JsonValueKind.Object || !server.TryGetProperty("urls", out var urls)) continue;
            IEnumerable<string?> values = urls.ValueKind switch
            {
                JsonValueKind.String => [urls.GetString()],
                JsonValueKind.Array => urls.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()),
                _ => []
            };
            foreach (string? url in values)
            {
                // Select only documented Cloudflare UDP endpoints. A TCP/TLS URL or
                // another provider must never turn this into a false Cloudflare pass.
                int port = url?.ToLowerInvariant() switch
                {
                    "turn:turn.cloudflare.com:3478?transport=udp" => 3478,
                    "turn:turn.cloudflare.com:443?transport=udp" => 443,
                    _ => 0
                };
                if (port == 0) continue;
                if (!server.TryGetProperty("username", out var username) || username.ValueKind != JsonValueKind.String
                    || !server.TryGetProperty("credential", out var password) || password.ValueKind != JsonValueKind.String
                    || string.IsNullOrWhiteSpace(username.GetString()) || string.IsNullOrWhiteSpace(password.GetString()))
                    throw new ProbeFailure("FAIL", "MISSING_TURN_CREDENTIALS");
                return new(username.GetString()!, password.GetString()!, port);
            }
        }
        throw new ProbeFailure("FAIL", "NO_CLOUDFLARE_UDP_URL");
    }
}

internal sealed class CloudflareAccount : IAsyncDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(25) };
    private readonly string _keyId;
    private readonly string _keyToken;
    private readonly string? _deleteUrl;
    private readonly JsonElement _accountAuth;
    private readonly Action<string> _stage;

    private CloudflareAccount(string keyId, string keyToken, string? deleteUrl,
        JsonElement accountAuth, Action<string> stage)
        => (_keyId, _keyToken, _deleteUrl, _accountAuth, _stage) = (keyId, keyToken, deleteUrl, accountAuth, stage);

    public static async Task CheckLoginAsync(Action<string> stage, CancellationToken ct)
    {
        stage("wrangler_account_access");
        var login = await WranglerAsync(["whoami", "--json"], ct);
        if (!login.TryGetProperty("loggedIn", out var loggedIn) || loggedIn.ValueKind != JsonValueKind.True)
            throw new ProbeFailure("BLOCKED", "WRANGLER_AUTH_UNAVAILABLE");
    }

    public static async Task<CloudflareAccount> GetKeyAsync(Action<string> stage, CancellationToken ct,
        string? keyFile = null)
    {
        if (keyFile is not null)
        {
            stage("turn_key_file");
            using var document = JsonDocument.Parse(await File.ReadAllTextAsync(keyFile, ct));
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("keyId", out var id) || id.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("keyToken", out var token) || token.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(id.GetString()) || string.IsNullOrWhiteSpace(token.GetString()))
                throw new ProbeFailure("FAIL", "INCOMPLETE_TURN_KEY_CONFIGURATION");
            return new(id.GetString()!, token.GetString()!, null, default, stage);
        }

        string? keyId = Environment.GetEnvironmentVariable("TURN_KEY_ID");
        string? keyToken = Environment.GetEnvironmentVariable("TURN_KEY_API_TOKEN");
        if (!string.IsNullOrEmpty(keyId) && !string.IsNullOrEmpty(keyToken))
            return new(keyId, keyToken, null, default, stage);
        if (!string.IsNullOrEmpty(keyId) || !string.IsNullOrEmpty(keyToken))
            throw new ProbeFailure("FAIL", "INCOMPLETE_TURN_KEY_CONFIGURATION");

        stage("wrangler_account_access");
        var login = await WranglerAsync(["whoami", "--json"], ct);
        var accounts = login.GetProperty("accounts").EnumerateArray().ToArray();
        string? accountId = Environment.GetEnvironmentVariable("CLOUDFLARE_ACCOUNT_ID");
        accountId ??= accounts.Length == 1 ? accounts[0].GetProperty("id").GetString() : null;
        if (string.IsNullOrWhiteSpace(accountId))
            throw new ProbeFailure("BLOCKED", "ACCOUNT_SELECTION_REQUIRED");

        stage("wrangler_token");
        var auth = await WranglerAsync(["auth", "token", "--json"], ct);
        string url = $"https://api.cloudflare.com/client/v4/accounts/{Uri.EscapeDataString(accountId)}/calls/turn_keys";
        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = JsonContent.Create(new { name = $"pinhole-probe-{Guid.NewGuid():N}" })
        };
        SetAuth(request, auth);
        stage("temporary_turn_key");
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(25) };
        using var response = await http.SendAsync(request, ct);
        RequireSuccess(response);
        using var created = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        if (!created.RootElement.GetProperty("success").GetBoolean())
            throw new ProbeFailure("FAIL", "TURN_KEY_CREATION_REJECTED");
        var key = created.RootElement.GetProperty("result");
        keyId = key.GetProperty("uid").GetString()!;
        keyToken = key.GetProperty("key").GetString()!;
        return new(keyId, keyToken, $"{url}/{Uri.EscapeDataString(keyId)}", auth, stage);
    }

    public async Task<CloudflareCredentials> IssueAsync(CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post,
            $"https://rtc.live.cloudflare.com/v1/turn/keys/{Uri.EscapeDataString(_keyId)}/credentials/generate-ice-servers")
        {
            Content = JsonContent.Create(new { ttl = 600 })
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _keyToken);
        using var response = await _http.SendAsync(request, ct);
        RequireSuccess(response);
        return CloudflareCredentials.Parse(await response.Content.ReadAsStringAsync(ct));
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (_deleteUrl is null) return; // Caller-owned keys are never deleted.
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            using var request = new HttpRequestMessage(HttpMethod.Delete, _deleteUrl);
            SetAuth(request, _accountAuth);
            using var response = await _http.SendAsync(request, cleanup.Token);
            RequireSuccess(response);
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cleanup.Token));
            if (!body.RootElement.GetProperty("success").GetBoolean())
                throw new ProbeFailure("FAIL", "TURN_KEY_DELETION_REJECTED");
        }
        catch
        {
            _stage("temporary_key_cleanup");
            throw new ProbeFailure("FAIL", "TURN_KEY_CLEANUP_FAILED");
        }
        finally { _http.Dispose(); }
    }

    private static void SetAuth(HttpRequestMessage request, JsonElement auth)
    {
        if (auth.GetProperty("type").GetString() == "api_key")
        {
            request.Headers.Add("X-Auth-Key", auth.GetProperty("key").GetString());
            request.Headers.Add("X-Auth-Email", auth.GetProperty("email").GetString());
        }
        else request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auth.GetProperty("token").GetString());
    }

    private static void RequireSuccess(HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode)
            throw new ProbeFailure(response.StatusCode is System.Net.HttpStatusCode.Unauthorized
                or System.Net.HttpStatusCode.Forbidden ? "BLOCKED" : "FAIL", $"CLOUDFLARE_HTTP_{(int)response.StatusCode}");
    }

    private static async Task<JsonElement> WranglerAsync(string[] args, CancellationToken ct)
    {
        string temporary = Path.Combine(Path.GetTempPath(), $"pinhole-cloudflare-auth-{Guid.NewGuid():N}");
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(temporary);
        else Directory.CreateDirectory(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo(Environment.GetEnvironmentVariable("WRANGLER_BIN") ?? "wrangler")
                { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false }
            };
            foreach (string arg in args) process.StartInfo.ArgumentList.Add(arg);
            process.StartInfo.Environment["WRANGLER_SEND_METRICS"] = "false";
            process.StartInfo.Environment["WRANGLER_LOG_PATH"] = Path.Combine(temporary, "wrangler.log");
            process.StartInfo.Environment["CI"] = "true";
            process.Start();
            var stdout = process.StandardOutput.ReadToEndAsync(ct);
            var stderr = process.StandardError.ReadToEndAsync(ct);
            try { await process.WaitForExitAsync(ct); }
            catch
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(CancellationToken.None);
                throw;
            }
            string errors = await stderr;
            string output = await stdout;
            // Never echo raw CLI output: token/account commands contain sensitive data.
            if (process.ExitCode != 0)
                throw new ProbeFailure("BLOCKED",
                    (errors + output).Contains("Cloudflare auth server could not be reached", StringComparison.Ordinal)
                        ? "CLOUDFLARE_AUTH_SERVER_UNREACHABLE" : "WRANGLER_AUTH_UNAVAILABLE");
            using var document = JsonDocument.Parse(output);
            return document.RootElement.Clone();
        }
        finally { Directory.Delete(temporary, recursive: true); }
    }
}
