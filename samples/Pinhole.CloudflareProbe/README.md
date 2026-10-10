# Cloudflare TURN UDP probe

Runs two C# Pinhole peers through the real Cloudflare TURN service. Uses the
existing managed TURN implementation; no WebRTC stack or native library is added.

From the repository root, with .NET 8 or 10 and an authenticated Wrangler CLI:

```sh
dotnet run --project samples/Pinhole.CloudflareProbe -f net10.0
```

The probe checks that the process can create a UDP socket, uses `wrangler whoami
--json` and `wrangler auth token --json` to obtain account access in memory, creates
one temporary TURN key, and requests two credential pairs with a ten-minute TTL.
It deletes its own key at exit before reporting a live pass. It never deletes or
changes existing TURN keys. Account access must permit TURN key creation/deletion
([Calls Write](https://developers.cloudflare.com/api/resources/calls/subresources/turn/methods/create/));
a Workers-only login may lack that permission. With multiple accounts, select one
using `CLOUDFLARE_ACCOUNT_ID`. Set `WRANGLER_BIN` if Wrangler is outside `PATH`.

Alternatively, set `TURN_KEY_ID` and `TURN_KEY_API_TOKEN` to use an existing key.
That key is retained. These are backend credentials for Cloudflare's
[generate-ice-servers API](https://developers.cloudflare.com/realtime/turn/generate-credentials/),
and stay in this diagnostic process. The API-issued usernames and passwords are
the credentials supplied to Pinhole. `TurnRestCredentials.Issue` is for coturn
servers configured with a shared secret; it does not generate Cloudflare passwords.

An existing key can also be supplied in a private local JSON file with fields
`keyId` and `keyToken`. It is retained, and its secret never appears in command-line
arguments or diagnostic output:

```sh
dotnet run --project samples/Pinhole.CloudflareProbe -f net10.0 -- --turn-key /tmp/cloudflare-turn-key.json
```

A private file containing the API's `{"iceServers":[...]}` response also works:

```sh
dotnet run --project samples/Pinhole.CloudflareProbe -f net10.0 -- --ice-servers /tmp/ice-servers.json
```

Only `turn:turn.cloudflare.com:3478?transport=udp` and the documented UDP port 443
alternative are accepted. The first matching URI in the response is selected.
Credentials, full connection strings, account tokens and API error bodies are
never printed. Wrangler logs are captured in a private temporary directory and
removed after each command.

The live checks are:

1. Two RFC 5766 allocations, mutual permissions, and four byte-matching TURN
   round trips. An authentication or permission error is reported at its stage.
2. Two Pinhole nodes with Cloudflare as their only relay. Direct UDP, direct TCP,
   iroh, LAN discovery and signed discovery publication are disabled. Invitations
   contain only Cloudflare TURN candidates and retain their pinned public keys.
   Both invitations are exchanged in memory before both nodes dial; TURN receive
   permissions require each peer's allocated data IP. Cloudflare can assign
   different data IPs even to two peers on the same computer. A one-way invitation
   alone does not supply this information to the listener.
3. One encrypted connection, with both endpoints on `PathKind.Relay`, carrying
   48 byte-matching round trips in each direction. Each round trip may retry up to
   three times; `sendAttempts` records every application send, including retries.

The process deadline is 120 seconds, plus at most 15 seconds for owned-key cleanup.
The payload volume without retries is under 50 KiB; service traffic also includes
handshakes, permissions and maintenance. Usage counts toward the account's
[Realtime allowance](https://developers.cloudflare.com/realtime/sfu/platform/pricing/).

The final JSON reports `status`, `stage`, and `relayTested`. Exit codes are 0 for
success, 1 for a failed check, and 3 for an environment/account blocker. A live pass
requires `stage=encrypted_relay` and `relayTested=true`. These auxiliary commands
explicitly report `relayTested=false`:

```sh
dotnet run --project samples/Pinhole.CloudflareProbe -f net10.0 -- --auth-check
dotnet run --project samples/Pinhole.CloudflareProbe -f net10.0 -- --validate-ice /tmp/ice-servers.json
```

This tests the real relay using two peers on one computer. Physical NAT traversal,
phone radio handoffs and a Worker-hosted short-code directory are separate checks.
The library's current Host/Join directory uses UDP; an HTTP Worker needs an adapter.

Set `PINHOLE_CLOUDFLARE_DIAGNOSTICS=1` for progress stages and Boolean comparisons
of the control/data addresses. Diagnostic output contains no credentials, full
tickets or endpoint addresses.

See [the live results](../../docs/evidence/cloudflare-turn-2026-10-11/README.md)
for what has actually been verified.
