# Pinhole.Net

A connection library for .NET. The bottom layer — nothing else.

One job: **get a connection between two machines, then keep it open until the app closes it.**

- **Free infrastructure.** Google/Cloudflare STUN and n0's public iroh HTTPS relays by default; standard TURN servers can be added with your own credentials. Consumed as protocols from pure C#.
- **Router mappings, iroh-style.** PCP / NAT-PMP / UPnP port mapping is attempted at bind — a granted mapping is advertised as a candidate and hard home NATs become directly punchable. NAT classification (cone vs symmetric) is derived automatically from the STUN observations.
- **LAN IPv6 fallback by default.** Link-local candidates supplement routable addresses, with probes on each eligible local Wi-Fi/Ethernet interface. Mobile and tunnel interfaces are excluded from link-local probing.
- **Discovery enabled by default.** Nodes announce `_pinhole._udp.local` on the LAN and publish signed native iroh records with direct addresses and relay URLs. `DiscoverLanPeersAsync` finds nearby peers; `ConnectIrohAsync` resolves a shared endpoint ID. A `pinhole1:` connection string also carries the peer's keys and candidates, so it can be dialed without a discovery lookup.
- **Encrypted and authenticated, by default.** Every session is AES-256-GCM per frame over a triple-DH X25519 handshake; the answering key is pinned to the connection string, so a man in the middle kills the dial instead of intercepting it. No certificates, no downgrade window — a stripped handshake fails, it never falls back. `Optional` speaks plaintext only with pre-1.6 peers; `Disabled` reproduces the old wire. [`Pinhole.Blobs`](#moving-files-pinholeblobs) rides the same session encryption.
- **Open forever.** WiFi→mobile, IP changes, NAT rebinding, path death: the connection re-punches, migrates, or falls back to relay and stays up — modeled on how iroh keeps connections alive. It closes when you close it.
- **Payload ceilings that follow the path.** 1200 bytes guaranteed on every session; RFC 8899-style path-MTU discovery probes upward and lifts the per-connection ceiling (to 1435 on an ordinary Ethernet path) as the path proves it can carry more.
- **Unreliable — by design.** No delivery guarantees, ordering, or retransmission; bring your protocol above this layer. An optional keepalive heartbeat exists for NAT warmth; reliability stays yours.

## Scope contract

**In scope**: a connection between machines using all free STUN + all free relays; connection strings, LAN discovery via mDNS, and signed iroh address records (sharing a remote peer's ticket or ID = app's concern); encryption, authentication, and anti-replay on the wire; path-MTU discovery; open-forever with roaming and path-failure handling; an optional keepalive heartbeat; connection tools.

**On top, bring your own protocol**: UDP/TCP/QUIC — the app's libraries. We are the bottom layer and nothing else.

**Non-goals, stated loudly**: no delivery guarantees, ordering, or retransmission — a half-baked ARQ is worse than none, so retransmit at the app layer if you care (the engine's internal path validation keeps the *transport* honest, never your protocol alive; the optional keepalive is a NAT heartbeat, not reliability). No signaling transport, storage, or coordination services — anything stateful about your app belongs to your app.

## Install

```
dotnet add package Pinhole.Net          # the connection core
dotnet add package Pinhole.Blobs        # verified, encrypted, resumable file transfer
```

`Pinhole.Net` pulls in `Pinhole.Turn` (RFC 5766 relay client), `Pinhole.Providers` (the
free STUN/TURN catalog), and managed BouncyCastle cryptography. Parameterless `BindAsync()`
gets the free STUN catalog, public iroh relays, LAN announcements, and signed
endpoint/direct-address publication by default. `dotnet test` from a fresh
clone needs no submodules, Rust, or native toolchain — pure C# end to end.

## Platforms

The packages target **net8.0 (LTS) and net10.0**, managed-only — no native dependencies,
P/Invoke, or cgo-style baggage:

| Where | Status |
|---|---|
| Linux, macOS, Windows | CI-tested on all three every push |
| Any .NET-supported OS (FreeBSD, Android, iOS via .NET workloads, …) | Runs — anything with a UDP socket and .NET 8+ |
| NativeAOT / trimming | Supported (`IsAotCompatible`, single-file publish); the rendezvous server ships as an AOT binary |
| Browser/WASM | No — browsers do not expose UDP sockets |

The wire protocol is documented in [docs/PROTOCOL.md](docs/PROTOCOL.md), precisely enough
to re-implement either side.

For **iroh-compatible discovery and raw connectivity**, use `IrohTransport`: native
endpoint IDs/tickets, signed iroh DNS/Pkarr publication and lookup, and unchanged
UDP/relay packets for your protocol engine. See [the iroh connectivity guide](docs/IROH_CONNECTIVITY.md)
for the API and the boundary between preparing a route and completing the peer's
transport handshake.

## The two-PC program

This is the whole API surface a connection needs:

```csharp
using System.Text;
using Pinhole;

// ---------- PC A (listener) ----------
await using PinholeNode a = await PinholeNode.BindAsync();
// binds UDP and registers with public iroh HTTPS relays as the standing fallback,
// probes free STUN, announces on the LAN, and publishes signed direct/relay addresses.

string cs = a.ConnectionString;
// "pinhole1:AAE..." — peer ID + relay + direct/reflexive candidates.
// THE app moves this string to PC B: paste, lobby, your server — your problem.

await using PinholeConnection conn = await a.AcceptAsync();

conn.Received += dgram => Console.WriteLine(Encoding.UTF8.GetString(dgram));
conn.Send("hello from A"u8);          // unreliable datagram, zero-alloc on direct UDP
await conn.Closed;                    // roaming never fires it

// ---------- PC B (dialer) ----------
await using PinholeNode b = await PinholeNode.BindAsync();
await using PinholeConnection conn = await b.ConnectAsync(csFromA);

conn.Send("hello from B"u8);
```

`ConnectAsync` runs the chain internally — direct punch first, relay as the standing
fallback — and returns when connected **on either path**; it never "fails because the punch
failed". Both directions of a conversation ride the same connection object for its whole
life, across every network change.

`ConnectAsync` accepts surrounding whitespace and codes with or without `pinhole1:`.
The library validates the code and rejects a self-dial; callers do not need to parse it first.

Discovery defaults can be disabled independently: `EnableLanDiscovery = false`
stops LAN announcements, `PublishIrohAddress = false` stops signed publication,
and `PublishDirectIrohAddresses = false` keeps the published record to relay URLs
and the authenticated session-key binding. A shared ticket may still include IP
addresses. Publication makes the advertised IPs retrievable by anyone holding the
endpoint ID. `Encryption = Disabled` also requires `PublishIrohAddress = false`;
signed Pinhole discovery cannot bind a plaintext session key.

LAN announcements use IPv4 mDNS today; native signed records and tickets can carry
both IPv4 and IPv6 candidates. Application-supplied lookup providers and rendezvous
servers still need configuration. Discovery failures are tolerated and publication
retries in the background. More candidates improve the available direct attempts;
they do not guarantee a direct route through every NAT or host firewall.

Or run it with no code at all:

```bash
# The 30-line version — samples/Pinhole.Tiny: machine A prints a ticket, B dials it, chat.
dotnet run --project samples/Pinhole.Tiny                   # machine A
dotnet run --project samples/Pinhole.Tiny <ticket>          # machine B, anywhere on earth

# The basic interactive demo — run the same command on both PCs.
dotnet run --project samples/Pinhole.Demo
```

The demo prints your own connection string first. One person presses Enter to listen;
the other pastes the listener's string. Type messages after it says `Connected`, or
`/quit` to exit. Run the updated build on both PCs and share fresh strings so they include
the new HTTPS relay candidates. A code pasted without the `pinhole1:` prefix is accepted.

## Moving files: Pinhole.Blobs

The connection layer is deliberately raw. `Pinhole.Blobs` is the file-transfer layer
above it — the [sendme](https://github.com/n0-computer/sendme) model: one ticket moves a
file or a whole directory between machines, chunk-verified while streaming (BLAKE3,
1 KiB chunks), resumable across restarts, healed through datagram loss, and encrypted
end to end with a ticket-borne key so the public relays forward nothing but ciphertext.
It connects anywhere the connection layer does — that's the point.

Encrypted blob transfers use wire v3: both endpoints contribute a 32-byte session
nonce, and the downloader authenticates the provider's first response before adopting
the key. Upgrade both sides together; older encrypted blob peers are refused. Ticket
format stays the same. See [compatibility notes](docs/BLOBS.md#compatibility-wire-v3).

```csharp
using Pinhole.Blobs;

// PC A: serve until disposed; the ticket is the whole capability.
await using var server = await BlobServer.ServeAsync(@"C:\photos");
Console.WriteLine(server.Ticket);   // pinholeblob1:...

// PC B: verified, resumable download with progress.
var result = await BlobClient.DownloadAsync(ticket, @"D:\downloads",
    progress: new Progress<BlobProgress>(p => Console.WriteLine($"{p.VerifiedBytes}/{p.TotalBytes}")));
```

Or from the shell — `samples/Pinhole.Send`:

```bash
dotnet run --project samples/Pinhole.Send -- send ~/photos.tar    # prints ticket, serves until Ctrl-C
dotnet run --project samples/Pinhole.Send -- recv <ticket> ~/dl   # downloads into ~/dl, resumable
```

The wire format, ticket layout, ARQ, encryption, and resume format are documented in
[docs/BLOBS.md](docs/BLOBS.md), precisely enough to re-implement either side.

## Usage

### Connection errors and relay availability

`node.HasRelay` reports whether a relay is currently connected or allocated. It updates
after disconnects and reconnects; it does not guarantee the other peer is reachable.

Use `ConnectAsync` for the shortest successful path, or `TryConnectAsync` when you want
to display a failure and let the user try another code:

```csharp
PinholeConnectResult result = await node.TryConnectAsync(pastedCode);
if (!result.IsSuccess)
{
    Console.WriteLine(result.ErrorMessage);
    return;
}
await using PinholeConnection conn = result.Connection;
```

`result.Failure` distinguishes an invalid code, your own code, a failed direct attempt
without an advertised relay fallback, and a timeout with relay candidates. Failed attempts
are cleaned up so callers can retry. Cancellation still throws `OperationCanceledException`;
unexpected errors, such as using a disposed node, still throw. `ConnectAsync` keeps its
existing `FormatException`, `ArgumentException`, and `TimeoutException` categories and
now includes an actionable failure message.

### Receiving datagrams

`Received` fires on the connection's receive thread. The span is only valid during the
call — copy (`dgram.ToArray()`) if you queue it somewhere. Keep handlers fast; do real
work on your own scheduler.

```csharp
conn.Received += dgram => Console.WriteLine(Encoding.UTF8.GetString(dgram));

// Need the bytes to outlive the handler?
List<byte[]> inbox = new();
conn.Received += dgram =>
{
    lock (inbox) { inbox.Add(dgram.ToArray()); }   // copy: the span dies with the handler
};
```

The event has one race it cannot close: a datagram arriving between `AcceptAsync` and
the first `+=` is dropped. Opt into a bounded receive buffer at bind — the queue exists
before the handshake completes, so the first read delivers everything that arrived early:

```csharp
await using PinholeNode node = await PinholeNode.BindAsync(new PinholeOptions
{
    ReceiveBufferCapacity = 64,   // 0 (default) keeps the callback-only behavior
});
await using PinholeConnection peer = await node.AcceptAsync();

// One datagram at a time (null = closed and drained), or an endless stream:
ReadOnlyMemory<byte>? datagram = await peer.ReceiveAsync();
await foreach (ReadOnlyMemory<byte> dgram in peer.ReadAllAsync(ct))
    Handle(dgram.Span);

peer.DroppedDatagrams;   // how many the full queue threw away (drop-oldest, never blocks)
```

Buffering is local queueing only: datagrams are copied to owned arrays, a full queue
drops the oldest, and nothing about the network becomes reliable. One reader at a time;
cancellation ends a pending read without closing the connection; roaming and relay
fallback never end the stream — only closing does, after the buffer drains.

### Watching the connection

States are honest at all times, and `Path` tells you what is physically carrying traffic:

```csharp
conn.StateChanged += state => Console.WriteLine($"{DateTime.Now:T} -> {state}");
// Punching -> Open : a direct path opened
// Open     -> Degraded : direct path died, relay took over (datagrams keep flowing)
// Degraded -> Open    : a direct path was re-found (automatic upgrade)
// *        -> Dead     : no usable path (no relay configured); the object can come back
// *        -> Closed   : someone closed it — the only terminal state

Console.WriteLine(conn.State);            // PinholeConnectionState.Open
Console.WriteLine(conn.Path.Kind);        // Direct or Relay
Console.WriteLine(conn.Path.Remote);      // the peer endpoint in use right now
Console.WriteLine(conn.Path.RelayUrl);    // HTTPS relay URL when using an iroh relay
Console.WriteLine(conn.Path.Since);       // when this path became the one
```

### Unreliable means unreliable

`Send` fires a datagram into the network and returns. There is no ack, no retransmit, no
ordering — by design. If your protocol needs an exchange, retransmit until you hear back
(this is exactly what the mesh canary does):

```csharp
// Send until the peer's reply arrives (or give up).
var replied = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
conn.Received += reply => replied.TrySetResult(reply.ToArray());

var sw = Stopwatch.StartNew();
while (!replied.Task.IsCompleted && sw.Elapsed < TimeSpan.FromSeconds(5))
{
    conn.Send(payload);
    await Task.Delay(300);
}
```

Datagrams larger than `MaxPayload` (1200 bytes) throw `ArgumentOutOfRangeException`
before touching the network — chunk your protocol above this layer instead.

### Roaming — the connection survives the network

WiFi→mobile, IP change, NAT rebind, path death: handled inside. The same
`PinholeConnection` object keeps working; datagrams pause for a moment and resume. You
never re-dial and you never get a replacement object. `Closed` does not fire — roaming is
not closing.

```csharp
// Everything below is usually automatic (network-change watch is on by default).
// Force a re-probe yourself when you know better than the OS:
await node.RoamNowAsync();

// Or just observe:
conn.StateChanged += s => log($"path now: {conn.Path.Kind} via {conn.Path.Remote}");
```

If the network dies completely with no relay configured, the connection becomes `Dead`
— the object survives, and once the network is back:

```csharp
await node.RoamNowAsync();   // re-probe STUN, rebind if needed, re-announce, re-punch
// conn returns to Open (or Degraded) on its own; no re-dial, same object
```

Two safety nets complement the OS network watch. The periodic STUN refresh catches the
mapping moves that fire no OS event at all (see the failure table), and relay
reconnects are backoff-paced so an infrastructure blip heals without a retry storm.

### Tools: ping, RTT, stats

`Ping()` is a tool you call — Pinhole never schedules keepalives for your protocol.
(Separately, and invisibly to these counters, the engine validates the *transport path*
itself — see the failure table below; that is network maintenance, not app liveness.)

```csharp
conn.Ping();
// ...after the pong lands:
Console.WriteLine(conn.LastRtt);     // TimeSpan? — most recent answered ping
Console.WriteLine(conn.AverageRtt);  // TimeSpan? — EWMA across answered pings

PinholeStats s = conn.Stats;
Console.WriteLine($"{s.DatagramsSent} sent, {s.DatagramsReceived} received, " +
                  $"{s.DatagramsSendFailed} failed, {s.PingsLost} pings lost");
// Loss on an unreliable path can't be observed directly; PingsLost (pings sent −
// pongs received) is the honest approximation. All counters are AOT-safe plain numbers.
```

### Know your NAT — automatically

The node classifies its own NAT from its ordinary bind-time STUN probes: when two or
more servers observe the same mapping the NAT is a cone (the reflexive candidate is
punchable); when servers in the same address family observe different mappings it is symmetric, and the hint is
embedded in future connection strings so dialers go relay-first — public reflexive
punching depends on the other peer's filtering, but direct candidates keep a
one-second trickle. LAN and router mappings can also provide direct paths. IPv4 and IPv6
observations are compared separately. The classification repeats on every
STUN refresh, so a network change is picked up without re-dialing, and a manual
override always wins:

```csharp
Console.WriteLine(node.NatHint);   // Unknown / Cone / Symmetric — already in the string
node.SetNatHint(NatHint.Cone);     // only if the app knows better than the observations
node.SetNatHint(NatHint.Unknown);  // back to automatic
```

`NatDetector` remains available for apps that want the standalone detection it
performs.

### Router port mappings — the direct-path head start

At bind the node also asks the network's router for an explicit UDP mapping, trying
PCP, then NAT-PMP, then UPnP (IGDv1/v2, `AddAnyPortMapping` with a `AddPortMapping`
fallback) — the same strategy iroh's portmapper uses, implemented from the protocols
in pure C#. A granted mapping is advertised as a reflexive candidate, which turns
many hard home NATs into directly punchable ones *before* hole punching even starts;
it is renewed at half its lease, recreated after a rebind, and released when the node
closes. It is entirely background and best-effort — routers without these protocols
cost nothing, and nothing about the bind ever waits on them.

```csharp
Console.WriteLine(node.PortMappedEndpoint);  // e.g. 203.0.113.7:55555, or null
// Disable on networks where router control traffic is unwelcome:
var node = await PinholeNode.BindAsync(new PinholeOptions { EnablePortMapping = false });
```

### Configuration

Parameterless `BindAsync()` probes free STUN and connects to n0's public iroh relays over
HTTPS WebSockets. The managed C# relay client implements iroh's signed challenge and
datagram framing; BouncyCastle supplies Ed25519 and BLAKE3. Relays introduce peers and
carry Pinhole datagrams while both sides punch UDP, then remain available for fallback
and reconnect automatically after a disconnect. This is the iroh relay transport with
Pinhole's own datagram protocol; `PinholeNode` sessions do not interoperate with native
iroh application endpoints. `IrohTransport` provides the separate native-address/raw-packet
API described in [IROH_CONNECTIVITY.md](docs/IROH_CONNECTIVITY.md). Pinhole session payloads are end-to-end encrypted between the two
peers; the relay (like any relay) sees only ciphertext frames.

Everything is overridable — and every infrastructure setting is tri-state: `null`
(default) takes the free defaults, an empty list disables that provider, explicit
entries replace the defaults. Customizing one setting never silently drops the rest,
so there is no need to fetch `DefaultAsync` first anymore:

```csharp
// A scalar tweak only — free STUN and the public iroh relays stay enabled:
var node = await PinholeNode.BindAsync(new PinholeOptions
{
    ConnectTimeout = TimeSpan.FromSeconds(30),
});

// Full form, every knob at its default:
var node = await PinholeNode.BindAsync(new PinholeOptions
{
    // Optional TURN in addition to the default HTTPS relays:
    Relays = [new TurnServerConfig(
        new IPEndPoint(IPAddress.Parse("203.0.113.10"), 3478), "user", "pass")],

    // Or replace the public iroh relays with your own:
    // IrohRelayUrls = [new Uri("https://relay.example.com/")],

    StunServers = null,             // null = free catalog; [] = no reflexive stage
    Listen = true,                  // accept strangers dialing your string
    EnableNetworkWatch = true,      // auto-roam on OS network changes
    AdvertiseLinkLocal = true,      // LAN IPv6 fallback; false omits link-local candidates
    EnablePathValidation = true,    // detect silent direct-path death (see failure table)
    StunRefreshInterval = TimeSpan.FromMinutes(1), // re-probe STUN; 0 = off
    ReceiveBufferCapacity = 0,      // > 0 enables ReceiveAsync/ReadAllAsync
    ConnectTimeout = TimeSpan.FromSeconds(15),  // whole-chain dial budget
    BindProbeBudget = TimeSpan.FromSeconds(5),  // bind-time probe budget (failures tolerated)
});
```

`StunRefreshInterval` is the periodic re-discovery iroh also performs: NAT mappings move
silently (DHCP renew, router reboot) with no OS network event, so the node re-probes its
STUN servers on a timer. When the observed mapping changed, the reflexive candidates are
replaced, every peer is re-advertised via a gentle announce, and the next
`ConnectionString` read carries the new addresses — while working direct paths keep
working, untouched.

Deterministic test/offline node (no internet at all — what the test suite uses):

```csharp
var local = await PinholeNode.BindAsync(new PinholeOptions
{
    StunServers = [],
    Relays = [],
    IrohRelayUrls = [],
});
```

### Many peers

One node, many connections, one socket. Dial every string you're given, accept in a loop:

```csharp
// Dial a lobby full of peers:
List<PinholeConnection> peers = new();
foreach (string ticket in lobbyTickets)
{
    peers.Add(await node.ConnectAsync(ticket));
}

// And/or accept whoever dials you — each AcceptAsync call yields one connection:
while (running)
{
    PinholeConnection guest = await node.AcceptAsync(ct);
    guest.Received += HandleFrame;         // void HandleFrame(ReadOnlySpan<byte> frame)
}
```

Connections are identified by stable peer ID, never by IP — that's what makes roaming
invisible. Late joins don't disturb existing pairs.

## When does it connect?

Reachability depends on both peers' NATs, host firewalls, and available relay infrastructure
([#15](https://github.com/IAFahim/Pinhole.Net/issues/15)):

The [direct connectivity audit](docs/CONNECTIVITY_AUDIT.md) compares the .NET core
with the Kotlin phone dialer, identifies missing methods, and records the evidence
needed before claiming broad automatic direct connectivity.

| Dialer side | Publisher side | Direct punch | Path used |
|---|---|---|---|
| Reachable IPv6 | Reachable IPv6 | Yes, when both firewalls permit it | Direct IPv6 |
| Cone/EIM NAT | Cone/EIM NAT | Yes — simultaneous open, both sides punch at each other | Direct UDP |
| Cone NAT | Symmetric NAT | Depends on filtering and explicit mappings; direct probes continue once a second | Direct UDP when reachable, otherwise relay |
| Symmetric NAT | Cone NAT | Often — a symmetric NAT's *outbound* mapping still lands on their stable cone address | Direct UDP, else relay |
| Symmetric NAT | Symmetric NAT | Ordinary STUN-based punching is not guaranteed; explicit mappings can help | Usually relay |
| UDP blocked (hotel/corp firewall) | Anything | Impossible | iroh HTTPS relay — WebSocket over 443, looks like HTTPS browsing |
| TURN credentials configured | Firewall allows only relayed UDP | — | TURN relayed address (RFC 5766) |
| Both behind the same NAT (CGNAT hairpin) | Each other | Usually fails — hairpinning is router-dependent and rarely works on CGNAT | Relay automatically; direct is expected-not-guaranteed |
| Path dies mid-session | Any | Re-punched in the background | Survives on the relay until the punch lands |

A host firewall can block an otherwise reachable direct path. For a server with a restricted
inbound firewall, bind an application-owned UDP port and permit it in that firewall. The
library does not change host firewall rules. To verify direct connectivity without data
relay fallback, set `IrohRelayUrls = []` and `Relays = []` on the node, share a fresh ticket,
and check `connection.Path.Kind == PathKind.Direct`. This also disables iroh introductions;
peers that need simultaneous punching should exchange both tickets out of band. Fresh
authenticated direct-address announcements restart relay-to-direct probing even after the
previous upgrade budget has been spent.

Two former non-goals from that same audit are gone, retired deliberately:
**path-MTU discovery now runs by default** — padded token-checked pings climb from the
1200-byte floor and lift the payload ceiling as the path proves itself (RFC 8899-style,
`EnablePmtud = false` for a flat budget) — and **LAN discovery exists** via optional
mDNS announcement plus serverless browsing, while the connection string remains the
universal discovery artifact everywhere else.

## Failure modes, honestly

| What dies | What the connection does |
|---|---|
| The direct path (NAT mapping expires, peer's IP changes) | Degrades to `Degraded` and keeps flowing on the relay; re-probes for a direct path and upgrades back to `Open` silently |
| The direct path dies *silently* (firewall drops, NAT rebind — no send error, nothing comes back) | Detected, not assumed: after ~5 s with nothing received on the direct path, the engine probes it with the token-checked ping protocol; three unanswered probes mark it suspect and the normal handling kicks in (relay fallback, or honest death). One lost probe or live traffic never degrades a path, and relay traffic never certifies a direct one. Opt out with `EnablePathValidation = false` |
| The NAT mapping moves with no OS event (DHCP renew, router reboot) | The periodic STUN refresh (`StunRefreshInterval`, default 1 min) notices, replaces the reflexive candidates, and gently re-advertises to every peer; working direct paths are untouched — regenerate and re-share connection strings |
| The peer's whole network (WiFi→mobile) | That peer's node rebinds (new socket/port/relay), re-announces, re-punches — the same connection object, datagrams resume in both directions |
| Direct path dies and no relay is configured | Bounded re-punch, then honestly `Dead`; `Send` throws with a `RoamNowAsync()` hint; the object stays inspectable |
| Every STUN server goes silent | Treated as network loss → full rebind; a single rate-limited probe is *not* network death |
| A relay dies or is unreachable | Best-effort: the remaining configured relays carry the fallback; the dropped relay reconnects forever with capped exponential backoff (~1 s doubling to 30 s, ±10% jitter, reset on success — no synchronized retry storm); direct paths never notice |
| A datagram is lost | Nothing. It's an unreliable datagram protocol — retransmit at the app layer if you care |
| A machine in the middle substitutes the answering key, or strips the handshake | The dial dies loudly (`HandshakeFailed` / `ConnectAsync` faults with the reason) — there is no downgrade window to fall into |
| A tampered, replayed, or forged frame arrives | Dropped silently and counted in `FramesRejected`; replay-window state advances only on authenticated frames (RFC 4303 §3.4.3), so a forged counter — however far future — starves nothing, and steady zero is the healthy number |
| The peer closes (`CloseAsync`) | `Bye` frame, both sides end up `Closed`; `Closed` tasks complete |

## The libraries

- `src/Pinhole` — the connection core (`Pinhole.Net` package, net8.0 + net10.0): `PinholeNode`/`PinholeConnection` session API, managed iroh relay transport, automatic NAT classification, PCP/NAT-PMP/UPnP router port mapping, `NatDetector`, the raw `PeerSocket` punch engine — one UDP socket, zero allocations per datagram in either direction (perf-profiled), no native dependencies; wire format documented in [docs/PROTOCOL.md](docs/PROTOCOL.md); persistent identity and authenticated address rediscovery in [docs/REDISCOVERY.md](docs/REDISCOVERY.md)
- `src/Pinhole.Blobs` — file & directory transfer above the core (`Pinhole.Blobs` package, net8.0 + net10.0, AOT-compatible): one-ticket serving/downloading, BLAKE3 verified streaming, receiver-driven loss healing, resume sidecars, per-ticket ChaCha20-Poly1305; wire format documented in [docs/BLOBS.md](docs/BLOBS.md)
- `src/Pinhole.Turn` — TURN relay client (RFC 5766): allocate/permission/send+data indications against any standard TURN server
- `src/Pinhole.Providers` — catalog of all free endpoints: Google/Cloudflare/Metered/OpenRelay/Twilio STUN+TURN presets
- `src/Pinhole.Rendezvous` — optional rendezvous/introducer server (single binary, deployable anywhere a UDP port is open)
- `samples/Pinhole.Demo` — basic interactive chat: prints your connection string, then listens or dials a pasted string
- `samples/Pinhole.Tiny` — the 30-line chat: the whole library in one file
- `samples/Pinhole.Bench` — non-interactive throughput/allocation canary: two loopback nodes, no stdin, no infrastructure — what CI runs
- `samples/Pinhole.Mesh` — multi-machine canary harness: strangers discover each other over a signaling channel, connect with connection strings, verify, repeat
- `samples/Pinhole.Send` — sendme-style CLI: `send <path>` prints a ticket and serves until Ctrl-C, `recv <ticket> [dir]` downloads with console progress
- `tests/Pinhole.Tests` — loopback xunit suite: session API + punch/ping/data, roaming (rebind, degrade, honest death), silent-path-failure detection, periodic STUN refresh, reconnect backoff pacing, buffered receiving, options resolution, NAT detection, STUN+TURN and iroh relay authentication/reconnection against in-process fake servers, rendezvous protocol + bounds, BLAKE3 oracle-tested against BouncyCastle, and the full blobs matrix (roundtrips at every boundary size, directory trees, loss healing, corruption aborts, interrupt/resume, relay-forwarded-bytes-are-ciphertext) — plus the topology/loss lab: an in-process virtual internet (real NAT translation/filtering, Gilbert-Elliott loss, delay/reorder) driving the 16-cell NAT pairing matrix, adversarial scenarios, and the blob-ARQ loss-ladder baseline; see [docs/TESTING.md](docs/TESTING.md). Runtime instrumentation (connection attempts, recovery events, failure causes) is emitted on the .NET diagnostics meter `Pinhole.Net`; see [docs/METRICS.md](docs/METRICS.md). Measured congestion/recovery baselines live in [docs/BASELINES.md](docs/BASELINES.md). Compatibility guarantees, recovery limits, measured evidence, and known limitations are consolidated in [docs/RELIABILITY.md](docs/RELIABILITY.md)

## Build & test

```bash
git clone https://github.com/IAFahim/Pinhole.Net
cd Pinhole.Net
dotnet test tests/Pinhole.Tests        # self-contained: no network, no cargo, nothing native
dotnet run --project samples/Pinhole.Bench -c Release   # throughput/allocation canary (offline)
```

The bench prints two numbers: throughput in datagrams per second with the *sending
thread's* allocation cost per datagram (the zero-allocation contract for `Send`), and a
second line with *whole-process* allocations per datagram — the receive path and any GC
work included, so neither direction can quietly regress. The CI canary gates on the
throughput floor and the sender-side zero.

## Status — 1.0

Done: punch/TURN/rendezvous hardening ([#1](https://github.com/IAFahim/Pinhole.Net/issues/1)),
safe-layer migration ([#2](https://github.com/IAFahim/Pinhole.Net/issues/2)),
25-test suite + 3-OS CI + bench canary ([#3](https://github.com/IAFahim/Pinhole.Net/issues/3)),
session layer — connection strings + N peers + direct→relay chain ([#4](https://github.com/IAFahim/Pinhole.Net/issues/4), [#9](https://github.com/IAFahim/Pinhole.Net/issues/9)),
Rust fully removed ([#8](https://github.com/IAFahim/Pinhole.Net/issues/8)),
open-forever roaming ([#5](https://github.com/IAFahim/Pinhole.Net/issues/5)),
NAT/path/payload tools ([#6](https://github.com/IAFahim/Pinhole.Net/issues/6)),
this release ([#7](https://github.com/IAFahim/Pinhole.Net/issues/7)).

Post-1.0: red-team hardening (1.1.0), then options defaults preserved under partial
customization ([#11](https://github.com/IAFahim/Pinhole.Net/issues/11)),
opt-in buffered receiving ([#13](https://github.com/IAFahim/Pinhole.Net/issues/13)),
silent path-death detection ([#12](https://github.com/IAFahim/Pinhole.Net/issues/12)),
and a green CI again — dedicated offline bench sample, deterministic relay-reconnect
injection, loopback-stable spoof tests ([#10](https://github.com/IAFahim/Pinhole.Net/issues/10)).

The mesh canary runs weekly on three independent GitHub runners that have never met:
they find each other through tickets, connect with connection strings only, verify fresh
secrets, and repeat — three rounds, all pairs, every time (`.github/workflows/mesh.yml`).
