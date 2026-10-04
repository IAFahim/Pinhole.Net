# Pinhole.Net

A connection library for .NET. The bottom layer — nothing else.

One job: **get a connection between two machines, then keep it open until the app closes it.**

- **Free infrastructure.** Google/Cloudflare STUN and n0's public iroh HTTPS relays by default; standard TURN servers can be added with your own credentials. Consumed as protocols from pure C#.
- **Connection string, iroh-style.** An endpoint produces a connection string (stable peer ID + relay + direct candidates); the other side dials it. How the string travels between the two peers — clipboard, your server, your game lobby — is the application's concern, not this library's.
- **Open forever.** WiFi→mobile, IP changes, NAT rebinding, path death: the connection re-punches, migrates, or falls back to relay and stays up — modeled on how iroh keeps connections alive. It closes when you close it.
- **Bring your own protocol on top.** UDP, TCP, QUIC, your own — with your own libraries. Pinhole doesn't provide those and never will. It does the hard bottom part only.
- **Unauthenticated, unencrypted, unreliable — by design.** Do encryption, authentication, and reliability above this layer.

## Scope contract

**In scope**: a connection between machines using all free STUN + all free relays; connection strings as the discovery artifact (transport of the string = app's concern); open-forever with roaming and path-failure handling; connection tools.

**On top, bring your own protocol**: UDP/TCP/QUIC — the app's libraries. We are the bottom layer and nothing else.

**Non-goals, stated loudly**: no encryption/authentication — traffic is readable and peer identity is unauthenticated **by design**; encrypt and authenticate above this layer. (Anti-spoofing exists below that line: every frame carries a per-connection token that never appears in the connection string, so a string holder can dial you but cannot forge, hijack, or kill an established session.) No delivery guarantees, ordering, retransmission, or keepalive scheduling. No signaling transport, storage, or coordination services.

## Install

```
dotnet add package Pinhole.Net
```

`Pinhole.Net` pulls in `Pinhole.Turn` (RFC 5766 relay client), `Pinhole.Providers` (the
free STUN/TURN catalog), and managed BouncyCastle cryptography. Parameterless `BindAsync()`
gets the free STUN catalog and public iroh relays by default. `dotnet test` from a fresh
clone needs no submodules, Rust, or native toolchain — pure C# end to end.

## The two-PC program

This is the whole API surface a connection needs:

```csharp
using System.Text;
using Pinhole;

// ---------- PC A (listener) ----------
await using PinholeNode a = await PinholeNode.BindAsync();
// binds UDP and registers with public iroh HTTPS relays as the standing fallback,
// probes free STUN (Google/Cloudflare) for the reflexive candidate.

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

### Tools: ping, RTT, stats

`Ping()` is a tool you call — Pinhole never schedules keepalives for you.

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

### Know your NAT

`NatDetector` compares what several STUN servers observe of the same socket. A symmetric
NAT gets a hint embedded in future connection strings, so dialers skip the hopeless punch
and go straight to relay:

```csharp
NatType nat = await NatDetector.DetectAsync();       // free STUN catalog
node.SetNatHint(nat switch
{
    NatType.Cone      => NatHint.Cone,       // punch away
    NatType.Symmetric => NatHint.Symmetric,  // dialers will lean on the relay
    _                 => NatHint.Unknown,
});
```

### Configuration

Parameterless `BindAsync()` probes free STUN and connects to n0's public iroh relays over
HTTPS WebSockets. The managed C# relay client implements iroh's signed challenge and
datagram framing; BouncyCastle supplies Ed25519 and BLAKE3. Relays introduce peers and
carry Pinhole datagrams while both sides punch UDP, then remain available for fallback
and reconnect automatically after a disconnect. This is the iroh relay transport with
Pinhole's own datagram protocol; it does not implement iroh QUIC or interoperate with Rust
iroh application endpoints. Pinhole payloads remain unencrypted end to end, as described above.

Everything is overridable:

```csharp
PinholeOptions defaults = await PinholeOptions.DefaultAsync();
var node = await PinholeNode.BindAsync(defaults with
{
    // Optional TURN in addition to the default HTTPS relays:
    Relays = [new TurnServerConfig(
        new IPEndPoint(IPAddress.Parse("203.0.113.10"), 3478), "user", "pass")],

    // Or replace the public iroh relays with your own:
    // IrohRelayUrls = [new Uri("https://relay.example.com/")],

    StunServers = null,             // null = free catalog; [] = no reflexive stage
    Listen = true,                  // accept strangers dialing your string
    EnableNetworkWatch = true,      // auto-roam on OS network changes
    ConnectTimeout = TimeSpan.FromSeconds(15),  // whole-chain dial budget
    BindProbeBudget = TimeSpan.FromSeconds(5),  // bind-time probe budget (failures tolerated)
});
```

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

## Failure modes, honestly

| What dies | What the connection does |
|---|---|
| The direct path (NAT mapping expires, peer's IP changes) | Degrades to `Degraded` and keeps flowing on the relay; re-probes for a direct path and upgrades back to `Open` silently |
| The peer's whole network (WiFi→mobile) | That peer's node rebinds (new socket/port/relay), re-announces, re-punches — the same connection object, datagrams resume in both directions |
| Direct path dies and no relay is configured | Bounded re-punch, then honestly `Dead`; `Send` throws with a `RoamNowAsync()` hint; the object stays inspectable |
| Every STUN server goes silent | Treated as network loss → full rebind; a single rate-limited probe is *not* network death |
| A relay dies or is unreachable | Best-effort: the remaining configured relays carry the fallback; direct paths never notice |
| A datagram is lost | Nothing. It's an unreliable datagram protocol — retransmit at the app layer if you care |
| The peer closes (`CloseAsync`) | `Bye` frame, both sides end up `Closed`; `Closed` tasks complete |

## The libraries

- `src/Pinhole` — the connection core (`Pinhole.Net` package, net10.0): `PinholeNode`/`PinholeConnection` session API, managed iroh relay transport, `NatDetector`, the raw `PeerSocket` punch engine — one UDP socket, zero allocations on the direct path, no native dependencies
- `src/Pinhole.Turn` — TURN relay client (RFC 5766): allocate/permission/send+data indications against any standard TURN server
- `src/Pinhole.Providers` — catalog of all free endpoints: Google/Cloudflare/Metered/OpenRelay/Twilio STUN+TURN presets
- `src/Pinhole.Rendezvous` — optional rendezvous/introducer server (single binary, deployable anywhere a UDP port is open)
- `samples/Pinhole.Demo` — basic interactive chat: prints your connection string, then listens or dials a pasted string
- `samples/Pinhole.Tiny` — the 30-line chat: the whole library in one file
- `samples/Pinhole.Mesh` — multi-machine canary harness: strangers discover each other over a signaling channel, connect with connection strings, verify, repeat
- `tests/Pinhole.Tests` — loopback xunit suite: session API + punch/ping/data, roaming (rebind, degrade, honest death), NAT detection, STUN+TURN and iroh relay authentication/reconnection against in-process fake servers, rendezvous protocol + bounds

## Build & test

```bash
git clone https://github.com/IAFahim/Pinhole.Net
cd Pinhole.Net
dotnet test tests/Pinhole.Tests        # self-contained: no network, no cargo, nothing native
```

## Status — 1.0

Done: punch/TURN/rendezvous hardening ([#1](https://github.com/IAFahim/Pinhole.Net/issues/1)),
safe-layer migration ([#2](https://github.com/IAFahim/Pinhole.Net/issues/2)),
25-test suite + 3-OS CI + bench canary ([#3](https://github.com/IAFahim/Pinhole.Net/issues/3)),
session layer — connection strings + N peers + direct→relay chain ([#4](https://github.com/IAFahim/Pinhole.Net/issues/4), [#9](https://github.com/IAFahim/Pinhole.Net/issues/9)),
Rust fully removed ([#8](https://github.com/IAFahim/Pinhole.Net/issues/8)),
open-forever roaming ([#5](https://github.com/IAFahim/Pinhole.Net/issues/5)),
NAT/path/payload tools ([#6](https://github.com/IAFahim/Pinhole.Net/issues/6)),
this release ([#7](https://github.com/IAFahim/Pinhole.Net/issues/7)).

The mesh canary runs weekly on three independent GitHub runners that have never met:
they find each other through tickets, connect with connection strings only, verify fresh
secrets, and repeat — three rounds, all pairs, every time (`.github/workflows/mesh.yml`).
