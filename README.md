# Pinhole.Net

A connection library for .NET. The bottom layer — nothing else.

One job: **get a connection between two machines, then keep it open until the app closes it.**

- **All free infrastructure.** Every free STUN server and every free relay — Google, Cloudflare, OpenRelay, any standard TURN server. Consumed as protocols from pure C#, never as wrapped libraries.
- **Connection string, iroh-style.** An endpoint produces a connection string (stable peer ID + relay + direct candidates); the other side dials it. How the string travels between the two peers — clipboard, your server, your game lobby — is the application's concern, not this library's.
- **Open forever.** WiFi→mobile, IP changes, NAT rebinding, path death: the connection re-punches, migrates, or falls back to relay and stays up — modeled on how iroh keeps connections alive. It closes when you close it.
- **Bring your own protocol on top.** UDP, TCP, QUIC, your own — with your own libraries. Pinhole doesn't provide those and never will. It does the hard bottom part only.
- **Unauthenticated, unencrypted, unreliable — by design.** Do encryption, authentication, and reliability above this layer.

## Scope contract

**In scope**: a connection between machines using all free STUN + all free relays; connection strings as the discovery artifact (transport of the string = app's concern); open-forever with roaming and path-failure handling; connection tools.

**On top, bring your own protocol**: UDP/TCP/QUIC — the app's libraries. We are the bottom layer and nothing else.

**Non-goals, stated loudly**: no encryption/authentication — traffic is readable and peer identity is unauthenticated **by design**; encrypt and authenticate above this layer. No delivery guarantees, ordering, retransmission, or keepalive scheduling. No signaling transport, storage, or coordination services.

## Install

```
dotnet add package Pinhole.Net
```

`Pinhole.Net` pulls in `Pinhole.Turn` (RFC 5766 relay client) and `Pinhole.Providers` (the
free STUN/TURN catalog) — parameterless `BindAsync()` gets all free infrastructure by
default. `dotnet test` from a fresh clone needs nothing else: no submodules, no Rust, no
native toolchain — pure C# end to end.

## The two-PC program

This is the whole API surface a connection needs:

```csharp
using System.Text;
using Pinhole;

// ---------- PC A (listener) ----------
await using PinholeNode a = await PinholeNode.BindAsync();
// binds the UDP socket, allocates the free relay as the standing fallback,
// probes free STUN (Google/Cloudflare) for the reflexive candidate.

string cs = a.ConnectionString;
// "pinhole1:AAE..." — peer ID + relay + direct/reflexive candidates.
// THE app moves this string to PC B: paste, lobby, your server — your problem.

await using PinholeConnection conn = await a.AcceptAsync();

conn.Received += dgram => Console.WriteLine(Encoding.UTF8.GetString(dgram));
conn.Send("hello from A"u8);          // unreliable datagram, hot path, zero-alloc
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

Or run it with no code at all:

```bash
# The 30-line version — samples/Pinhole.Tiny: machine A prints a ticket, B dials it, chat.
dotnet run --project samples/Pinhole.Tiny                   # machine A
dotnet run --project samples/Pinhole.Tiny <ticket>          # machine B, anywhere on earth

# The fuller version — RTT display, path states, plus stun/nat/turn probes and bench.
dotnet run --project samples/Pinhole.Demo -- node           # prints the connection string, listens
dotnet run --project samples/Pinhole.Demo -- node <string>  # dials it from any machine
```

## Usage

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

Parameterless `BindAsync()` uses all free infrastructure (free STUN catalog + free
OpenRelay TURN). Everything is overridable:

```csharp
var node = await PinholeNode.BindAsync(new PinholeOptions
{
    // Your own relay instead of (or as well as) the free one:
    Relays = [new TurnServerConfig(
        new IPEndPoint(IPAddress.Parse("203.0.113.10"), 3478), "user", "pass")],

    // Or presets from Pinhole.Providers (DNS-resolved for you):
    // Relays = (await Providers.TurnServers.OpenRelay.ResolveAsync())
    //     .Select(ep => new TurnServerConfig(ep, "openrelayproject", "openrelayproject"))
    //     .ToArray(),

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

- `src/Pinhole` — the connection core (`Pinhole.Net` package, net10.0): `PinholeNode`/`PinholeConnection` session API, `NatDetector`, the raw `PeerSocket` punch engine — one UDP socket, zero allocations on the hot path, no native dependencies
- `src/Pinhole.Turn` — TURN relay client (RFC 5766): allocate/permission/send+data indications against any standard TURN server
- `src/Pinhole.Providers` — catalog of all free endpoints: Google/Cloudflare/Metered/OpenRelay/Twilio STUN+TURN presets
- `src/Pinhole.Rendezvous` — optional rendezvous/introducer server (single binary, deployable anywhere a UDP port is open)
- `samples/Pinhole.Demo` — the README program (`node` chat over connection strings), rendezvous chat, throughput bench, stun/nat/turn probes
- `samples/Pinhole.Tiny` — the 30-line chat: the whole library in one file
- `samples/Pinhole.Mesh` — multi-machine canary harness: strangers discover each other over a signaling channel, connect with connection strings, verify, repeat
- `tests/Pinhole.Tests` — loopback xunit suite (45 tests): session API + punch/ping/data, roaming (rebind, degrade, honest death), NAT detection, STUN+TURN against in-process fake servers, rendezvous protocol + bounds

## Build & test

```bash
git clone https://github.com/IAFahim/Pinhole.Net
cd Pinhole.Net
dotnet test tests/Pinhole.Tests        # self-contained: no network, no cargo, nothing native
```

## Tools

```bash
pinhole-demo stun stun.l.google.com:19302   # -> reflexive addr (verified live)
pinhole-demo nat                            # -> cone / symmetric / unknown, with advice
pinhole-demo turn <host:port> <user> <pass> # TURN allocate -> relayed addr, then relay datagrams
```

`NatDetector` compares what several STUN servers observe of the same socket: one mapping
everywhere → cone (strangers can punch each other); a mapping per destination → symmetric
(dial through a relay). Fewer than two answers → `Unknown`, because one mapping proves
nothing.

## Run it — own rendezvous

```bash
dotnet run --project src/Pinhole.Rendezvous -- 7777                        # signaling box
dotnet run --project samples/Pinhole.Demo -- rendezvous 127.0.0.1:7777 aaaa        # listen
dotnet run --project samples/Pinhole.Demo -- rendezvous 127.0.0.1:7777 bbbb aaaa   # dial
```

## Bench

```bash
pinhole-demo bench 100000 64
# 299k datagrams/s, 0 B/datagram allocated, 0 GCs (loopback)
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
