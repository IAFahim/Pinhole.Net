# Pinhole.Net

A connection library for .NET. The bottom layer — nothing else.

One job: **get a connection between two machines, then keep it open until the app closes it.**

- **All free infrastructure.** Every free STUN server and every free relay — Google, Cloudflare, iroh's public relays, any standard TURN server. Consumed as protocols from pure C#, never as wrapped libraries.
- **Connection string, iroh-style.** An endpoint produces a connection string (stable peer ID + relay + direct candidates); the other side dials it. How the string travels between the two peers — clipboard, your server, your game lobby — is the application's concern, not this library's.
- **Open forever.** WiFi→mobile, IP changes, NAT rebinding, path death: the connection re-punches, migrates, or falls back to relay and stays up — modeled on how iroh keeps connections alive. It closes when you close it.
- **Bring your own protocol on top.** UDP, TCP, QUIC, your own — with your own libraries. Pinhole doesn't provide those and never will. It does the hard bottom part only.
- **Unauthenticated, unencrypted, unreliable — by design.** Do encryption, authentication, and reliability above this layer.

## The libraries

- `src/Pinhole` — the connection core (`Pinhole` package, net10.0): `PinholeNode`/`PinholeConnection` session API + the raw `PeerSocket` punch engine — one UDP socket, zero allocations on the hot path, no native dependencies
- `src/Pinhole.Turn` — TURN relay client (RFC 5766): allocate/permission/send+data indications against any standard TURN server
- `src/Pinhole.Providers` — catalog of all free endpoints: Google/Cloudflare/Metered/OpenRelay/Twilio STUN+TURN presets
- `src/Pinhole.Rendezvous` — optional rendezvous/introducer server (single binary, deployable anywhere a UDP port is open)
- `samples/Pinhole.Demo` — the README program (`node` chat over connection strings), rendezvous chat, throughput bench, stun/turn probes
- `samples/Pinhole.Mesh` — multi-machine canary harness: strangers discover each other over a signaling channel, connect with connection strings, verify, repeat
- `tests/Pinhole.Tests` — loopback xunit suite: session API + punch/ping/data, STUN+TURN against in-process fake servers, rendezvous protocol + bounds, teardown bounds

## Build & test

```bash
git clone https://github.com/IAFahim/Pinhole.Net
cd Pinhole.Net
dotnet test tests/Pinhole.Tests        # self-contained: no network, no cargo, nothing native
```

Pure C# end to end — no submodules, no Rust toolchain, no TFM pins.

## Run it — connection strings (free infrastructure, no server)

```bash
dotnet run --project samples/Pinhole.Demo -- node          # prints the connection string, listens
dotnet run --project samples/Pinhole.Demo -- node <string> # dials it from any machine
```

`BindAsync` probes the free STUN servers and allocates the free OpenRelay TURN server as
the standing fallback; the string carries the peer ID plus direct/reflexive/relay
candidates. `ConnectAsync` runs the chain internally — direct punch first, relay when the
punch fails — and the connection opens on whichever path works.

## Run it — own rendezvous

```bash
dotnet run --project src/Pinhole.Rendezvous -- 7777                        # signaling box
dotnet run --project samples/Pinhole.Demo -- rendezvous 127.0.0.1:7777 aaaa        # listen
dotnet run --project samples/Pinhole.Demo -- rendezvous 127.0.0.1:7777 bbbb aaaa   # dial
```

## Free infrastructure probes

```bash
pinhole-demo stun stun.l.google.com:19302   # -> reflexive addr (verified live)
pinhole-demo stun stun.cloudflare.com:3478  # -> reflexive addr (verified live)
pinhole-demo turn <host:port> <user> <pass> # TURN allocate -> relayed addr, then relay datagrams
```

STUN probing rides the pinhole socket itself (`pin.ProbeStunAsync`), so the
observed mapping is the mapping punching needs. TURN allocations run on a
dedicated socket as a separate fallback channel. Verified against a real
coturn server: allocate -> create-permission -> send/data indications.

## Bench

```bash
pinhole-demo bench 100000 64
# 299k datagrams/s, 0 B/datagram allocated, 0 GCs (loopback)
```

## Roadmap — the 1.0 API

The dev surface the milestones below build toward. Iroh's ergonomics (`bind → ticket →
connect/accept`), this library's connection contract underneath:

```csharp
using Pinhole;

// ---------- PC A (listener) ----------
await using PinholeNode a = await PinholeNode.BindAsync();
// binds the UDP socket, registers with iroh's public relay (home base),
// probes free STUN (Google/Cloudflare) for the reflexive candidate.

string cs = a.ConnectionString;
// "pinhole1:AAE..." — peer ID + relay + direct/reflexive candidates.
// THE app moves this string to PC B: paste, lobby, your server — your problem.

await using PinholeConnection conn = await a.AcceptAsync();

conn.Received += dgram => Console.WriteLine(Encoding.UTF8.GetString(dgram));
conn.Send("hello from A"u8);          // unreliable datagram, hot path, zero-alloc
await conn.Closed;                    // fires only on Close() — roaming never fires it

// ---------- PC B (dialer) ----------
await using PinholeNode b = await PinholeNode.BindAsync();
await using PinholeConnection conn = await b.ConnectAsync(csFromA);

conn.Send("hello from B"u8);
```

- `PinholeNode.BindAsync()` → socket + relay home + STUN probe, all internal.
- `node.ConnectionString` → the single discovery artifact; `ConnectAsync(string)` consumes it.
- `ConnectAsync` runs the chain internally: direct punch first, iroh relay as the standing
  fallback — it returns when connected *on either path*, never "fails because punch failed".
- `PinholeConnection`: `Send(span)` / `Received` event / `State`
  (`Punching → Open → Degraded → Closed`) / `Path` (direct-reflexive-or-relay + RTT) /
  `CloseAsync()`. WiFi→mobile, rebind, NAT death: handled inside, same object, no events required.
- `MaxPayload` guard; `Ping()` as a tool.
- `Pinhole.Iroh` becomes the internal C# client of iroh's public relays; the dev never touches it.

Deliberately absent, by design: no encryption/auth (plaintext — do it above), no
reliability/ordering/streams, no keepalive scheduling, no signaling service (string
transport is yours). On top of the connection, bring your own protocol — UDP, TCP, QUIC.

## Status

Done: punch/TURN/rendezvous hardening ([#1](https://github.com/IAFahim/Pinhole.Net/issues/1)),
safe-layer migration ([#2](https://github.com/IAFahim/Pinhole.Net/issues/2)),
25-test suite + 3-OS CI + bench canary ([#3](https://github.com/IAFahim/Pinhole.Net/issues/3)).

Next: drop all Rust, standalone ([#8](https://github.com/IAFahim/Pinhole.Net/issues/8)) →
connection strings + N-peer + direct/reflexive/relay chain ([#4](https://github.com/IAFahim/Pinhole.Net/issues/4)) →
open-forever roaming ([#5](https://github.com/IAFahim/Pinhole.Net/issues/5)) →
NAT/path/payload tools ([#6](https://github.com/IAFahim/Pinhole.Net/issues/6)) →
1.0 ship ([#7](https://github.com/IAFahim/Pinhole.Net/issues/7)).
