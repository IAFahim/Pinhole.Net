# Pinhole.Net

A connection library for .NET. The bottom layer — nothing else.

One job: **get a connection between two machines, then keep it open until the app closes it.**

- **All free infrastructure.** Every free STUN server and every free relay — Google, Cloudflare, iroh's public relays, any standard TURN server. Consumed as protocols from pure C#, never as wrapped libraries.
- **Connection string, iroh-style.** An endpoint produces a connection string (stable peer ID + relay + direct candidates); the other side dials it. How the string travels between the two peers — clipboard, your server, your game lobby — is the application's concern, not this library's.
- **Open forever.** WiFi→mobile, IP changes, NAT rebinding, path death: the connection re-punches, migrates, or falls back to relay and stays up — modeled on how iroh keeps connections alive. It closes when you close it.
- **Bring your own protocol on top.** UDP, TCP, QUIC, your own — with your own libraries. Pinhole doesn't provide those and never will. It does the hard bottom part only.
- **Unauthenticated, unencrypted, unreliable — by design.** Do encryption, authentication, and reliability above this layer.

## The libraries

- `src/Pinhole` — the connection core (`Pinhole` package, net10.0): punch, STUN probe, datagrams — one UDP socket, zero allocations on the hot path
- `src/Pinhole.Turn` — TURN relay client (RFC 5766): allocate/permission/send+data indications against any standard TURN server
- `src/Pinhole.Providers` — catalog of all free endpoints: Google/Cloudflare/Metered/OpenRelay/Twilio STUN+TURN presets
- `src/Pinhole.Rendezvous` — optional rendezvous/introducer server (single binary, deployable anywhere a UDP port is open)
- `src/Pinhole.Iroh` — legacy bridge onto the iroh **Rust library** — being removed in [#8](https://github.com/IAFahim/Pinhole.Net/issues/8); after that, iroh remains in the picture only as free public relay infrastructure, consumed as a protocol
- `samples/Pinhole.Demo` — register/punch/chat demo + throughput bench + stun/turn/iroh probes
- `tests/Pinhole.Tests` — loopback xunit suite: punch/ping/data, STUN+TURN against in-process fake servers, rendezvous protocol + bounds, teardown bounds

## Build & test

```bash
git clone --recurse-submodules https://github.com/IAFahim/Pinhole.Net   # submodule goes away with #8
cd Pinhole.Net
# one-time, until #8 removes the iroh bridge: cargo build of the native lib
dotnet build extern/irohnet/N0.IrohNet.NativeAssets.Linux -f net10.0 -r linux-x64
dotnet build Pinhole.Net.slnx -p:TargetFrameworks=net10.0   # pin keeps the submodule's mobile TFMs out
dotnet test tests/Pinhole.Tests        # self-contained: no network, no cargo needed
```

After [#8](https://github.com/IAFahim/Pinhole.Net/issues/8) the clone needs no submodules, no cargo, no TFM pin — plain `dotnet test`.

## Run it — own rendezvous

```bash
dotnet run --project src/Pinhole.Rendezvous -- 7777            # signaling box
dotnet run --project samples/Pinhole.Demo -- 127.0.0.1:7777 aaaa        # listen
dotnet run --project samples/Pinhole.Demo -- 127.0.0.1:7777 bbbb aaaa   # dial
```

## Run it — iroh infra (free, no server)

```bash
dotnet run --project samples/Pinhole.Demo -- iroh          # prints ticket, listens
dotnet run --project samples/Pinhole.Demo -- iroh <ticket> # dials via iroh, then punches
```

Today this rides the iroh Rust bridge: both sides exchange UDP port + address candidates
over an iroh stream, then Pinhole punches its own raw-UDP pinhole, with the iroh stream
as the relayed fallback channel. The bridge is temporary scaffolding — the destination
shape is the [#4](https://github.com/IAFahim/Pinhole.Net/issues/4) session API: a
connection string in, an open-forever connection out, relay = free public infrastructure.

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

## Status & roadmap

Done: punch/TURN/rendezvous hardening ([#1](https://github.com/IAFahim/Pinhole.Net/issues/1)),
safe-layer migration ([#2](https://github.com/IAFahim/Pinhole.Net/issues/2)),
25-test suite + 3-OS CI + bench canary ([#3](https://github.com/IAFahim/Pinhole.Net/issues/3)).

Next: drop all Rust, standalone ([#8](https://github.com/IAFahim/Pinhole.Net/issues/8)) →
connection strings + N-peer + direct/reflexive/relay chain ([#4](https://github.com/IAFahim/Pinhole.Net/issues/4)) →
open-forever roaming ([#5](https://github.com/IAFahim/Pinhole.Net/issues/5)) →
NAT/path/payload tools ([#6](https://github.com/IAFahim/Pinhole.Net/issues/6)) →
1.0 ship ([#7](https://github.com/IAFahim/Pinhole.Net/issues/7)).
