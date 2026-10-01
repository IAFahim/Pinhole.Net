# Pinhole.Net

Lightweight NAT-traversal P2P transport for .NET — one UDP socket, no native dependencies.

Rendezvous + hole punching + keepalive, designed for multiplayer games and P2P apps.
Raw UDP fast path; NativeAOT throughout; zero allocations on the hot path.

- `src/Pinhole` — the client library (`Pinhole.Net` on NuGet, net10.0): punch, STUN probe, datagrams
- `src/Pinhole.Turn` — TURN relay client (RFC 5766): allocate/permission/send+data indications, any standard TURN
- `src/Pinhole.Providers` — known-provider catalog: Google/Cloudflare/Metered/OpenRelay/Twilio STUN+TURN presets
- `src/Pinhole.Iroh` — optional bridge: free rendezvous/signaling + relay fallback via n0's iroh infrastructure (via the [N0.IrohNet.Safe](https://github.com/IsaMorphic/N0.IrohNet/pull/50) submodule; needs `cargo` on Linux for the native lib)
- `src/Pinhole.Rendezvous` — the signaling/introducer server (single NativeAOT binary, deployable anywhere a UDP port is open)
- `samples/Pinhole.Demo` — register/punch/chat demo + throughput bench + stun/turn/iroh probes
- `tests/Pinhole.Tests` — loopback xunit suite: punch/ping/data, STUN+TURN against in-process fake servers, rendezvous protocol + bounds, teardown bounds

## Build & test

```bash
git clone --recurse-submodules https://github.com/IAFahim/Pinhole.Net
cd Pinhole.Net
# one-time: cargo build of the native iroh lib (also generates NativeMethods.g.cs via build.rs)
dotnet build extern/irohnet/N0.IrohNet.NativeAssets.Linux -f net10.0 -r linux-x64
dotnet build Pinhole.Net.slnx -p:TargetFrameworks=net10.0   # pin keeps the submodule's mobile TFMs out
dotnet test tests/Pinhole.Tests        # self-contained: no network, no cargo needed
```

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

Both exchange UDP port + address candidates over an iroh stream, then Pinhole
punches its own raw-UDP pinhole. If the punch fails, the iroh stream stays as
the relayed fallback channel.

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

## Status

Early: loopback/LAN punching verified via own rendezvous and iroh bridge;
multi-candidate spray, fallback stream, and clean teardown in place.
Symmetric-NAT relay fallback, crypto, and reliable channels on the roadmap.
