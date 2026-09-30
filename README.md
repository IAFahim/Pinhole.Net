# Pinhole.Net

Lightweight NAT-traversal P2P transport for .NET — one UDP socket, no native dependencies.

Rendezvous + hole punching + keepalive, designed for multiplayer games and P2P apps.
Raw UDP fast path; NativeAOT throughout; zero allocations on the hot path.

- `src/Pinhole` — the client library (`Pinhole.Net` on NuGet, net8.0)
- `src/Pinhole.Iroh` — optional bridge: free rendezvous/signaling + relay fallback via n0's iroh infrastructure
- `src/Pinhole.Rendezvous` — the signaling/introducer server (single NativeAOT binary, deployable anywhere a UDP port is open)
- `samples/Pinhole.Demo` — register/punch/chat demo + throughput bench + iroh bridge demo

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

## Bench

```bash
pinhole-demo bench 100000 64
# 299k datagrams/s, 0 B/datagram allocated, 0 GCs (loopback)
```

## Status

Early: loopback/LAN punching verified via own rendezvous and iroh bridge;
multi-candidate spray, fallback stream, and clean teardown in place.
Symmetric-NAT relay fallback, crypto, and reliable channels on the roadmap.
