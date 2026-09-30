# Pinhole.Net

Lightweight NAT-traversal P2P transport for .NET — one UDP socket, no native dependencies.

Rendezvous + hole punching + keepalive, designed for multiplayer games and P2P apps.
Raw UDP fast path; NativeAOT throughout.

- `src/Pinhole` — the client library (`Pinhole.Net` on NuGet)
- `src/Pinhole.Rendezvous` — the signaling/introducer server (single NativeAOT binary, deployable anywhere a UDP port is open)
- `samples/Pinhole.Demo` — two-process demo: register, punch, chat

## Run it

```bash
# terminal 1 — the rendezvous (your "signaling + STUN" box)
dotnet run --project src/Pinhole.Rendezvous -- 7777

# terminal 2 — a peer that listens
dotnet run --project samples/Pinhole.Demo -- 127.0.0.1:7777 aaaa

# terminal 3 — a peer that dials
dotnet run --project samples/Pinhole.Demo -- 127.0.0.1:7777 bbbb aaaa
```

## Status

Day-zero scaffold: loopback/LAN punching verified; symmetric-NAT relay fallback,
crypto, and reliable channels are on the roadmap.
