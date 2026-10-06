# Connecting through iroh discovery and infrastructure

`IrohTransport` supplies the iroh-compatible **addressing and raw packet layer** in
`Pinhole.Net`. It is managed C# on .NET 8/10 and has no native transport dependency.
Your packet protocol runs above it.

```csharp
using Pinhole;

await using var transport = await IrohTransport.BindAsync(new IrohTransportOptions
{
    SecretKeySeed = persisted32ByteEd25519Seed,
    PublishAddress = true,
});

Console.WriteLine(transport.EndpointId);       // native iroh Ed25519 ID
Console.WriteLine(transport.Address);          // native endpoint... ticket

// Accepts a native iroh ticket or an ID published through iroh discovery.
IrohRoute route = await transport.ConnectAsync(androidEndpointIdOrTicket);

// Feed packets produced by your protocol engine, including its handshake.
route.Send(protocolWirePacket);
IrohDatagram packet = await transport.ReceiveAsync();
protocolEngine.HandlePacket(packet.Payload, packet.Path);

// Once that engine authenticates the peer and validates the return path:
route.SelectPath(packet.Path);
route.Send(nextProtocolWirePacket);
```

`ConnectAsync` resolves addressing and prepares candidate routes. A route is a
network resource, **not proof that the peer is online or authenticated**. The protocol
above it completes its handshake, determines successful connection establishment,
and validates paths. `Send` races the initial candidates until the caller selects
a validated path; it adds no handshake, retransmission, or framing of its own.
`SendTo` permits explicit per-path probes and return traffic. `SelectPath(null)`
resumes the initial candidate race after path failure. Re-resolve the peer ID if its
advertised addresses have changed.

For an unchanged Kotlin/Rust/Swift/Python iroh `Endpoint`, the protocol engine above
this socket must produce the packet protocol that endpoint understands. Current
iroh requires its QUIC/TLS handshake and uses QUIC NAT-traversal/path validation;
those cannot be replaced by sending arbitrary plaintext datagrams. Pinhole does
not implement that engine here. An application protocol selected by ALPN operates
after the endpoint's transport handshake. See the [native endpoint connection
API](https://github.com/n0-computer/iroh/blob/v1.3.0/iroh/src/endpoint.rs) and
[native path establishment](https://github.com/n0-computer/iroh/blob/v1.3.0/iroh/src/socket/remote_map/remote_state.rs).

This is the distinction between discovery/packet compatibility and an immediately
usable application connection. Ordinary `PinholeNode` / `PinholeConnection` still
use the Pinhole session protocol, documented in [PROTOCOL.md](PROTOCOL.md).

## What is compatible

| Layer | Behavior |
|---|---|
| Endpoint identity | The full 32-byte Ed25519 public key, not Pinhole's u64 locator. `SecretKeySeed` is the exact seed consumed by native iroh `SecretKey::from_bytes`. |
| Tickets | Parses and produces iroh 1.x `EndpointTicket`: postcard `Variant1`, native IP/relay addresses, unpadded base32 with the `endpoint` prefix. |
| Resolve by ID | GETs the native HTTP pkarr service (`https://dns.iroh.link/pkarr/<z32-key>`). Verifies its Ed25519 signature against the requested key before adopting addresses. |
| Publish by ID | PUTs the native signature + BE timestamp + DNS payload, using BEP 44 signatures and `_iroh.<z32-key>` TXT records. Native iroh DNS/Pkarr lookup can consume it. |
| Direct packets | One dual-stack UDP socket; packet bytes pass unchanged in both directions, including packets whose first byte overlaps Pinhole's frame tags. |
| Relay packets | Native iroh relay authentication and WebSocket v1/v2 framing, addressed by full endpoint ID. Datagram bodies pass unchanged. |
| Local reachability | Reuses STUN, PCP/NAT-PMP/UPnP, periodic STUN refresh, and OS network-change handling. `Address` reflects current candidates; `RoamNowAsync` refreshes them explicitly. |

Unknown experimental custom transport addresses (e.g. Tor/BLE) require their own
adapters; this API implements IP/relay paths. Legacy `node...` tickets and native
iroh mDNS are not implemented. Pinhole's `_pinhole._udp.local` service is not an
iroh LAN discovery service.

Publication is opt-in. By default, published records contain live relay URLs only;
set `PublishDirectAddresses = true` to include IP addresses. Automatic publication
runs at bind and then about every 30 seconds, with jitter and bounded outage
backoff. A persisted seed preserves the native endpoint ID across restarts.

Direct datagrams do not carry an authenticated source ID. Relayed datagrams report
their routing source ID, which also does not replace end-to-end authentication.
Neither packet arrival nor a discovery record selects a path automatically. The
receive queue is bounded (`ReceiveBufferCapacity`, default 256), dropping its
oldest packet when full; disposal unblocks waiting readers.
Direct packets may contain 0–65507 bytes; native relay packets require 1–65502
bytes. Your protocol must also respect the actual path MTU, which is generally
much smaller than either socket ceiling.

Only the network-related settings in `IrohTransportOptions.Network` apply:
bind, STUN, iroh relay URLs, port mapping, network watch, probe budgets, and
deadlines. Pinhole-specific encryption, TURN, lookup providers, LAN discovery,
keepalive, and PMTU/path-validation settings do not run in the raw transport.

## Verification

`IrohConnectivityTests` contains native iroh-ffi ticket/identity vectors and a
native iroh-dns signed-record fixture. It checks exact ticket encoding, signature
pinning, tamper/rollback refusal, direct IPv4/IPv6 address encoding, unchanged raw
UDP/relay packets, large packets, cancellation, and pending-reader disposal.
`RawIrohConnectivity_RealRelay_PreservesPacketsWithoutPinholeFraming` runs against
the external reference `iroh-relay` server when `IROH_RELAY_BIN` is configured,
including the maximum relay packet in both directions. It uses a relay-only
ticket and cannot silently use loopback UDP.

On 2026-10-07, an external official **iroh-ffi 1.1.0** peer completed its authenticated
handshake through `IrohTransport` in both direct and relay-only experiments. The
relay experiment used a real **iroh-relay 1.3.0** process on loopback and no direct
candidate in Pinhole's route. The upper packet engine ran externally; no native
library was added to Pinhole. A native **iroh-dns 1.3.0** decoder also verified a
managed signed publication. These are Linux interop experiments; an Android
device/background/roaming matrix has not been validated.

Issue history: [#2](https://github.com/IAFahim/Pinhole.Net/issues/2) introduced a
native bridge; [#8](https://github.com/IAFahim/Pinhole.Net/issues/8) removed it in
favor of a fully managed bottom layer; [#23](https://github.com/IAFahim/Pinhole.Net/issues/23)
reaffirmed managed C#. This API supplies native discovery and packet formats
within that constraint, while the upper protocol remains the application's job.
