# Pinhole.Moq (experimental)

A reusable C# publisher/subscriber for the Cloudflare MoQ Draft16 service,
using the official `System.Net.Quic` API. It carries arbitrary application
bytes in reliable QUIC subgroup streams. This project has no NuGet runtime
packages, project-owned P/Invoke, Rust bridge, media encoder or WebRTC stack.
`System.Net.Quic` itself uses Microsoft's native MsQuic; Linux needs libmsquic.
The API is preview on .NET 8 and stable on .NET 9+. Windows 11/Server 2022+
uses the MsQuic shipped with .NET; other platforms follow Microsoft's support
matrix and are not established by this Linux live run.

```csharp
using Pinhole.Moq;

using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
await using var sender = await CloudflareMoqClient.ConnectAsync(publishSubscribeToken, timeout.Token);
await using var receiver = await CloudflareMoqClient.ConnectAsync(subscribeOnlyToken, timeout.Token);
var outgoing = await sender.CreatePublisherAsync("room-unique-sender-a", "messages", timeout.Token);
await using var incoming = await receiver.SubscribeAsync("room-unique-sender-a", "messages", timeout.Token);
await outgoing.PublishAsync("hello"u8.ToArray(), timeout.Token);
var message = await incoming.ReadAsync(timeout.Token);
Console.WriteLine(System.Text.Encoding.UTF8.GetString(message.Payload.Span));
```

For two-way traffic, both devices use publish+subscribe credentials, each
publishes its own namespace, and each subscribes to the other's track. A
subscribe-only credential can receive objects but cannot create an outgoing
track. Namespace ownership is exclusive at Cloudflare: use separate namespaces
for different publishers. Namespace strings map to one UTF-8 namespace element;
compound namespace tuples are outside this subset. The caller supplies the names;
short-code discovery and credential issuance remain the application's job.
Issue suitably limited tokens from a trusted backend; never ship an account API
token in a player/client. This code never logs the MoQ bearer token or a URL
containing it.

Operations accept cancellation. Connection, registration, subscription and
publishing each have an additional 15-second deadline; connection idle timeout
is 60 seconds and normal shutdown has a 3-second close budget. Every incoming
subgroup stream also has a 15-second total lifetime: the peer must finish that
stream within the deadline. This message-oriented subset does not accept
indefinitely open media subgroup streams. Receivers queue
up to 16 objects of at most 64 KiB per track; up to 32 incoming subscription attempts
(including failed requests and retired aliases) and 32 outgoing tracks/namespaces are allowed per
session. Exceeding a receive queue fails the session instead of growing memory.
Dispose subscriptions to unsubscribe; dispose the client to close its owned
streams and background readers. Read operations wait for the next object and
use the caller's cancellation token.

The client implements `CLIENT_SETUP`, `SERVER_SETUP`, `PUBLISH_NAMESPACE`,
`PUBLISH`, `PUBLISH_OK`, `SUBSCRIBE`, `SUBSCRIBE_OK`, `REQUEST_OK`,
`REQUEST_ERROR`, forwarding updates, `MAX_REQUEST_ID`, `UNSUBSCRIBE`,
`PUBLISH_DONE`, and subgroup objects. It publishes one group with one object
per call. Unsupported control messages and malformed fields fail the session.
It does not expose media codecs, FETCH, namespace discovery, automatic GOAWAY
migration, reconnect, unreliable QUIC datagrams, or browser WebTransport.
Draft16 mandates QUIC DATAGRAM support for a fully conformant implementation;
.NET 8/10's public QUIC API does not expose that data path. This is a verified
Cloudflare stream compatibility subset, not a claim of complete Draft16
conformance or compatibility with every MoQ relay.

TLS protects each client-to-Cloudflare connection. Cloudflare can see object
payloads; this standalone adapter does not add Pinhole's end-to-end peer
cryptography. The shipping `PinholeNode` does not automatically select MoQ,
hole-punch through it, or switch an established Pinhole session onto it. This
optional project is deliberately separate from the core package and is not
packaged/published yet.

See the [live probe](../../samples/Pinhole.MoqProbe/README.md) and
[sanitized evidence](../../docs/evidence/cloudflare-moq-2026-10-11/README.md).
Protocol references: [Cloudflare endpoints and authentication](https://developers.cloudflare.com/moq/),
[Cloudflare feature matrix](https://developers.cloudflare.com/moq/feature-matrix/),
and [MoQ Transport Draft16](https://www.ietf.org/archive/id/draft-ietf-moq-transport-16.html).
Runtime deployment: [Microsoft QUIC platform support](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/quic/quic-overview).
