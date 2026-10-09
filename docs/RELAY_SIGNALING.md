# Relay signaling with direct application traffic — local draft

This implements the initial candidate-exchange and signaling-only requirement in
[#40](https://github.com/IAFahim/Pinhole.Net/issues/40). It is local work pending
real relay/socket/platform checks, Kotlin parity and release validation.

```csharp
await using var node = await PinholeNode.BindAsync(new PinholeOptions
{
    RelaySignalingOnly = true,
});
var connection = await node.ConnectAsync(peerTicket);
// Connect completed on authenticated direct UDP or TCP.
connection.Send(payload);
```

The default remains `false`: relays can carry encrypted application datagrams
when direct paths fail. Enable the new option at both endpoints when the
application requires direct data traffic but permits relay-assisted introduction.
It requires `Encryption = Required`; optional/plaintext policies are refused.
This is a local policy, not a command that changes an older peer's configuration.
An older peer can send relayed data under its own policy; this node will reject it.

When the peer's ticket advertises a relay, this mode first establishes session
keys and exchanges the current candidate lists through the relay. Initial direct
probes wait for the authenticated list. A receiver waiting for that list also
holds direct proof responses, so both current lists arrive before the direct
application path can complete. No application payload is needed to introduce the
peers. A ticket without relay candidates follows the ordinary authenticated
direct handshake. If the advertised introducer is unavailable, the initial
exchange can time out even when the ticket includes a reachable direct tuple:
this mode explicitly requires that introduction before using those tuples.

`ConnectAsync` and `AcceptAsync` complete only with a direct application path.
While authenticated relay control works but direct is pending, the connection
remains `Punching` with `Path.Kind = None`. `RelaySignalingReady` reports the
authenticated control leg without asserting an application route. A signaling
stranger is not queued for acceptance until direct succeeds, so it does not hold
the accept queue ahead of a working peer. Deadline/cancellation closes the dial
and can send an authenticated control `Bye` through the relay.

Relays may carry PUNC/PACK/HSCK, encrypted candidate announcements, control
ping/pong and close. Application `Data` is blocked at outbound relay routing and
after authentication on the inbound path. `RelayedDatagramsBlocked` counts those
authenticated inbound drops; receive events/buffers and application byte counters
do not include them. Existing direct UDP/TCP data paths remain usable.

If direct subsequently fails, this mode moves the same connection to `Punching`
with no application path. Relay signaling stays available to exchange updated
candidates and recover direct. Application sends fail while direct is unavailable.
The same connection object resumes after recovery; it never reports a relay data
route as `Degraded`. Control announcements retry once a second while punching.
Unchanged announcements do not keep extending the initial punch budget.

UDP completion in this mode requires encrypted direct evidence. Replaying an
unsealed PUNC at another address can receive an encrypted probe but cannot complete
a direct application connection by itself. Initial/reverse PUNC keys also honor
the ticket's pinned static key before changing tokens or deriving session keys.
TCP continues to require its fresh per-stream encrypted challenge.

The 15 offline checks run production iroh relay framing/authentication and Pinhole
session crypto over an independent bounded in-memory WebSocket relay. They cover
both candidate lists, gating of initial direct probes, announcement loss, default
relay fallback, direct failure/recovery, forbidden data, replay/tamper/static-key
substitution, blocked strangers, cancellation and honest timeouts. The virtual
network checks actual routing decisions in the engine, not physical firewall/NAT
behavior. Real HTTPS relay, TURN, socket/platform and Kotlin checks remain required.
