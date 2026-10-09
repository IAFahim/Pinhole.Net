# IPv6 router firewall pinholes — local draft

This implements the IPv6 firewall-control requirement in
[#40](https://github.com/IAFahim/Pinhole.Net/issues/40). It is local work pending
real socket/router checks, Kotlin parity, platform CI and publication. The parent
issue remains open. This feature does not establish an Internet-wide direct
connection success rate.

Global IPv6 avoids IPv4 address translation, but a router can still block incoming
connections. The UPnP `WANIPv6FirewallControl:1` service can grant a temporary
filter rule for a specific internal endpoint. Pinhole requests UDP protocol 17
and, when its TCP sidecar actually listens, TCP protocol 6. Each rule covers only
that protocol and the node's actual address and listening port. The remote host
and remote port are wildcarded to accept a new authenticated peer. Gateways may
refuse wildcard rules or deny router control entirely; neither response prevents
the node from binding or using other routes.

`EnableIPv6FirewallPinholes` defaults to `true` alongside `EnablePortMapping`.
Either flag can disable this router-control stage. Direct UDP disabled means no
UDP pinhole request; TCP disabled or a failed listening bind means no TCP request.
Loopback binds, IPv4-only binds, virtual test sockets and raw iroh transport do not
request these rules. Only global IPv6 addresses on active Wi-Fi/Ethernet links
qualify, with at most two source addresses and four live workers. Interface or
address changes withdraw and release the old leases. Cancelled discovery workers
remain bounded during rapid churn.

IPv6 SSDP queries go to `ff02::c` on the selected local interface. The client pins
each description to the responding link-local or ULA address and uses only control
URLs for that address. It refuses DNS-based locations, remote/global description
addresses, redirects, URL credentials, XML entities and responses over 64 KiB.
This deliberately bounded discovery does not contact a router discovered only
through an IPv4 description. A gateway without a usable IPv6 description supplies
no lease.

Router-control HTTP binds to the same global IPv6 address sent as `InternalClient`,
so the gateway can apply its ordinary control-point authorization. Before creation
and each renewal, `GetFirewallStatus` must report both firewall enabled and inbound
pinholes allowed. `AddPinhole` requests a one-hour lease. A validated 16-bit
`UniqueID` identifies that exact lease for `UpdatePinhole` and `DeletePinhole`;
zero is a valid ID. Renewals occur at half the granted lifetime using the shared
serialized lease worker. Failed renewals and expiry withdraw the diagnostic grant;
rebind/disposal releases it with a bounded deadline. Rules also expire at the
gateway if cleanup cannot reach it.

`PinholeNode.IPv6FirewallEndpoints` and `TcpIPv6FirewallEndpoints` report currently
granted UDP and TCP endpoints separately. These endpoints already appear as host
candidates: pinholes do not translate addresses or manufacture another public IP.
An empty list means no live grant, not a measured blocked route. A grant is router
permission, not proof that the host firewall or remote network allows the traffic.
Only the authenticated session's direct path establishes actual connectivity.

Independent SOAP fixtures cover exact arguments, both protocols, permitted and
refused policies, fault responses, malformed IDs/XML, lease limits, namespace
variants, renewal and deletion. Lifecycle fixtures cover address/port changes,
late replies after shutdown and worker limits during rapid interface churn.
Separate real socket tests check IPv6 SSDP and source-bound HTTP. The restricted
workspace cannot execute those socket tests; platform and real-router evidence is
still required before release.

Protocol reference: [UPnP WANIPv6FirewallControl:1 service, sections 2.4 and 2.6](https://upnp.org/specs/gw/UPnP-gw-WANIPv6FirewallControl-v1-Service.pdf).
