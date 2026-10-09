# NAT behavior measurements — local .NET draft

Parent: [#40](https://github.com/IAFahim/Pinhole.Net/issues/40).
Implementation is local; actual sockets, cooperating public servers, platform CI
and phone parity remain release checks.

`NatDetector.InspectAsync(server, ct)` uses a fresh diagnostic UDP socket and a
cooperating [RFC 5780](https://www.rfc-editor.org/rfc/rfc5780.html) STUN endpoint.
It returns `NatBehaviorReport`: the tested local endpoint, ordered mapped
observations, mapping behavior, positive filtering evidence, probe count and time.
It does not classify the application's already-active source socket.

The first reply must advertise a consistent `RESPONSE-ORIGIN` and a distinct
`OTHER-ADDRESS` address/port before alternate tests run. Filtering tests occur
before contacting the alternate destinations. Changed-address/port responses
establish endpoint-independent filtering evidence; after unanswered changed-address
tests, a changed-port response establishes address-dependent filtering evidence.
Each filtering test has at most two attempts. Silence remains `Unknown`, including
when the server advertises alternates but ignores change requests. Packet loss
can still affect any inference about restrictions.

Mapping tests compare the primary mapping with the alternate IP at the primary
port, then (when different) with the alternate IP/port pair. The report distinguishes
endpoint-independent, address-dependent and address-and-port-dependent mappings.
There are at most seven binding requests, each bounded by two seconds. Caller
cancellation propagates and disposes the diagnostic node/socket.

STUN replies must match the receiving socket, expected source and every byte of
the 12-byte transaction. The entire attribute stream is validated before an
observation completes. Known malformed/conflicting address attributes, invalid
origins, truncated padding, zero ports, multicast/unspecified mapped addresses and
address-family mismatches are refused. XOR-MAPPED-ADDRESS takes precedence over
legacy MAPPED-ADDRESS. These checks also apply to ordinary node/interface probes.

The ordinary `NatHint` remains mapping-only scheduling advice. Equal mappings do
not prove permissive filtering or connectivity to a particular peer. The diagnostic
pass does not measure binding lifetime, fragmentation or hairpinning and cannot
count NAT layers or guarantee behavior after the measurement.

Evidence: 19 socket-free checks use an independent four-socket STUN responder and
the actual engine's transaction handling over modeled NAT translation/filtering.
They cover full/restricted/port-restricted/symmetric NAT, IPv6, ordering, unsupported
change requests, malformed responses and cancellation. Two public-API socket checks
compile but have not run here. Model results are not physical network measurements.

[Port prediction](PORT_PREDICTION.md) uses separate fresh sequential measurements
from the actual application socket, rather than reusing this diagnostic report.
