# Measure NAT behavior and coordinate bounded, evidence-based port prediction

Parent: https://github.com/IAFahim/Pinhole.Net/issues/40 (created before implementation).
This child issue body is prepared locally for publication by the user.

The existing multi-server hint compares mappings. It does not measure filtering,
prove a predictable allocation sequence or authorize trying arbitrary ports.

Implement independent RFC 5780 alternate-address measurements, strict STUN reply
correlation and conservative unknown results for missing capabilities or lost
responses. Report the actual tested source and timing; a dedicated diagnostic
socket must not be presented as the application's socket.

Add an authenticated, negotiated prediction round using sequential observations
from the actual application source. Bound sample count, candidate count, rate,
duration and concurrent work. Refuse inconsistent addresses, random allocation,
stale observations, port wrapping and unconfirmed peers. Predictions stay outside
published reflexive candidates and become direct paths only after normal peer
proof. Keep ordinary direct attempts and relay fallback available.

Validate independent protocol fixtures, mapping/filtering cases, unsupported
servers, wrong source/nonce/attributes, cancellation, packet loss, bounded work,
predictable and randomized allocation, old-peer behavior and real sockets/interop.
Do not infer universal reachability or reliable double-NAT detection from STUN.
