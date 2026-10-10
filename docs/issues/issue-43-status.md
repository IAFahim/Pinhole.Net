UDP, IPv6 and explicit router mappings still leave a gap when UDP is blocked but a peer can accept TCP. Add an authenticated direct TCP route to the managed Pinhole session engine and the Kotlin phone dialer. This is part of #40, created before implementation.

Design constraints:
- Keep existing v1/v2/v3 ticket envelopes and origin kinds wire-compatible. Direct/reflexive endpoint tuples may be tried using UDP and the new TCP sidecar; a sidecar normally listens on the same numeric port as UDP. Independently granted TCP mappings contribute additional reflexive tuples. Legacy peers can still use their UDP routes.
- Negotiate a versioned TCP framing preface, bound frame sizes/queues/connections, and use the existing key-pinned encrypted PUNC/PACK/HSCK session. A connected stream or unsealed probe must never promote an authenticated path.
- Prefer confirmed healthy UDP. Label confirmed TCP paths as direct TCP, with relay paths still reported separately. TCP has stream head-of-line behavior and is a fallback, not a new direct-connect guarantee.

Acceptance:
- [x] Managed TCP listener/active connector and bounded length framing, cancellation, deadlines, queue limits and teardown.
- [x] Full .NET encrypted session routing, path validation/failure recovery, direct UDP preference and authenticated reverse initiation over TCP.
- [x] Automatic PCP/NAT-PMP/UPnP TCP mappings with renewal/release and correct port/protocol fields.
- [ ] Kotlin transport/dialer parity, scoped IPv6 and Android app path reporting.
- [ ] Real IPv4/IPv6 TCP-only socket tests and .NET/Kotlin cases, including downgrade/key substitution, malformed/oversized frames, connection floods, close/rebind and disabled TCP.
- [ ] Preserve previous-version UDP interoperability and throughput floors.
- [ ] Evaluate TCP simultaneous-open using source-bound managed sockets on supported OSes; record actual capability/limitations rather than claiming every NAT can open.
- [ ] Platform CI, default/opt-out documentation and pushed implementation.

Primary reference: https://www.rfc-editor.org/rfc/rfc6544.html


## Implementation status — 2026-10-09

The managed .NET draft is implemented in `50cea0f`, with related interface/signaling hardening in `dd7f8ac`. It includes bounded framing/listener/connector lifecycle, a fresh encrypted per-stream challenge before path adoption, reverse initiation, UDP preference/recovery, and separate renewable/releasable TCP router mappings. TCP paths are labeled direct TCP rather than relay. Default TCP and explicit opt-out are documented in `docs/DIRECT_TCP.md`.

The latest local full solution build has zero warnings/errors. TCP framing, crypto/proof, stream-session and port-mapping fixtures are included in the 154 passing socket-free checks reported in #40. The actual IPv4/IPv6 TCP session/router tests compile but remain unexecuted in that local profile. These are implementation/model checks, not production-network validation.

Remaining: Kotlin transport/scoped IPv6/app labels, .NET/Kotlin and previous-version interoperability, real socket negative/flood/close/rebind cases, resource/throughput/platform checks and an actual source-bound OS simultaneous-open evaluation. There is no simultaneous-open or universal direct-connect claim. Keep this issue open until those acceptance criteria are met.


## Socket execution and evaluation — 2026-10-10

The current profile grants real loopback sockets, so the previously unexecuted
checks ran on Linux (net10.0, Release):

- Real socket suite: 588 passing checks including the TCP session tests over
  IPv4 (`127.0.0.1`) and IPv6 (`::1`) loopback — TCP-only dial/authenticate/
  exchange/close, UDP preference with TCP enabled, sidecar opt-out, malformed
  length and plaintext stranger refusal, and admission/disposal bounds.
- New hardening cases (`TcpSocketHardeningTests`): oversized frame headers
  (8193 and 65535) close the stream before any body read with no session
  created; a substituted ticket key over TCP-only fails fast with the explicit
  `possible man in the middle` InvalidOperationException, never downgrades,
  never surfaces to AcceptAsync, and both sides condemn their husks on
  schedule; close/rebind on the same numeric port tears down the old session
  and admits a fresh one.
- Simultaneous-open evaluation (`TcpSimultaneousOpenTests`): two source-bound
  managed sockets on `127.0.0.2`/`127.0.0.3` each connect to the other's bound
  tuple with jittered retries; the SYN crossing establishes both ends with no
  listener and payload crosses both directions. On this Linux host the first
  crossing took 11 attempts (~10% per attempt); macOS needs the CI loopback
  alias prep, and the probe skips honestly where secondary loopback addresses
  are unavailable. This records the OS primitive only — whether two production
  NATs pass the crossed packets is a per-network property, and no NAT-wide
  claim is made.
- Previous-version UDP interop: the interop harness gained `echo`/`dial`
  datagram modes; current-to-1.9.0 and 1.9.0-to-current exchanges encrypted
  direct UDP datagrams with byte-exact echoes in both dial directions.
  Recorded ceiling: a 1.9.0 peer's send API refuses payloads over 1176 bytes
  (its wire carries the current tree's 1200-byte frames inbound), so the
  shared datagram envelope across versions is 1176.
- Throughput floor: `Pinhole.Bench` measured 463,863 dps of 64-byte datagrams
  (300,000 sent) at 0.014 B allocated per datagram — 18.5x the 25,000 dps CI
  canary floor, with the UDP zero-allocation contract intact.

Kotlin dialer parity, scoped IPv6, and route labels ship in OpusVoice draft
PR #4 with device evidence (Wi-Fi→LTE→Wi-Fi and VPN handoffs); its listener /
simultaneous-open parity remains tracked here. Cross-machine production
validation remains under #33/#34/#35.
