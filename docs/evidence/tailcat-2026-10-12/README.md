# Tailcat DERP public-service probe — 2026-10-12

All four hosts in [Tailcat's dedicated DERP map](https://tailcat.dev/derpmap.json)
authenticated and carried three encrypted, byte-verified 32-byte round trips on
both .NET 8.0.31 and .NET 10.0.12. The production managed adapter used TLS and the
`derp` WebSocket subprotocol. Reports contain SHA-256 ticket hashes only.

Both peers ran on the Arch desktop. Direct UDP/TCP, iroh, TURN, STUN, LAN
discovery, and discovery publication were disabled. Every accepted connection
had encryption enabled and `PathKind.Relay` with the selected DERP URL.
These results establish protocol/service compatibility from this desktop;
they do not establish physical NAT traversal, phone/Kotlin interoperability,
multi-machine availability, or bandwidth. No shared-relay throughput test ran.

| Region | .NET 8 connect ms | .NET 10 connect ms | .NET 8 RTT p50 ms | .NET 10 RTT p50 ms | Result |
|---|---:|---:|---:|---:|---|
| Tokyo (`tc304a`) | 389.90 | 407.69 | 254.45 | 255.90 | PASS / PASS |
| Frankfurt (`tc303a`) | 503.78 | 514.82 | 338.49 | 342.41 | PASS / PASS |
| New York (`tc301a`) | 956.30 | 730.28 | 454.85 | 488.09 | PASS / PASS |
| San Francisco (`tc302a`) | 715.89 | 730.03 | 470.35 | 479.73 | PASS / PASS |

Connection timing starts after both nodes bind; RTT medians have only three
samples. These are observations of one run, not a framework performance
comparison or operator latency guarantee. The public fleet is
[free, rate-limited, and best effort](https://github.com/tailscale/tailcat#stability).

Raw reports: [net8.json](net8.json), [net10.json](net10.json).
Probe source and instructions: [Pinhole.TailcatProbe](../../../samples/Pinhole.TailcatProbe/README.md).

```sh
dotnet run --project samples/Pinhole.TailcatProbe -c Release -f net10.0 -- \
  --all --output /tmp/tailcat-net10.json
dotnet run --project samples/Pinhole.TailcatProbe -c Release -f net8.0 -- \
  --all --output /tmp/tailcat-net8.json
```

Deterministic local tests additionally exercise provider outages in both
directions, with the original encrypted connection continuing over iroh or
DERP; those tests do not simulate an outage of the shared public service.

## Local regression checks

The [test summary](tests-summary.json) records outcomes per framework. On both
.NET 8 and .NET 10, 636 functional cases passed after fixes and isolated reruns;
the real-coturn case was skipped because coturn is absent. Five previous-release
interop cases and seven resource cases passed per framework. Two opt-in soak
cases were skipped. The warnings-as-errors solution build passed with zero
warnings. The performance category and long soaks were not run for this change.

The first full runs exposed a multicast-family test failure, a .NET 8 reconnect
timing failure, and a relay-only test that allowed direct paths to open during
its assertions. The first two passed in isolated reruns; the relay-only test
now explicitly disables direct UDP/TCP. The new signed-discovery test also
needed distinct peer identity seeds. Added host/join cases verify both default
relay fleets through the enlarged, bounded UDP code directory and default
DERP fallback through the Worker coordinator. Summary counts combine the full
runs with the corrected and newly added scenarios; they do not claim a single
uninterrupted all-green run.
