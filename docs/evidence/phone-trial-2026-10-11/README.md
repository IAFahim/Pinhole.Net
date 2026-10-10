# Physical phone ↔ desktop trial — 2026-10-11

First real-device validation of the direct UDP transport between the Kotlin
dialer and the C# engine on physical hardware over a real network.

## Setup

- **Desktop** (listener): Arch Linux x64, .NET 10, this repository at `59c29eb`
  (main, CI green). Online echo host (`echo-host.cs`): `PinholeNode.BindAsync`
  with production defaults — public STUN, the four n0 iroh relay URLs, mDNS,
  port mapping, network watch — accepts one peer and echoes every datagram.
- **Phone** (dialer): OPPO CPH2819 (OnePlus), Android 16, Wi-Fi on the same
  LAN (192.168.0.0/24), **no cellular service** (`cellular=false`), USB with
  adb. The prepared `org.pinhole.devicetest` instrumented harness
  (versionCode 1, debug build installed 2026-10-10) embeds the Kotlin
  `pinhole/` module; tests take `-e pinholeTicket <connection string>` plus
  optional `-e relayOnly true` / `-e tcpOnly true`.
- Both endpoints behind the same home NAT; traffic left the box (real Wi-Fi,
  real STUN, real internet relays).

## Results

| Scenario | Outcome |
| --- | --- |
| Default (UDP + relay racing) | **PASS** — details below |
| `-e relayOnly true` | **FAIL** — relay handshake completes, first data frame never reaches the C# app (4 reproducible runs) |
| `-e tcpOnly true` | **FAIL** — same signature as relayOnly (1 run) |
| `encryptedConnectionSurvivesNetworkHandoffs` | Assume-skipped — requires cellular; the phone has no active SIM |

### Default mode — pass evidence

logcat (`10910`, 00:39:41):

```
PASS device=OPPO/CPH2819 android=16 cellular=false relayOnly=false tcpOnly=false
     path=Direct(address=/192.168.0.187:38373) connectMs=1110
     echoes=48 attempts=48 rttP50Ms=8 rttP95Ms=12 rttMaxMs=213
```

- Initial connection in **1.11 s** on real hardware (the UDP-first window),
  then **48/48 encrypted echo round-trips**, p50 **8 ms** / p95 **12 ms** /
  max 213 ms over Wi-Fi.
- The C# echo host printed `PEER encrypted=True kind=Relay` at accept while
  the phone reports `path=Direct`: the session established over the relay
  first and upgraded to the direct LAN path, on real devices,
  cross-implementation, exactly as designed.
- mDNS nearby discovery also worked end-to-end: the OpusVoice app listed the
  desktop receiver (`OpusVoiceReceiver` @ 192.168.0.187) without typing a
  ticket (`phone-23.png`).

### relayOnly / tcpOnly — reproducible interop defect

Signature (every run): the dialer completes the encrypted handshake over the
relay; the C# node accepts (`kind=Relay, encrypted=True`); **zero** data
datagrams ever reach `ReceiveAsync` on the C# side; the test fails with
`AssertionError: Echo 0 did not arrive before its deadline`
(`test-runner-events.txt`).

Exoneration: two C# nodes on this machine with `EnableDirectUdp=false` on
**both** ends (`relay-only-probe.cs`) round-trip 64-byte datagrams over the
same public relays, `kind=Relay` throughout, ~100 ms RTT — so the C# relay
data path is sound C#↔C#. The black hole is specific to the cross-implementation
relay path (Kotlin QUIC/iroh relay transport dialing in, C# WebSocket +
TURN-style permit model accepting). Suspect area: peer relay-address changes
or permit staleness across the two relay transports. Root cause needs a wire
capture or engine trace; not fixed by this trial.

### OpusVoice app (separate defect, found on the way)

The installed OpusVoice app (side-load built 2026-10-08) reached a UI state
showing `STREAMING` with a live path label while sending **zero packets** —
verified by both endpoints' counters (`/proc/net/snmp` Udp OutDatagrams
frozen on the phone, InDatagrams +72 over 4 min on the desktop). The first
START attempt showed a generic error dialog; a later attempt rendered the
streaming/stats cards with no traffic behind them. A debug build was
installed on the phone to continue diagnosis (`phone-01-home.png` …
`phone-28.png` show the flow). This is an app-level defect in OpusVoice,
not a transport failure — nothing ever left the phone.

## Reproduction

```bash
# desktop: echo host (one peer per process start)
dotnet run docs/evidence/phone-trial-2026-10-11/echo-host.cs   # prints TICKET …

# phone: harness
adb shell am instrument -w \
  -e pinholeTicket 'pinhole1:…' \
  [-e relayOnly true | -e tcpOnly true] \
  org.pinhole.devicetest.test/androidx.test.runner.AndroidJUnitRunner
```

The harness accepts **one** peer per echo-host process — restart the host
between runs or the second run fails on a dead accept queue.

## Honest scope

- One device, one OS (Android 16), one LAN, Wi-Fi only. No cellular handoff,
  no VPN, no suspend/resume, no iOS. This is *initial-connection + steady-state
  latency + reliability* evidence for the direct path on real hardware —
  not the full #33 support matrix.
- The relay-pinned failure means relay-only operation (blocked-UDP fallback
  for a mobile peer) is **not validated** and currently appears broken
  cross-implementation; tracked in OpusVoice PR #4 and blocking the #26
  "HTTPS-relayed" phone-side claim until root-caused.

## Files

- `logcat.txt` — full device log for the session window
- `test-runner-events.txt` — TestRunner pass/fail/assumption events
- `echo-host.cs`, `relay-only-probe.cs` — the two probes used
- `phone-*.png` — app-flow screenshots (fake-STREAMING defect on the way)
