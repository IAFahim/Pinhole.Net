# Physical phone ↔ desktop trial — 2026-10-11

Real-device validation of the transport between the Kotlin dialer and the C#
engine on physical hardware over real networks, including a live Wi-Fi↔cellular
handoff. Supersedes the first draft of this file (see *Correction* below).

## Setup

- **Desktop** (listener): Arch Linux x64, .NET 10, this repository at `59c29eb`
  (main, CI green). Online echo host (`echo-host.cs`): `PinholeNode.BindAsync`
  with production defaults — public STUN, the four n0 iroh relay URLs, mDNS,
  port mapping, network watch — accepts one peer and echoes every datagram.
  Run with `PINHOLE_TRACE_FILE=...` for the engine trace used here.
- **Phone** (dialer): OPPO CPH2819 (OnePlus), Android 16, Wi-Fi on the home
  LAN, dual SIM with Teletalk LTE data (`Stay Home-Teletalk`, 47004), USB with
  adb. The prepared `org.pinhole.devicetest` instrumented harness
  (versionCode 1, debug build installed 2026-10-10) embeds the Kotlin
  `pinhole/` module; tests take `-e pinholeTicket <connection string>` plus
  `-e relayOnly true` / `-e tcpOnly true` / `-e networkSequence wifi,cellular,wifi`.
- The handoff test **waits for the operator** to switch radios on
  `WAIT_HANDOFF stage=N network=…` cues; we automated this with
  `svc wifi disable/enable` driven from a logcat watcher (`radio-cue` pattern
  below).

## Results

| Scenario | Outcome | Connect | Echoes | RTT p50 / max |
| --- | --- | --- | --- | --- |
| Default, direct upgrade | **PASS** | 1110 ms | 48/48 | 8 / 213 ms (LAN direct) |
| Default, relay path | **PASS** | 842 ms | 48/48 | 132 / 193 ms (aps1 relay) |
| `-e relayOnly true` | **PASS** | 812 ms | 48/48 | 139 / 183 ms (aps1 relay) |
| `-e tcpOnly true` | **FAIL** | timeout 30 s | 0 | dialer never reached the node |
| Handoff wifi→cellular→wifi | **PASS** | — | 48/50 | session preserved, 1 connection |

Raw lines: `handoff-and-redo-events.txt`, `test-runner-events.txt`, `logcat.txt`.

### Handoff evidence (the #31 roaming scenario, real hardware)

```
PASS_HANDOFF stage=0 network=wifi      echoes=16/16 firstEchoMs=159  rttMaxMs=188  path=Relay(aps1-1)
PASS_HANDOFF stage=1 network=cellular  echoes=16/18 firstEchoMs=2167 rttMaxMs=2167 path=Relay(aps1-1)
PASS_HANDOFF stage=2 network=wifi      echoes=16/16 firstEchoMs=146  rttMaxMs=165  path=Relay(aps1-1)
PASS_HANDOFF_COMPLETE stages=3 connectionAttempts=1 pathChanges=0
```

One encrypted session end-to-end (`connectionAttempts=1`): 2 of 18 echoes lost
while Wi-Fi dropped and LTE took over, first cellular echo 2.17 s later, and
instant recovery (146 ms first echo) when Wi-Fi returned. The engine trace
shows the node punching the phone's Wi-Fi, link-local, and public addresses
throughout while the relay carried the session.

### tcpOnly — open finding against the PR #4 draft dialer

The dialer times out after 30 s with **zero** traffic reaching the C# node (no
frames, no TCP connection; engine trace empty). The ticket was verified
(`TicketDump`) to carry `Direct 192.168.0.187:<port>` candidates where the
port is the TCP sidecar listener (confirmed listening via `ss`), so usable
TCP candidates exist. Prime suspect: the dialer dials the **reflexive**
candidate (`157.10.28.45:<port>` — the router's WAN address), which from
inside the LAN is a hairpin connection this router does not support. Needs
the PR #4 branch's dialer source to confirm; filed on OpusVoice PR #4.

## Correction

The first draft of this trial reported `relayOnly`/`tcpOnly` as a
"reproducible cross-implementation relay data black hole" and locally
"exonerated" the C# relay path. That finding was **wrong**: the failures were
an artifact of the desktop harness — backgrounded echo-host restarts silently
died (a `pkill` pattern was matching its own launching shell), and the test
runs were handed **stale tickets belonging to dead nodes**; the dialer could
never have connected. With a verified single live host and a ticket read from
its own log, `relayOnly` passes 48/48 at 139 ms p50 (and default mode also
passes on a pure relay path). Only `tcpOnly` still fails, as a genuine
dialer-side finding above. The C#↔C# relay-only probe (`relay-only-probe.cs`)
remains valid and passing.

## Reproduction

```bash
# desktop: one peer per process start; give the dialer THIS process's ticket
PINHOLE_TRACE_FILE=/tmp/trace.txt dotnet run echo-host.cs   # prints TICKET …

# phone: harness (restart the host between runs — single accept)
adb shell am instrument -w \
  -e pinholeTicket 'pinhole1:…' \
  [-e relayOnly true | -e tcpOnly true] \
  org.pinhole.devicetest.test/androidx.test.runner.AndroidJUnitRunner

# handoff: the test waits on the operator; toggle on the WAIT_HANDOFF cues
adb logcat -v time | grep --line-buffered WAIT_HANDOFF   # stage=1 → cellular …
```

## Honest scope

- One device, one OS (Android 16), one Wi-Fi AP + one LTE carrier
  (Teletalk), relay-path handoff (aps1-1). No VPN, no suspend/resume, no
  iOS, no carrier-GNAT-only direct punching (the direct PASS was same-LAN).
- Direct-path handoff (punching through LTE CGNAT after the switch) was not
  isolated: the session rode the relay across the handoff, which is the
  designed continuity mechanism; `pathChanges=0` reflects that.
- tcpOnly (the #43 sidecar from a real phone) remains unvalidated pending the
  PR #4 dialer fix.

## Files

- `logcat.txt` — full device log for the first-session window
- `test-runner-events.txt`, `handoff-and-redo-events.txt` — pass/fail/stage events
- `echo-host.cs`, `relay-only-probe.cs` — the two probes used
- `phone-*.png` — app-flow screenshots (fake-STREAMING defect on the way)
