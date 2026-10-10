# Physical phone ↔ desktop trial — 2026-10-11

Real-device validation of the transport between the Kotlin dialer and the C#
engine on physical hardware over real networks, including a live Wi-Fi↔cellular
handoff. Supersedes the first draft of this file (see *Correction* below).

## Setup

- **Desktop** (listener): Arch Linux x64, .NET 10, this repository at `59c29eb`
  (main, CI green). Online echo host (`echo-host.cs`): `PinholeNode.BindAsync`
  with public STUN, n0 iroh relay URLs, mDNS and network watch — accepts one
  peer and echoes every datagram. Direct UDP and port mapping were disabled
  in the helper committed at `0ba65a1`; that helper alone does not reproduce
  every mode in the table. The configurable helper now reports these options
  and the actual primary/TCP listening ports explicitly.
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
| `-e tcpOnly true` (ephemeral port) | **FAIL** | timeout 30 s | 0 | host firewall dropped the inbound SYN — see below |
| `-e tcpOnly true`, port 53317 permitted (primary ticket) | **PASS** | 313 ms | 48/48 | 10 / 48 ms (LAN `DirectTcp`) |
| `-e tcpOnly true`, port 53317 permitted (full ticket) | **PASS** | 389 ms | 48/48 | 10 / 45 ms (LAN `DirectTcp`) |
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
146 ms for the first echo after the test observed Wi-Fi again. First-echo
timings start with the first send after the requested Android network is
observed; they exclude radio-transition waiting and the initial connection.
These counters describe the logical session and selected path; they do not
count underlying relay WebSocket/TLS reconnections. The engine trace
shows the node punching the phone's Wi-Fi, link-local, and public addresses
throughout while the relay carried the session.

### tcpOnly — resolved: a host firewall port restriction, not a dialer defect

The original 30-second failure advertised an **ephemeral** TCP port. The host
runs UFW with a default DROP input policy whose user rules permit incoming
TCP/UDP on **53317** only, so the phone's SYN never reached the node — the
engine trace showed no frames because none arrived. This also explains the
pattern of the night's other results: the relay path is an outbound-initiated
WebSocket and direct UDP is opened by the host's own punch packets (both pass
stateful inspection), while inbound-first TCP on an unpermitted port is
silently dropped.

The follow-up coordinator (`tcp-trial.py`, reproduction below) bound the host
to the already-permitted port 53317 and re-ran the phone test with fresh
owned hosts and tickets, no firewall or radio changes:

```
primary-ipv4-direct: PASS   connect 313 ms, echoes 48/48, rtt p50 10 ms / p95 15 ms / max 48 ms
full:                PASS   connect 389 ms, echoes 48/48, rtt p50 10 ms / p95 12 ms / max 45 ms
path=DirectTcp(address=/192.168.0.187:53317)   host: PEER encrypted=True kind=Direct transport=Tcp
```

Both the primary IPv4 direct-only ticket **and** the full ticket (reflexive,
relay and scoped-IPv6 candidates included) connect over physical TCP on the
LAN, so the dialer's candidate racing, TCP framing and pinned-key
authentication all work; the earlier reflexive-hairpin suspicion is withdrawn.
The full report with assembly, core, APK and ticket hashes is
`tcp-trial-report.json`; raw tickets stayed in private local logs.

Scope of this resolution: same-LAN TCP. A dialer on another network still
needs the host on a reachable port (bound explicitly or forwarded); WAN TCP
and simultaneous-open variants remain future #43 work, and no firewall rule
was changed to obtain these passes.

## Correction

The first draft of this trial reported `relayOnly`/`tcpOnly` as a
"reproducible cross-implementation relay data black hole" and locally
"exonerated" the C# relay path. That finding was **wrong**: the failures were
an artifact of the desktop harness — backgrounded echo-host restarts silently
died (a `pkill` pattern was matching its own launching shell), and the test
runs were handed **stale tickets belonging to dead nodes**; the dialer could
never have connected. With a verified single live host and a ticket read from
its own log, `relayOnly` passes 48/48 at 139 ms p50 (and default mode also
passes on a pure relay path). `tcpOnly` on an ephemeral port also failed for a
host-side reason — the firewall port restriction resolved above — not a
dialer or relay defect. The C#↔C# relay-only probe (`relay-only-probe.cs`)
remains valid and passing.

## Reproduction

```bash
# desktop: from the repository root, one owned process and fresh ticket per run.
# Choose a port already permitted on YOUR host; 53317 is this machine's rule.
PINHOLE_TRACE_FILE=/tmp/trace.txt dotnet run \
  --project docs/evidence/phone-trial-2026-10-11/EchoHost.csproj -- \
  --port 53317
# For TCP isolation, append --disable-direct-udp --disable-port-mapping.
# First run with --primary-direct-only; restart without it for the full-ticket run.
# This preserves the peer ID and pinned keys while omitting reflexive, relay,
# scoped IPv6 and alternate UDP-only interface tuples from the diagnostic ticket.
# Verify HOST_PID, PORT and TCP_PORT; use only THIS live process's TICKET.

# phone: harness (restart the host between runs — single accept)
adb shell am instrument -w \
  -e pinholeTicket 'pinhole1:…' \
  [-e relayOnly true | -e tcpOnly true] \
  org.pinhole.devicetest.test/androidx.test.runner.AndroidJUnitRunner

# handoff: the test waits on the operator; toggle on the WAIT_HANDOFF cues
adb logcat -v time | grep --line-buffered WAIT_HANDOFF   # stage=1 → cellular …
```

For the bounded TCP comparison, build the helper and run the coordinator with
the phone already on the same Wi-Fi network:

```bash
dotnet build docs/evidence/phone-trial-2026-10-11/EchoHost.csproj
python3 docs/evidence/phone-trial-2026-10-11/tcp-trial.py \
  --adb /home/i/.android-sdk/platform-tools/adb --port 53317
```

The coordinator creates a private output directory, hashes the host/core
assemblies and installed test APKs, then runs primary IPv4 direct-only and full
tickets against separate owned host processes. It confirms each host's PID,
primary/TCP port and effective options before using its freshly printed ticket.
A unique log marker excludes old phone events. Passing requires the one Android
test to complete successfully, its fresh TCP event to report 48 verified echoes,
and the host to report encryption, TCP transport and at least 48 echoed frames.
An assumption skip, empty engine trace or stale success line cannot pass.
The coordinator stops only its own host/logcat processes and the test package;
it does not change radios, VPN, firewall rules or installed packages. Raw logs
and tickets remain private; the JSON summary contains hashes and verdicts.

### Local follow-up and physical retest

A host launch exposed an engine cleanup bug: disposal of the not-yet-created
UDP socket replaced the bind error with `NullReferenceException`. Cleanup now
tolerates that absent socket, preserving the original error. Injected
AccessDenied/AddressAlreadyInUse regressions cover both PinholeNode and raw
IrohTransport binding; all four cases pass on each of .NET 8 and .NET 10,
and the rebuilt host now exits cleanly with `BIND_FAILED
socket-error=AccessDenied native-error=13`. The authoring session that fixed
this was sandboxed (no adb, no sockets), so its coordinator run recorded
`BLOCKED` at ADB preflight. A full-access session then executed the
coordinator for real on port 53317 with the phone attached on Wi-Fi: both
profiles passed (results above, `tcp-trial-report.json`). Its first attempt
also caught a script bug — the APK-path validator rejected Android's `~~`
randomized `/data/app` directories — fixed before the recorded run.

## Honest scope

- One device, one OS (Android 16), one Wi-Fi AP + one LTE carrier
  (Teletalk), relay-path handoff (aps1-1). No VPN, no suspend/resume, no
  iOS, no carrier-GNAT-only direct punching (the direct PASS was same-LAN).
- Direct-path handoff (punching through LTE CGNAT after the switch) was not
  isolated: the session rode the relay across the handoff, which is the
  designed continuity mechanism; `pathChanges=0` reflects that.
- tcpOnly validated same-LAN with the host bound to the firewall-permitted
  port (both ticket profiles, `DirectTcp`, 48/48 echoes). WAN TCP, port
  forwarding and simultaneous-open variants remain open #43 work.

## Files

- `logcat.txt` — full device log for the first-session window
- `test-runner-events.txt`, `handoff-and-redo-events.txt` — pass/fail/stage events
- `echo-host.cs`, `EchoHost.csproj`, `relay-only-probe.cs` — the probes used
- `tcp-trial.py`, `tcp-trial-report.json` — physical TCP coordinator and its
  hash-only summary (raw tickets stayed in private local logs)
- `phone-*.png` — app-flow screenshots (fake-STREAMING defect on the way)
