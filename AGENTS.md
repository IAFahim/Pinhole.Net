# AGENTS.md — machine/phone facts that are expensive to rediscover

Verified 2026-10-11 during the physical phone trials and QUIC probe runs.
Read this before running any device or network work; it exists so agents stop
re-deriving the environment (or wrongly declaring it blocked) each session.

## Code style rule: NO `///` XML doc comments

The maintainer finds them noise. Every `///` line was stripped repo-wide once
(2026-10-25) — **never write `///` doc comments in this repo, on any member,
public or internal.** `Directory.Build.props` suppresses the missing-doc
warnings (CS1591 & co.) so builds stay clean without them. State a constraint
in a plain `//` comment only where the code cannot say it itself; anything a
user needs lives in `docs/*.md`, not in the source.

## This machine's environment (Arch/Omarchy desktop)

- **adb is not on PATH.** It lives at `/home/i/.android-sdk/platform-tools/adb`.
  A `command not found` here does NOT mean no device access — agents have
  wrongly concluded that. The Android SDK dir is `/home/i/.android-sdk`
  (set it in `local.properties` as `sdk.dir` for Gradle builds).
- **The machine has real internet and UDP sockets.** If a tool reports
  `AccessDenied (native 13)` on socket creation, `gh: error connecting`, or
  `could not install *smartsocket* listener`, that is the *calling agent's
  sandbox*, not the host. Never record "network unavailable" as a finding
  until an unrestricted session confirmed it — this produced a false
  "QUIC unsupported / UDP denied" BLOCKED report once already.
- **Host firewall: UFW enabled, default DROP input; user rules allow inbound
  TCP/UDP on port 53317 only.** Anything that must *receive* inbound
  connections (direct-TCP trials with the phone as dialer) must bind 53317.
  Ephemeral ports are silently dropped — this caused the false "tcpOnly
  dialer defect" (resolved 0e08c76: relay passes because the host dials out;
  direct UDP passes because host-initiated punching opens the stateful flow;
  inbound-first TCP on an ephemeral port just dies).
- **libmsquic is not installed system-wide**, so `QuicConnection.IsSupported`
  is false until provided. User-space fix without root: extract Microsoft's
  `libmsquic_*_amd64.deb` (packages.microsoft.com ubuntu/24.04/prod pool),
  symlink `libmsquic.so` to the extracted `libmsquic.so.2.*`, and run with
  `LD_LIBRARY_PATH=<dir>`. See `docs/evidence/quic-probe-2026-10-11/`.
- .NET SDK 10 + 8, cargo 1.98.1 with Quinn/rustls crates already in
  `~/.cargo/registry` (offline Rust builds work).

## The test phone

- OPPO/OnePlus **CPH2819, Android 16**, USB adb, authorized (serial `4cf0b91a`).
- Wi-Fi on the home LAN: phone `192.168.0.205`, desktop `192.168.0.187`.
  Dual SIM: **Teletalk** ("Stay Home-Teletalk") has LTE data; Grameenphone is
  voice-only. `svc data enable` / `svc wifi enable|disable` control radios;
  Wi-Fi can silently drop after SIM changes — check `ip addr show wlan0`.
- Microphone/runtime permission dialogs are granted by tapping the dialog
  (`input tap x y` from a `exec-out screencap -p` screenshot), not `pm grant`
  (shell lacks GRANT_RUNTIME_PERMISSIONS on this device).

## Device-test harness (`org.pinhole.devicetest`)

- Instrumented runner, already installed (debug build). One test run:
  ```
  $ADB shell am instrument -w -e class \
    org.pinhole.devicetest.PhysicalPeerTest#encryptedRoundTripsAcrossThePhysicalNetwork \
    -e pinholeTicket 'pinhole1:…' [-e relayOnly true | -e tcpOnly true] \
    org.pinhole.devicetest.test/androidx.test.runner.AndroidJUnitRunner
  ```
- Results go to **logcat tag `PinholeDeviceTest`**: `PASS device=… path=…
  connectMs=… echoes=… rttP50Ms=…`, and for handoffs `WAIT_HANDOFF stage=N
  network=…` (the test **waits for the operator** to switch radios on these
  cues — automate with a logcat watcher calling `svc wifi disable/enable`),
  then `PASS_HANDOFF_COMPLETE …`.
- The handoff test also needs `-e networkSequence wifi,cellular,wifi`.

## Trial discipline (learned the hard way)

- **The C# echo host accepts ONE peer per process.** Start a fresh host per
  run and pass only the ticket printed by *that live process* (grab with
  `grep -oP 'TICKET \Kpinhole1:\S+' host.log`). Stale tickets from dead
  hosts look exactly like a transport "black hole" — that false finding was
  once published and had to be retracted.
- For TCP trials use the committed coordinator instead of improvising:
  `docs/evidence/phone-trial-2026-10-11/tcp-trial.py --port 53317 --adb
  /home/i/.android-sdk/platform-tools/adb` (fresh owned hosts, hash-only
  report, strict PASS gates).
- **Shell trap:** `pkill -f`/`pgrep -f` patterns match your own `bash -c`
  wrapper text and self-kill the command. Use a bracket:
  `pkill -f "EchoHos[t].dll"`. Keep kill and launch in separate commands.
- **Ground truth for "is traffic flowing" is kernel counters**:
  `/proc/net/snmp` Udp In/OutDatagrams on both ends, `ss -tin` byte counts
  (beware IPv6-mapped `[::ffff:IP]:443` form). SELinux hides app sockets from
  phone-side `ss`. Vision/OCR tools have fabricated readings here — never
  cite them as evidence.
- Pinhole engine tracing: `PINHOLE_TRACE=1` (console) or
  `PINHOLE_TRACE_FILE=<path>` (per-line file writes; env prefixes don't
  propagate to backgrounded processes — export in a launcher script).

## Evidence conventions

Results live in `docs/evidence/<topic>-<date>/` with a README stating scope
honestly; raw `pinhole1:` tickets never enter committed logs (hashes only).
Post significant physical-network results to the tracking issue (#33/#43).
CI: 20 jobs on every push; timing-sensitive tests occasionally flake on a
first pass and pass on rerun (seen: `PcpClientTests.Mapping_Retries…` on
Ubuntu, `CryptoTests.WireOracle_LatePunch…` on macOS). Rerun failed jobs
before investigating.
