# Runnable sample verification — 2026-10-12 and 2026-10-13

These checks run the actual console sample executables and verify received
messages or downloaded bytes. A build or a completed handshake alone is not a
delivery check. The process harness is [samples/verify.py](../../../samples/verify.py).

## Desktop process checks

| Options | Passing cases | Scope |
| --- | --- | --- |
| Isolated loopback | 8 | Tiny, Demo interoperability, stale-ticket retry, group forwarding/rejoin, files/directories, UDP code directory, three mesh rounds/live guest, clean CLI errors |
| Default infrastructure | 6 | Tiny, Demo, group, files, code directory and mesh |
| iroh only | 6 | Same cases; direct UDP/TCP disabled |
| Tailcat DERP only | 8 | Full process matrix; direct UDP/TCP and other relays disabled |
| Direct TCP only | 5 | Tiny, Demo, group, files and code directory; direct UDP and relays disabled |
| Local Worker | 2 | CloudflareChat and CodeShare; external networking disabled |
| Deployed development Worker | 2 | CloudflareChat and CodeShare, default infrastructure |

The checked Worker is `https://pinhole-coordinator.fahimmanowarj5.workers.dev`.
The local Worker entry point also passed its 48 encrypted echoes in each
direction on both .NET 8 and .NET 10, and then ran the actual console samples.
All 13 sample projects built in Release with warnings treated as errors,
including the separate Cloudflare, MoQ, QUIC, WebRTC and Tailcat probes.
Build success for a probe does not imply its external service was exercised.

The local tests use separate processes on one desktop. Forced relay runs do
exchange traffic through the real public relay services, but they do not
establish connectivity through two physical home NATs. File transfers include
two downloads from the same live sender, a directory, an empty file and paths
with spaces; every output byte is compared with its source.

The first group-check harness incorrectly required a new participant to have
received a message before sending a message to that participant. The corrected
check explicitly verifies both directions after the rejoin. `auto.json` and
`derp.json` retain the initial harness failure names and the replacement passing
cases; `loopback.json` is a clean full run. The mesh reruns also cover the newly
buffered guest/ACK exchange.

Invitations appear only as SHA-256 hashes in these reports. No live tickets,
coordinator tokens or TURN credentials are recorded.

## Reproduced sample defects and changes

- Mesh's relay-only invitation filter discarded both identity keys, producing
  a plaintext invitation that encrypted peers rejected. The filter now retains
  both keys and DERP candidates, and disables direct transports in the options.
  All three nodes failed the original relay-only run; the corrected runs verify
  all three rounds and a guest through each HTTPS provider.
- Demo used unbuffered event receives and waited for console input before
  accepting. It now uses the same buffered invitation/chat flow as Tiny and
  accepts while its paste prompt is open.
- Tiny canceled its accept before dialing and exited after a timed-out join.
  It now keeps accepting, reports the failed attempt and permits a retry. The
  stale-host test then connects to that same waiting process without restarting.
- Mesh guest welcomes could be missed before event subscription. Buffered
  receives and a retried welcome/ACK exchange now verify that the guest read it.
- Send and CodeShare now pass cancellation through startup and receive work,
  and report startup failures cleanly. Send accepts quoted, copy-safe tickets.
- The runnable samples share transport diagnostic options and keepalives.
  CodeShare is now included in the solution build. CI exercises the actual
  sample processes on all three desktop operating systems.

The chats remain datagram examples without application message retransmission.
Public relays and the development coordinator remain best-effort services.
All peers need the current build; old downloaded executables do not update
themselves, and the group chat envelope differs from plain chat.

## Independent Windows/Linux/macOS machines

The final [Sample network run 38370976673](https://github.com/IAFahim/Pinhole.Net/actions/runs/38370976673)
passed on source commit `9afd69f4ea14a3523387900f2a097da92f2c530d`.
The three `remote-final/peer-*.json` reports contain distinct machine hashes
and Windows/Linux/Darwin OS values. All three runners also passed the eight
isolated runnable-process cases before beginning the cross-machine checks.

| Configuration | Verified app behavior | Machines |
| --- | --- | --- |
| Default | Tiny/Demo chat in both directions; group forwarding and reconnect; byte-checked 32 KiB file | Linux/Windows pair; all three machines in the group |
| iroh only | Same chat, group and file checks, direct UDP/TCP disabled | Same independent machines |
| Tailcat DERP only | Same chat, group and file checks, direct UDP/TCP and other relays disabled | Same independent machines |
| Deployed development Worker | CloudflareChat messages in both directions and CodeShare's greeting/reply | Linux/Windows pair; macOS observes completion |

These are independent hosted machines using real sockets and public services.
They establish cross-OS application delivery. They do not stand in for every
home/cellular NAT, firewall or mobile client. An `observer` role in a report
means that runner coordinated the case but did not exchange that case's app
payload; group cases use all three participants.

The earlier `remote-first/` reports document the initial Windows TLS failure
after default/iroh cases passed. The `remote-coordinator/` reports independently
verify the coordinator examples before the TLS fix. They are retained with
their original statuses; the final pass is not inferred from those failures.
Signaling invitations were encrypted with a per-run AES-GCM key in a temporary
Git branch. That branch and the key artifact were removed after each run.
Only hash-only/otherwise sanitized result artifacts are copied here.

## Windows TLS comparison and managed fallback

Build 26100's native .NET TLS failed for all four relays before certificate
validation, under both TLS 1.2 and TLS 1.3 and with/without ALPN. The same
Windows runner's curl/Schannel HTTPS request succeeded. The public server's
certificate list includes an unrelated Ed25519 non-CA DERP metadata certificate.
This extra certificate is a suspected native interoperability trigger; the
diagnostics do not prove the exact failing Schannel implementation step.

The `managed-tls/windows-native-before.json` report captures the failure.
After the adapter retried the specific `0x80090308` error using managed TLS,
`managed-tls/windows-after.json` passed three encrypted echoes through every
relay. The trace confirms that fallback was used on that runner. The
`managed-tls/net8.json` and `net10.json` reports force the managed connector on
Linux and pass all four real relays on each framework; the scope is same-host
public-relay connectivity, not a two-machine test.

Before push, 22 focused DERP/TLS/directory tests passed on each framework.
They include rejection of an untrusted chain, a wrong hostname and incorrect
server-authentication usage; the Ed25519 metadata never supplies trust. Async
TLS tests verify TLS 1.2/1.3, simultaneous read/write, a 32 KiB exchange, and
cancellation followed by a successful continued exchange. The full solution
built with warnings as errors and zero warnings/errors.

The owner-side Windows AI separately [reported native results](https://github.com/IAFahim/Pinhole.Net/issues/48#issuecomment-6141583394)
on Windows 11 Pro 23H2 build 22631.6936: 30/30 TLS configurations and all four
encrypted DERP probes passed on `bf45e2c`. These are that agent's reported
results, not tests executed on the Linux desktop. Its reports are discussed
in [issue #48](https://github.com/IAFahim/Pinhole.Net/issues/48).

## Physical Windows/Linux LAN exchange

The actual Tiny apps on both physical PCs used source `9afd69f`, direct TCP
only, with relays, STUN and discovery disabled. The Linux host bound its actual
interface at `192.168.68.113:53317`; the Windows PC was `192.168.68.108`.
The fresh listener's invitation came from that live process. Each process kept
its stdin pipe open and continuously drained stdout.

The Linux receiver printed `WINDOWS_AI_HELLO2` and then `WINDOWS_AI_ACK2`.
The Windows agent [reported its exact received lines](https://github.com/IAFahim/Pinhole.Net/issues/48#issuecomment-6142091372):
`LINUX_AI_HELLO2` and `LINUX_AI_ACK2`. Both apps reported
`Connected: Direct Tcp, encrypted=True`. The kernel's established TCP flow and
advancing byte counters corroborate the physical path; the received-message
markers supply the two-way application gate. Sanitized output and the kernel
snapshot are in `physical-lan/`. This is a real LAN test, not a cellular or
different-home NAT result.

The earlier physical trial verified the Windows-to-Linux hello only. The
Windows agent edited its still-open log in place, detaching subsequent output
from the file it inspected; reverse receipt therefore could not be established.
The Linux host was deliberately stopped at approximately 08:49 UTC for the
fresh run. The earlier trial is not counted as a two-way pass or evidence of a
transport failure. The fresh listener started at 08:49:55 UTC, and the Windows
peer joined around 09:01 UTC; the two-way report was posted at 09:02:46 UTC.
