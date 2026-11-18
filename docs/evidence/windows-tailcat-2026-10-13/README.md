# Windows Tailcat verification — 2026-10-13

Owner's Windows PC verification for issue #48 / draft PR #47, run in the fresh
checkout `D:\GitHub\Pinhole.Net-tailcat-verify-20261013` at commit
`bf45e2c0b5e4dbc9363f2f17108d752e5a46161f` (branch `verify/tailcat-samples`).
Nothing here was committed or pushed (issue instruction 5); the report to the
Linux-side agent lives in issue #48 comments.

## Scope, honestly

- Same-host two-process probes through the **public Tailcat DERP relays** with
  direct UDP/TCP and all other relays disabled. This proves the relay path
  works on this Windows installation; it does **not** prove two PCs behind
  separate home NATs can connect.
- The one real cross-machine data point is `tiny-live.log`: a live direct-TCP
  `Pinhole.Tiny` chat with the Linux-side agent's listener (192.168.68.113,
  same /24), ticket supplied in issue #48. One peer per ticket, live process
  only.
- Certificate and hostname validation stayed enabled; no firewall, trust-store,
  TLS-policy or system settings were changed.

## Environment

`environment.json`: Windows 11 Pro 23H2 build 22631.6936 (64-bit), SDKs
10.0.400/10.0.401, runtimes NETCore/AspNetCore/WindowsDesktop 10.0.11+10.0.12,
**no .NET 8 runtime** (so no `net8.0` pass), curl 8.13.0 Schannel.

## Files

| file | what it is |
|---|---|
| `tls-net10.json` + `-console.log` | `--all --tls-only` probe: 5 hosts × 6 TLS settings, 30/30 PASS, every attempt reached certificate validation (`policyErrors=None`) |
| `derp-net10.json` + `-console.log` + `derp-net10.log` | `--all` encrypted DERP probe (`PINHOLE_TRACE_FILE`): 4/4 relays PASS, 3 echoes each |
| `curl-default.log`, `curl-tls12.log` (+ `-exit.txt`) | Schannel curl `-Iv https://tc301a.ipn.dev/derp`, default and forced TLS 1.2: both `HTTP/1.1 426` |
| `tiny-live.log` | Live cross-machine Tiny chat log (own invitation redacted to sha256) |

## Result

All checks passed on this machine. Notably the GitHub Windows runner failure
(`0x80090308` before the certificate-validation callback, runner build 26100)
did **not** reproduce on this 23H2 build 22631 installation under any tested
TLS/ALPN setting — a meaningful difference from the runner environment.

No raw `pinhole1:`/`pinholeblob1:` capabilities appear in any file here; probe
JSONs carry listener-ticket SHA-256 hashes only, and the live log's own
invitation was replaced with its hash.
