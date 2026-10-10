# Cloudflare MoQ live probe

This sample exercises the reusable [C# MoQ client](../../src/Pinhole.Moq/README.md)
against the real Cloudflare Draft16 relay. It uses three independent outbound
QUIC sessions: two publishing peers and a separate subscribe-only observer.
No local relay or Rust/native binding is used. Normal system TLS certificate
validation remains enabled.

Keep credentials in a private, untracked JSON file (mode 0600 on Unix):

```json
{
  "publishSubscribeToken": "CLOUDFLARE_MOQ_PUBLISH_SUBSCRIBE_TOKEN",
  "subscribeToken": "CLOUDFLARE_MOQ_SUBSCRIBE_ONLY_TOKEN"
}
```

```sh
dotnet build samples/Pinhole.MoqProbe/Pinhole.MoqProbe.csproj -c Release
dotnet samples/Pinhole.MoqProbe/bin/Release/net10.0/Pinhole.MoqProbe.dll --credentials /private/moq.json
python samples/Pinhole.MoqProbe/verify.py --framework net10.0 --credentials /private/moq.json --output artifacts/moq/net10.json
python samples/Pinhole.MoqProbe/verify.py --framework net8.0 --credentials /private/moq.json --output artifacts/moq/net8.json
```

On Linux provide libmsquic, using `LD_LIBRARY_PATH` for a user-space installation.
On this machine the existing verified extraction is
`/tmp/pinhole-quic-live/msquic/usr/lib/x86_64-linux-gnu`.
The verifier also accepts `--dotnet /path/to/dotnet`.

A PASS requires all these actual service interactions:

- Native QUIC ALPN `moqt-16` and Draft16 setup, with bearer token in PATH.
- 48 distinct 256-byte A→B→A round trips and subscribe-only observer copies.
- Empty and 64-KiB objects round-trip byte-exactly; 64 KiB + 1 is rejected locally.
- Subscribe-only publication rejected, with successful publication to that same
  target using the publish+subscribe token as a positive control.
- A valid token's signature deliberately changed: subscription to the known
  active track must be explicitly refused or the service must close that
  session. A timeout cannot pass this gate.
- All owned subscriptions/sessions disposed before the single PASS JSON line.

Cloudflare currently returns request error 32 (UNINTERESTED) for the
subscribe-only publication and closes the modified-signature session with
application error 3 (PROTOCOL_VIOLATION). The evidence preserves these exact
codes; it does not relabel them as UNAUTHORIZED. Cloudflare may send SERVER_SETUP
before checking token authorization, so setup acceptance alone is not an auth
pass. The functional requests and negative controls establish the boundary.

The process has a 90-second cancellation deadline; the verifier kills only its
owned child if it exceeds 120 seconds. It records assembly hashes, filters report
fields and refuses to overwrite existing evidence. Token values, token-bearing
URLs, namespace/session identifiers, raw peer error phrases and exception
messages never enter reports. The relay itself and account configuration are
untouched.

These are Internet relay results from three independent sessions in one process on one
computer, not a phone trial or a comparison of geographical latency. TLS is
client-to-relay encryption; this sample does not implement peer-to-peer
end-to-end encryption. Direct connectivity and automatic fallback remain
Pinhole core integration work.

[Recorded run](../../docs/evidence/cloudflare-moq-2026-10-11/README.md).
