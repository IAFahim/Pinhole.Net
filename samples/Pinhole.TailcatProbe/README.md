# Tailcat DERP connectivity probe

Checks authentication and three encrypted 32-byte echoes over a selected DERP
relay. Direct UDP/TCP, iroh, TURN, STUN, and discovery publication are disabled.
Both peers run on this machine and connect through the public HTTPS service;
this does not establish physical NAT traversal or mobile interoperability.
Reports contain ticket hashes only. This is not a bandwidth benchmark.

```sh
dotnet run --project samples/Pinhole.TailcatProbe -c Release -f net10.0 -- \
  --all --output /tmp/tailcat-net10.json
dotnet run --project samples/Pinhole.TailcatProbe -c Release -f net8.0 -- \
  https://tc304a.ipn.dev/ --output /tmp/tailcat-net8.json
```

The four `--all` hosts come from the [Tailcat relay map](https://tailcat.dev/derpmap.json),
verified 2026-10-12. Pass an HTTPS URL to check an owned DERP server instead.
