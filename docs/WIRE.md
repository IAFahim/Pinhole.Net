# Pinhole wire formats — the interop reference

Every layout here is generated from the canonical codecs: `Pinhole.Wire`
(src/Pinhole.Wire/*.cs) for the format definitions, `Pinhole.Blobs`
(BlobWire.cs, BlobTicket.cs, RunVerify.cs) for the blob transport, and the
legacy production parsers where noted. Byte offsets, widths and endianness are
the code's, not a re-derivation. When this document and a codec disagree, the
codec wins and this document has a bug.

**Status, 2026-10-26:** BlobWire **v4 and verified runs are landing now**. The
v4 sections below describe the landed wire layer — `BlobWire.cs`,
`Pinhole.Wire/BlobFrameCodec.cs`, `RunVerify.cs` — which is complete and
mutually consistent; the receiver/provider *behavior* around them (run
staging, fold-before-write ordering, v4 negotiation) is still being integrated
in `BlobClient.cs`/`BlobServer.cs`. Everything else described is shipped.

**Canonical vs legacy.** Where a canonical codec is stricter than the legacy
production parser (padded base64url, non-minimal varints, TURN tail bytes, …),
this document states the CANONICAL rule as normative; the legacy lenience is
recorded in a short note and consolidated in the last section. Implementors
should emit canonical bytes and may choose their own tolerance on read.

Related: [PROTOCOL.md](PROTOCOL.md) (the connection/session wire),
[BLOBS.md](BLOBS.md) (the blob transfer behavior built on these frames).

## Primitives and conventions (`WirePrimitives.cs`)

All codecs in `Pinhole.Wire` build on one set of primitives, so endianness and
varint canonicality are decided once.

- **Fixed-width integers.** `TryReadU16Be/U32Be/U64Be`, `TryReadU16Le/U64Le`
  over `ReadOnlySpan<byte>`; big-endian ("Be") or little-endian ("Le") exactly
  as named per field below. Nothing on Pinhole wires uses host endianness.
- **Totality contract.** `TryRead*` returns false on any malformed input and
  never throws on wire-controlled bytes. `Write*` throws
  `ArgumentException`-family errors only on programmer error (destination too
  small, value out of range).
- **QUIC variable-length integer** (RFC 9000 §16), 62-bit values:

  | First 2 bits | Encoded size | Value range |
  |---|---|---|
  | `00` | 1 byte | 0 .. 2^6−1 |
  | `01` | 2 bytes | 2^6 .. 2^14−1 |
  | `10` | 4 bytes | 2^14 .. 2^30−1 |
  | `11` | 8 bytes | 2^30 .. 2^62−1 |

  The length prefix bits carry the top 2 value bits; the rest is big-endian.
  **Only the minimal encoding of a value is canonical**: a longer padded form
  of a small value is rejected on read (`VarintLength(value) != size` ⇒ false)
  and never written. Maximum value 2^62−1.
- **base64url.** Two flavors, both deliberate:
  - connection strings: unpadded RFC 4648 §5, strict charset
    (`A–Z a–z 0–9 - _`), `=` rejected, and the unused trailing bits of a short
    final quantum must be zero (a 2-char tail must have `v1 & 0x0F == 0`, a
    3-char tail `v2 & 0x03 == 0`);
  - blob tickets: unpadded on write; on read, `=` padding and surrounding
    whitespace are tolerated (mirroring the shipped `BlobTicket.Parse`, which
    callers already paste with padding).
- **Text.** Names on tickets/manifests are UTF-8 and are checked for strict
  well-formedness (no overlong forms, surrogate halves, or > U+10FFFF).
  Short ASCII texts (candidate strings, DNS labels, MoQ is not — see MoQ) must
  be 7-bit clean; the legacy decoders substitute `?` for high bytes, canonical
  codecs reject.

## Connection string (`pinhole1:`) — `ConnectionStringCodec.cs`

Text form: `pinhole1:` + unpadded base64url of the body. The body is
versioned; keys pin the version:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version: `1` bare, `2` +static key, `3` +static+endpoint keys, `4` +knock |
| 1 | 1 | flags: bit 0 = static key, bit 1 = endpoint key, bit 2 = knock — v1..v3 must equal exactly the key-presence bits implied by the version byte; v4 must be `static+knock` (0x05) or `static+endpoint+knock` (0x07) |
| 2 | 8 | peer id, u64 **LE** |
| 10 | 1 | NAT hint: 0 unknown, 1 cone, 2 symmetric |
| 11 | 1 | candidate count, 1..32 (zero is not canonical) |
| 12 | … | candidates, back to back |
| … | 32 | static key, present iff version ≥ 2 |
| … | 32 | endpoint key, present iff version 3, or version 4 with bit 1 set |
| … | 1 + 1..64 | knock length (u8) then raw knock bytes, present iff version 4 |

No trailing bytes. Bodies run 13 bytes minimum; the structural maximum is
5,549 bytes / **7,408 characters** (32 candidates of maximal shape, both keys,
and a 64-byte knock). The legacy parser's separate 8,192-character cap
(`ConnectionString.MaxEncodedLength`) still governs the production SDK; the
canonical bound is tighter and derived.

The knock (R5 phase 2 remainder) is the optional per-string secret a node may
be configured with (`PinholeOptions.Knock`): present in a string iff the
publisher is knock-configured, and never on v1..v3 — a pre-v4 reader rejects
the version byte as unsupported, exactly the additive-versioning discipline
the engine handshake's v4 frames use. Old strings parse identically: v1..v3
bodies are untouched. The knock is raw bytes (a generated ≥16-byte secret;
the options surface enforces 8..64) and rides the string only — LAN-discovery
strings never carry it, because a multicast announcement would hand the secret
to every listener and the knock's whole point is that only string holders may
connect.

**Candidate layout** (repeated, in order):

| Field | Size | Notes |
|---|---|---|
| address | 1 + 4 or 16 + 2 | family byte `4` or `16`, raw address bytes, port u16 **BE** |
| kind | 1 | 1 direct, 2 reflexive (STUN), 3 TURN relay, 4 iroh HTTPS relay, 5 DERP HTTPS relay |
| extras | per kind | see below |

- kind 1/2: nothing more.
- kind 3 (TURN): relay server endpoint (same encoding as address), then two
  short texts — username, credential — each `u8 length + ≤64 ASCII bytes`.
- kind 4/5 (HTTPS relays): one short text — the relay URL — then a 32-byte
  relay public key. The URL must parse absolute with scheme `https` (or
  `http` on a loopback host) and carry no userinfo, query or fragment.

Canonical rules beyond the legacy parser: the candidate list is non-empty and
duplicate-free (compared on encoded bytes); short texts are strict 7-bit ASCII
(the legacy decode maps ≥ 0x80 to `?`); the flags byte must match the version
exactly (for v4, one of its two legal shapes); a v4 knock length is 1..64 and
the knock tail must tile the body exactly; the base64url layer is the
unpadded, zero-trailing-bit form (legacy `Pinhole.Base64Url.Decode` accepts
`=` padding and dirty trailing bits).

## Address record — `AddressRecordCodec.cs`

The rendezvous/pkarr signed record. The **signed body** is a byte
compatibility contract — Ed25519 signatures cover these exact bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version: `1` direct only, `2` + relayed list |
| 1 | 8 | peer id, u64 **LE** |
| 9 | 32 | endpoint public key (Ed25519), raw |
| 41 | 8 | sequence, u64 **LE** |
| 49 | 8 | expiry, i64 **LE** — raw Unix seconds; never converted through `DateTimeOffset` on wire values (audit C-06), so no bit pattern can throw |
| 57 | 1 | direct endpoint count, 0..16 |
| 58 | … | direct endpoints |
| … | 1 + … | version 2 only: relayed endpoint count **1..4** (zero is non-canonical; version 1 has no byte here at all), then relayed endpoints |

Endpoint: family byte `4`/`16` + raw address + port u16 **BE**. Minimum body
58 bytes; the body must consume its input exactly — trailing bytes fail. The
full signed record is body ‖ 64-byte detached Ed25519 signature; the signature
bytes are opaque to the codec (verification is the caller's job).

## STUN — `StunCodec.cs` (RFC 5389 shapes)

20-byte header, then attributes:

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | message type, u16 **BE**, must be < 0x4000 |
| 2 | 2 | body length, u16 **BE** — must equal frame length − 20 and be a multiple of 4 |
| 4 | 4 | magic cookie `0x2112A442`, **BE** |
| 8 | 12 | transaction id |

**Attribute:** `type u16 BE | length u16 BE (raw, unpadded) | value | zero
padding to align4(length)`. Canonical rules: the attribute walk ends exactly at
the body end; **padding bytes must be zero** (the legacy
`StunBindingMessage.TryRead` tolerates garbage padding).

**Address values** (MAPPED-ADDRESS 0x0001, XOR-MAPPED-ADDRESS 0x0020,
RESPONSE-ORIGIN 0x802B, OTHER-ADDRESS 0x802C): `0x00 reserved | family (1 =
IPv4, 2 = IPv6) | port u16 BE | address`. Exact value length 8 (IPv4) or 20
(IPv6) — no trailing bytes inside the value. XOR form: `port ^=
0x2112` (cookie >> 16); IPv4 address XOR the 4 cookie bytes; IPv6 address XOR
the 16-byte mask `cookie ‖ transaction-id`.

**Binding request** (type 0x0001): 20 bytes with no attributes, or 28 bytes
with one CHANGE-REQUEST (0x0003) whose 4-byte **BE** value is `2` or `6`.
**Binding success response** (0x0101): XOR-MAPPED-ADDRESS always; optional
RESPONSE-ORIGIN and OTHER-ADDRESS in plain form. On read, a usable mapped
address must have port > 0, not the unspecified address, not multicast, and an
IPv4 first octet in 1..223; a repeated attribute must decode identically;
XOR-MAPPED wins over MAPPED; a RESPONSE-ORIGIN must equal the expected origin
and family.

## TURN — `TurnCodec.cs` (RFC 5766 over the RFC 5389 framing)

Same 20-byte header and attribute tiling as STUN (cookie, txid, align4
padding, type < 0x4000, datagram-exact length, whole datagram a multiple of
4). Methods and classes:

| Constant | Value |
|---|---|
| Allocate | 0x0003 |
| Refresh | 0x0004 |
| CreatePermission | 0x0008 |
| Send Indication | 0x0016 |
| Data Indication | 0x0017 |
| success response class mask | 0x0100 |
| error response class mask | 0x0110 |

Attributes in use:

| Type | Attribute | Value shape |
|---|---|---|
| 0x0001 | MAPPED-ADDRESS | address value (plain) |
| 0x0006 | USERNAME | text |
| 0x0008 | MESSAGE-INTEGRITY | exactly 20 bytes (HMAC-SHA1), opaque to the codec |
| 0x0009 | ERROR-CODE | `0x00 0x00 | class byte | number byte | UTF-8 reason`; class/number encode code = class×100 + number (300..699) |
| 0x000D | LIFETIME | exactly 4 bytes, u32 **BE** seconds |
| 0x0012 | XOR-PEER-ADDRESS | address value (XOR) |
| 0x0013 | DATA | opaque payload (empty is present, not absent) |
| 0x0014 | REALM | text |
| 0x0015 | NONCE | text |
| 0x0016 | XOR-RELAYED-ADDRESS | address value (XOR) |
| 0x0019 | REQUESTED-TRANSPORT | exactly 4 bytes: protocol then three zero RFFU bytes; UDP is `11 00 00 00` (17) |
| 0x0020 | XOR-MAPPED-ADDRESS | address value (XOR) |

The XOR mask is the same `cookie ‖ transaction-id` construction as STUN.

**Authenticated request bytes:** attributes in the given order, then
MESSAGE-INTEGRITY **last**, its 24 padded bytes included in the header length
field. The unauthenticated first Allocate is a single REQUESTED-TRANSPORT
attribute. Send/Data indications carry XOR-PEER-ADDRESS then DATA. A parsed
Data Indication takes the last occurrence of each attribute (an empty DATA
attribute is present, not absent).

Canonical strictness vs `TurnClient` (the legacy production client): the
legacy attribute walker clamps overflowing attribute lengths to what remains
(`vlen = Math.Min(len, end - pos - 4)`) and silently drops stray tail bytes
(`end = Math.Min(msg.Length, 20 + headerLength)`); it never checks the type's
top bits, ignores padding bytes, accepts LIFETIME values of ≥ 4 bytes (reading
the first 4), and accepts address values longer than the address. The
canonical codec rejects all of those. The legacy behavior is the *client's*
tolerance for sloppy servers, not a format rule.

## MoQ wire — `MoqWireCodec.cs` (Cloudflare Draft-16 relay shapes)

All integers are the QUIC varint above (minimal encodings only — the shipped
`MoqReader`/`MoqStreamWire` accept padded forms; the canonical codec does not).

**Control framing:** `type varint | payload length u16 **BE** (not a varint) |
payload`. Unknown types are not parseable. Known types:

| Type | Message | Payload (in order) |
|---|---|---|
| 0x02 | SUBSCRIBE_UPDATE | requestId, existingRequestId, parameters |
| 0x03 | SUBSCRIBE | requestId, trackNamespace, trackName, parameters |
| 0x04 | SUBSCRIBE_OK | requestId, trackAlias, parameters, extension block |
| 0x05 | SUBSCRIBE_ERROR | requestId, errorCode, trackAlias, reason |
| 0x06 | ANNOUNCE | requestId, trackNamespace, parameters |
| 0x07 | ANNOUNCE_OK | requestId, parameters |
| 0x0a | UNSUBSCRIBE | requestId |
| 0x0b | SUBSCRIBE_DONE | requestId, status, trackAlias, reason |
| 0x10 | GOAWAY | reason |
| 0x15 | MAX_REQUEST_ID | maximum |
| 0x1d | PUBLISH | requestId, trackNamespace, trackName, trackAlias, parameters |
| 0x1e | PUBLISH_OK | requestId, parameters |
| 0x20 | CLIENT_SETUP | parameters |
| 0x21 | SERVER_SETUP | parameters |

- **Text**: `length varint (≤ 4096) | UTF-8`, strictly valid UTF-8. A
  **namespace** is `count varint (exactly 1) | text` — list-of-one only.
- **Parameters**: `count varint (≤ 128)` then pairs. Keys are **delta-encoded,
  strictly increasing** (duplicates rejected; the first key may be 0; every
  cumulative key ≤ 2^62−1). Even key = varint value; odd key = `length varint
  (≤ 65535) | blob`. An **extension block** is the same pair list without a
  count, filling its span exactly; only SUBSCRIBE_OK tolerates one after the
  parameters (mirroring the client's Parameters()+Extensions() read).
- Payloads consume their frame exactly; a TryRead accepts a buffer holding
  exactly one framed message.

**Subgroup stream header:** `streamType varint` must be < 0x40, carry the
marker bit `0x10`, and not set both bits of `0x6`. Then `trackAlias varint`,
`groupId varint`; a `subgroupId varint` is present exactly when
`(type & 0x6) == 4`; a **raw priority byte** (not a varint) exactly when
`(type & 0x20) == 0`.

**Object header:** `objectId varint`; an extension block (`length varint ≤
65535` + pairs, present iff the stream type's extension bit is set, which the
caller supplies); `payloadLength varint ≤ 65536`. Payload length 0 means a
`status varint` follows instead of payload. Object-id delta chaining is a
session-layer concern, not the codec's.

## DNS, mDNS and pkarr — `DnsWireCodec.cs`, `IrohDiscovery.cs`

**Header (12 bytes, all u16/u32 BE):** `id | flags | questions | answers |
authorities | additionals`. Canonical `TryReadMessage` requires **id == 0**
(every DNS message the repo writes is mDNS or pkarr); flags pass through
unchecked. Answers+authorities+additionals ≤ 256; the question+record walk
ends exactly at the message end.

**Names:** labels of 1..63 **ASCII** bytes, each `u8 length + bytes`,
terminated by `0x00`; total wire name ≤ 255 bytes after decompression. A
length byte ≥ 0x40 that is not a pointer is rejected. **Compression pointer:**
two bytes `0xC0 | offset>>8, offset&0xFF` (14-bit offset); the target must lie
strictly before the pointer (no forward or self pointers) and a name may
follow at most 128 pointers. Writers emit uncompressed names except the
explicit `WriteCompressionPointer` used by the pkarr owner encoding.

**Question:** name, `type u16`, `class u16`. **Resource record:** name, type,
class, `ttl u32`, `rdlength u16`, rdata (rdlength bytes, verbatim).

Types in use: A 1, PTR 12, TXT 16, AAAA 28, SRV 33; classes IN 1, ANY 255;
the mDNS **cache-flush bit** is `0x8000` OR'd into the class of SRV/TXT/A/AAAA
records (PTR records carry plain IN).

Rdata shapes (canonical readers require each to fill its rdlength exactly):

- **PTR:** exactly one name.
- **SRV:** `priority u16 | weight u16 | port u16 | target name`.
- **TXT:** length-prefixed strings tiling the rdata. mDNS entries are ASCII
  `key=value` (strings without `=` at index > 0 are skipped, not rejected);
  pkarr strings concatenate into one strict-UTF-8 text.

**mDNS writer shapes** (byte-exact mirrors of `LanDiscovery`'s `DnsCodec`):
PTR question (service, PTR, IN); PTR record owner = service, rdata =
`instance.service`; SRV record owner = `instance.service`, priority 0, weight
0; TXT record owner = `instance.service`, one `key=value` string per entry;
A/AAAA records owner = host, rdata = raw 4/16 address bytes.

**pkarr payload** (iroh-dns 1.x / BEP 44 style, `IrohDiscovery`):

| Offset | Size | Field |
|---|---|---|
| 0 | 64 | Ed25519 signature over the signable prefix (below) |
| 64 | 8 | timestamp, u64 **BE** — microseconds, monotonic per publisher; rollback rejected |
| 72 | … | DNS message, ≤ 1000 bytes; total payload ≤ 1072 |

Signable prefix: the ASCII bencode-style string `3:seqi<timestamp>e1:v<dns
length>:` immediately followed by the DNS bytes. The DNS message is a reply
(flags `0x8000`, id 0) whose answers are TXT records for the owner
`_iroh.<zbase32(endpoint key)>`: the first answer writes the full owner name,
every later answer a compression pointer `C0 0C` (offset 12); TTL 60, class
IN; each value is chunked into ≤ 255-byte strings (`rdlength = textLen +
chunkCount`). TXT value keys: `relay=<uri>`, `pinhole-derp=<uri>` (≤ 64 ASCII
bytes), `addr=<endpoints, space-separated>`, `user-data=<≤ 245 UTF-8 bytes>`.

Legacy behavior: `DnsCodec` tolerates trailing bytes, lossily maps high bytes
to `?`, and drops a malformed TXT tail; `IrohDiscovery` throws
`InvalidDataException` on invalid UTF-8 (audit C-06). The canonical codec is
total and strict instead.

## Blob ticket (`pinholeblob1:`) — `BlobTicketCodec.cs`

Text form: `pinholeblob1:` + base64url of the binary payload (unpadded on
write; padding and surrounding whitespace tolerated on read), ≤ 16 KiB
encoded. Binary payload:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version `1` |
| 1 | 1 | flags: bit 0 = directory, bit 1 = pre-shared key present; **unknown bits reject** |
| 2 | 1 | name length `n` (UTF-8 bytes, ≤ 255) |
| 3 | n | name, must be valid UTF-8 |
| 3+n | 32 | content root (BLAKE3) |
| 3+n+32 | 0 or 32 | pre-shared key, iff the encrypted flag is set |
| … | 2 + c | connection-string length u16 **LE** + ASCII bytes, ending the payload exactly |

Canonical tightenings over the legacy `BlobTicket` (audit C-15): unknown flag
bits are rejected (the legacy parser ignores them, so one ticket had several
valid encodings); names must decode as strict UTF-8 and are truncated on a
code-point boundary at encode time (the legacy `ToString` cuts at byte 255
mid-codepoint); the connection string must be pure ASCII (the legacy decode
mangles high bytes). The legacy `Parse` additionally requires the embedded
connection string to parse; the canonical codec treats it as opaque ASCII and
leaves validation to the layer above.

## Directory manifest — `ManifestCodec.cs`

Binary, little-endian, hashed by BLAKE3 into the directory ticket's root:

| Field | Size |
|---|---|
| name length | u16 LE |
| name | UTF-8 |
| entry count | u32 LE |
| per entry: path length u16 LE, path UTF-8 ('/'-separated), size i64 LE (≥ 0), root 32 | 2 + p + 8 + 32 |

Nothing else — trailing bytes reject. Entries are stored in ordinal
(byte-wise UTF-8) path order so the same tree hashes to the same manifest root
under every culture. Canonical rules: strict UTF-8 (the legacy decoder's
lossy `GetString` silently changed the hash preimage); sizes ≥ 0; roots
exactly 32 bytes.

## Blob transfer frames, v1–v4 — `BlobWire.cs`, `BlobFrameCodec.cs`

Frames ride inside Pinhole session datagrams (or plaintext when the ticket is
unencrypted). The two parsers agree by construction; the canonical codec's
writers additionally refuse to emit what the parser would reject (the legacy
`BlobWire.Head`/`Request` writers do not validate).

**Common header (9 bytes):** `type u8 | stream id u64 **BE**`. The stream id
is the first 8 bytes of the content root, big-endian — one blob per root,
several streams share one connection (a directory is the manifest stream, then
one stream per entry root).

| Type | Frame | Length | Body after the 9-byte header |
|---|---|---|---|
| 1 | Hello | 9 / 41 / 42 | v1: empty. v2: `sessionId[32]`. v3/v4: `version u8 (3 or 4) | sessionId[32]` |
| 2 | Head | 25 | `totalBytes i64 LE @9 | totalChunks i64 LE @17`; totalBytes ≥ 0 and totalChunks must equal ⌈totalBytes/1024⌉ |
| 3 | Req | 19 | `startChunk i64 LE @9 | count u16 LE @17`, count 1..64 |
| 4 | Chunk | 50..1073 | `index i64 LE @9 | cv[32] @17 | data[1..1024] @49` |
| 5 | Bye | 9 | empty |
| 6 | Welcome | 123 | `version u8 (3 or 4) @9 | sessionId[32] @10 | providerNonce[32] @42 | sealedHead[49] @74` |
| 7 | Proof | 18..2066 | `runIndex i64 LE @9 | count u8 @17 | count × 32 sibling CVs @18`; count ≤ 64 and the frame length must equal 18 + count×32 exactly |

Hello is sent unsealed at the blob layer. **Wire v1/v2 are refused by design**
(decision, issue #49): they sealed under a fixed per-ticket key with no
per-connection nonces, so (key, nonce) pairs repeated across connections — no
provider of this protocol may ever answer or seal under them again. The v1/v2
Hello shapes are parseable *only so a provider can refuse them explicitly*:
every provider, encrypted or plaintext, closes the connection without
answering, and the open-only `LegacyDetector` hangs up pre-2.0 sealed traffic
without sealing so much as a Bye. The largest plaintext frame (Chunk, 1073
bytes) stays under the session layer's 1200-byte datagram budget.

**Version negotiation.** v4 is layout-identical to v3 — only the Hello/Welcome
version byte (`4`) and the HKDF info string differ. An encrypted ticket's
downloader opens with a version-4 Hello; a pre-v4 provider closes the
connection without answering, and the downloader falls back to version 3 for
the rest of the call (the fallback persists across re-dials). A provider
accepts Hello version 3 or 4, answers a Welcome with the negotiated version,
ignores session/version swaps mid-connection, and on v4 activates
verified-run serving. Plaintext tickets negotiate v3. **v3 is the supported
compatibility bridge** — the v4 fallback and the deployed 1.9.0 interop
floor; its removal is scheduled for the next minor release boundary (changelog:
"blob v4 required; v3 interop removed"), once the interop target speaks v4.

**The sealed session.** With a PSK in the ticket (the default), all frames
after the Welcome exchange are sealed:

- **Key:** `HKDF-SHA256(psk, salt = ticket-root ‖ sessionId ‖ providerNonce,
  info = "pinhole-blobs-v3" | "pinhole-blobs-v4")`, 32 bytes. The info string
  is the only v3/v4 crypto difference. Root and both nonces are exactly 32
  bytes each.
- **Wire form:** `counter u64 LE | ciphertext | tag 16`. The 12-byte nonce is
  `role u8 | counter u64 LE | 0×3`, role `0` = downloader, `1` = provider —
  reflected frames cannot decrypt.
- **Cipher:** ChaCha20-Poly1305, 128-bit tag. (Still BouncyCastle per call in
  `BlobWire.Cipher`; the BCL-backed `Pinhole.Crypto.Aead` is the planned
  replacement — deletion ledger item 5.)
- **Counter:** per-connection and per-direction, monotonic, shared across all
  streams on the connection. Receivers run **authenticate-then-commit**: a
  frame's counter must exceed the watermark, and the watermark moves only
  after the tag verifies. A replayed or regressed counter re-admits nothing; a
  forged far-future counter cannot starve the frames behind it. A tag failure
  drops the frame silently.
- **Welcome binding:** the Welcome's 49-byte sealed head is
  `counter(8) | sealed 25-byte Head frame | tag(16)`. The receiver checks the
  echoed sessionId, derives a *candidate* key from the Welcome's nonce,
  verifies the sealed Head's tag and stream, and only then commits the
  provider nonce, key and watermark. A different provider nonce afterwards is
  refused; Hello retries get a fresh counter under the established key. A
  fixed-key open-only detector (`info = "pinhole-blobs-v1"`, salt = root)
  exists to *recognize* legacy v1 sealed traffic and close without answering.

**Verified runs (v4).** A **run** is an aligned 64-chunk subtree of the file's
canonical left-complete BLAKE3 tree (`RunVerify.RunChunks = 64 =
MaxRequestCount`); the ragged tail is one run. Chunk frames carry each leaf's
CV (the standard BLAKE3 chunk chaining value: 8 little-endian u32 words, the
chunk index as the compress counter, CHUNK_START/CHUNK_END flags, no ROOT).
The **Proof frame** carries the sibling CVs from the run's node up to the file
root, **bottom-up**; the chain itself is a pure function of `(runIndex,
totalChunks)` (`RunVerify.SiblingPath`), so the proof only supplies CV bytes —
a receiver rejects any count that does not match the derived path length.

Receiver semantics (`RunVerify.VerifyRun`): fold the run's leaf CVs into the
run CV (the left-complete fold for the run's length, exactly the streaming
hasher's shape), then fold the sibling chain with the ROOT flag on the fold
that completes the file, and compare the digest to the **ticket root**. Disk
writes happen only after that comparison passes; a single-chunk file has no
fold, so its check is the chunk hashed with the ROOT flag
(`VerifySingleChunk`). At completion the receiver folds the per-run CVs to the
root (`FoldRunsToRoot`) — verified bytes are hashed once. The sibling-count
bound of 64 caps the format at 2^32 chunks (2^42 bytes = 4 TiB). The provider
side (`RunTree`) retains the internal nodes of the run tree and emits proofs
in O(depth). Note this is Pinhole's own frame-level construction; it is not
byte-compatible with iroh-blobs' pre-order Bao encoding (roadmap §10 records
that interop decision as open).

## Engine handshake frames, v3/v4 — `NodeEngine.cs` + `CryptoWire`

Datagram frames on the engine's direct path (`HeaderSize` header + body; frame types
`Punc`, `Pack`, `Hsck`, `Cookie`; bodies sized by `CryptoWire`). Frame lengths by class:

| Frame | v3 legacy | v3 crypto | v4 (mac1) | v4 (mac1+mac2) |
|---|---|---|---|---|
| PUNC  | 13 | 77 | 94 | 111 |
| PACK  | 17 | 97 | 114 | — |
| HSCK  | 29 | 29 | 29 | — |
| COOKIE | — | — | 30 | — |

Every v4 length class is distinct from every v3 class, so a v3 reader silently ignores
v4 frames on length alone and the extensions are purely additive.

- PUNC v3 crypto body: ephemeral(32) + static(32) + token(4) + confirm(16). PACK v3
  crypto body: two tokens(8) + ephemeral(32) + static(32) + confirm(16). HSCK body:
  token(4) + confirm(16).
- **v4 (R5 phase 1):** the v3 crypto body plus a 17-byte extension — marker byte
  `0x04` followed by `mac1[16]` = `BLAKE3-Keyed(responderStaticPub32, frame[0..^16])[..16]`,
  the whole frame including the marker, excluding the MAC bytes themselves.
- The mac1 key is the answering node's static public key (or a pinned key when the
  dialer knows one): public material by design. mac1 filters random-source and
  port-scan floods, not attackers holding the target's key; that is mac2's job.
  A frame that carries the extension but fails verification is refused silently — no
  PACK, no HSCK, no state, and no key agreement — counted only in the `Mac1Refused`
  counter. Unversioned v3 initiations behave exactly as before; mac1 becomes
  mandatory only after the support window (same policy as blob wire v4).
- **v4 + mac2 (R5 phase 2):** under initiation load a v4 PUNC may carry a second
  17-byte extension — marker `0x05` + `mac2[16]` =
  `BLAKE3-Keyed(cookie16 zero-extended to 32, frame[0..^16])[..16]`, the whole frame
  including mac1 and both markers, excluding the mac2 bytes themselves. mac1 covers
  exactly the bytes it always did (a mac2-carrying frame is read through its mac1
  view, the frame truncated at mac2's marker), so a mac1 verdict never depends on
  whether mac2 rode along.
- **COOKIE frame (type `0x59`):** the under-load reply instead of PACK —
  `type(1) | sender peerId(8) | echo of the PUNC's token(4) | epoch tag u8(1) |
  cookieValue[16]`, 30 bytes. The echo binds the cookie to one dial attempt (the
  token is random per connection and never on the wire except in that attempt's own
  PUNCs). The epoch tag names the minting epoch for diagnostics; verification never
  trusts it. No DH, no state — the cheapest frame the engine can answer with, and
  smaller than the PUNC it answers (no amplification).
- **The cookie:** `cookieValue = BLAKE3-Keyed(rotatingSecret32, sourceAddress)[..16]`,
  where `sourceAddress` is the arrival's source endpoint in SocketAddress wire form,
  exactly as the responder saw it. The secret rotates every 120 s and the previous
  epoch stays valid, so a cookie minted in epoch N-1 still answers in epoch N
  (in-flight handshakes survive rotation); epoch N-2 is refused — that secret is gone.
  The binding is the source address: a cookie minted for one source never validates a
  frame from another, so a replayed or foreign cookie is just a wrong key.

**mac2/cookie load policy.** The responder counts mac1-valid PUNCs that have earned no
completed session (a confirmed peer's retransmissions are not load), direct-UDP arrivals
only — relay datagrams are bound to the sender's static key and a TCP peer completed a
three-way handshake, so neither path can spoof a source and neither is gated. Two arms:

- **Per source:** ≥64 counted PUNCs within a 10 s window from one source address. An
  honest dialer punches at one PUNC per candidate per 200 ms (5/s per candidate), so
  even a several-candidate dial that completes inside the window stays far below 64
  from its single mapped address.
- **Global:** ≥512 counted PUNCs within 10 s engine-wide. This arm exists because a
  spoofed-source flood wears a fresh address on every PUNC — no per-source count can
  ever trip. 512 in 10 s is ~51 PUNCs/s sustained; honest concurrent dials do not
  reach it, floods exceed it by orders of magnitude.

Both windows are tumbling and bounded in memory: one global counter plus a fixed
64-entry source table that evicts the coldest window when full. The threshold-crossing
PUNC trips the gate for itself: the first 63 (or 511) are admitted by design, exactly as
WireGuard's cookie answers nothing until the responder is under load. The gate cools by
window expiry — one quiet 10 s window and the same source is admitted again.

**The gate.** Under load for the arrival's source: a PUNC without a valid mac2 earns a
COOKIE reply only — never PACK, no state, no key agreement (a stranger earns it before
any connection object exists, mirroring the stranger mac1 gate; a conn'd arrival earns
it from `HandshakeMachine`, which sequences the decision as `CookieRequired`/`CookieOk`
→ `ReplyCookie` before every other check). With a valid mac2: the normal PACK path. Not
under load: mac2 is ignored, present or absent. mac1-invalid frames remain silent
refusals even under load. v3 frames are unchanged while the responder is not under
load; under load a v3 PUNC earns COOKIE replies it cannot answer — a v3 dialer cannot
complete against a loaded responder. That is the documented cost of the armor and one
more reason the support window is scheduled to close.

**Dialer side.** A v4 dialer that receives a COOKIE stores the cookie for that
connection, rebuilds its PUNC frame with mac2 appended, and retries immediately (the
extra round trip must not wait out a punch pace tick). Receiving a COOKIE also proves
the responder speaks v4, so the v3 fallback clock restarts — the cookie exchange can
never bounce an honest dialer into the unversioned fallback (that fallback fires only
on total silence: no PUNC/PACK/HSCK received for the whole window). If the dialer's
source address changed between PUNCs (a NAT rebind), the recomputed cookie differs,
mac2 fails, and the responder's fresh COOKIE for the new source heals the exchange.
Counters: `CookieDemanded` (COOKIE replies sent) and `CookieAccepted` (under-load PUNCs
whose mac2 verified) sit beside `Mac1Refused` and `HandshakeKeyAgreements`.

**Threat model of the plaintext cookieValue.** WireGuard encrypts its cookie to the
initiator's static public key; this phase sends the value in the clear, and the
consequence is deliberate: anyone who *receives* a COOKIE — the spoofed victim whose
address was forged, an on-path observer, or the dialer itself — holds a cookie valid
only for PUNCs *from that source address*. They can compute valid mac2 frames and
extract a PACK — but the PACK travels to that same source address, so an attacker
gains nothing beyond what already having a receive path at that address gives (and a
real socket can simply dial honestly). The demand stage stays un-amplified (a 30-byte
reply to a ≥94-byte mac1-valid PUNC) and a spoofed source, which never sees the
COOKIE, remains unable to move the responder at all. Encrypting the cookie to the
dialer's static key remains available as a later hardening if on-path cookie theft
ever matters in practice.

**The knock (R5 phase 2 remainder).** A node MAY be configured with a per-string
secret (`PinholeOptions.Knock`, 8..64 raw bytes; the node's connection string then
carries it as the v4 knock field). When set, possession of the string becomes a
precondition for the handshake:

- **mac1 is knock-keyed.** The mac1 key is no longer the raw static pub but
  `KnockMac1Key = BLAKE3-DeriveKey("pinhole-knock-mac1-v1", responderStaticPub32 || knock)`.
  The frames are byte-shape identical to knock-less v4 — only the key material
  differs — so the wire stays indistinguishable and no length class changes. A
  dialer whose string carries the knock computes the same key; a scanner holding
  only the static pub (public material) fails the same silent `RejectMac1` gate a
  random flood does: no PACK, no COOKIE, no state, no key agreement, counted only
  in `Mac1Refused`. The pinned-key path in `Mac1OkForConn` verifies knock-keyed
  only (the raw-pin form is a knock-less impostor); the own-key fallback is
  knock-keyed exactly when the engine itself is knock-configured, so crossed
  simultaneous-dial frames still verify.
- **v3 is ignored.** A knock-configured responder cannot distinguish an honest v3
  dialer from a scanner, and the operator has said nobody without the string gets
  in — so unversioned PUNCs (the 13-byte legacy and 77-byte crypto shapes, on every
  transport) are ignored outright: before the encryption policy, before the cookie
  gate, before any state, and without even a `Mac1Refused` tick. The knock closes
  that node's v3 support window unilaterally; its OUTBOUND window is untouched (a
  knock-configured node dials v3-only peers normally). A knock string's dialer
  never fires the v4→v3 unversioned fallback — its responder is knock-configured
  by construction and ignores v3.
- **The knock is a PSK.** `KeySchedule.Derive` mixes it as a fourth HKDF ikm slice:
  `psk = BLAKE3-DeriveKey("pinhole-knock-psk-v1", knock)`, appended to `ee || se || es`.
  The dialer holds the knock from the string, the responder from its options — a
  knock-less MITM that somehow slipped a frame past mac1 still cannot produce a
  confirm MAC that verifies (every sealed artifact differs; pinned in
  HandshakeKnockTests). A dial whose string promised a knock also prices a crypto
  PACK *without* the mac1 extension (a truncated or knock-less impostor's answer)
  as a failed mac1 — same silent refusal. Mismatch is impossible without a forged
  string, and forging one is priced by the mac1 gate itself.
- **Layering.** mac1 (knock-keyed) runs before the cookie gate, and only
  knock-keyed VALID PUNCs count toward the cookie load windows — a knock-less flood
  cannot even arm them. Under load from knock holders (the compromised-string
  scenario), the honest knock dialer pays the mac2 round trip on the same attempt
  and seals, exactly as without a knock.
- **Entropy guidance.** The knock is subject to offline guessing: anyone who saw a
  single valid v4 frame can test guesses at BLAKE3 speed. Generate it as ≥16 random
  bytes (the options surface enforces 8..64); never a human password. A knock
  holder can still do everything a string holder could always do — dial honestly,
  and arm the cookie gate with a flood of mac1-valid PUNCs, which is exactly the
  load the cookie layer exists to absorb.

- Dialer side, versioning: a v4 dialer sends versioned frames and, when a peer never
  answers (a v3-only responder ignoring the unknown shape), retries unversioned
  exactly once per connection attempt.

**Rendezvous pricing (R5 final): address validation before large replies, the 3x
rule, the per-source ledger.** The armor above gates *who may complete a
handshake*; these rules gate *what any stranger may extract before it completes
one*. Three invariants, each checkable per reply:

1. **Address validation before large replies.** A reply to a source that has not
  validated is priced by its request: never larger than 3x the request's bytes,
  never an unbounded frame, no key agreement or state without an admission.
  Validation means one of: the cookie (mac2 under load — the source proved it
  receives at that address), a confirmed handshake (the peer produced a frame
  that verifies under the derived keys: PACK confirm, HSCK, or any sealed frame
  — possession plus a return path), or the transport (a TCP peer completed a
  three-way handshake; relay datagrams are bound to the sender's static key).
  Concretely: the **announce is withheld until the peer confirms** — answering a
  PUNC never again emits the candidate list (which can run to hundreds of bytes
  and carries relay credentials); the candidate exchange begins at the first
  confirmed frame (HSCK/PACK-confirm both trigger it, so an honest dial loses
  zero round trips). The **PMTU floor-ping introduction probe** (~1237 B) is
  withheld the same way. After these, the only frames a stranger can extract are
  PACK (17/97/114 B answering 13/77/94–111 B) and COOKIE (30 B) — every one
  priced ≤ 1.31x, far under the 3x bound.
2. **The 3x rule.** A stranger's unvalidated requests earn at most 3 priced
  replies (PACK-class answers, each including the DH/state admission they pay
  for) per source per 10 s window. After 3 without progress toward validation,
  silence until the window rolls. COOKIE replies are exempt — they are the
  armor's own priced reply (30 B answering ≥ 94 B) and exempting them keeps the
  cookie gate armed: PUNCs keep counting toward the 64/512 load windows even
  while the ledger silences the PACKs, so a single-source flood transitions to
  COOKIE-only exactly as before. A source that validates (its HSCK/sealed frame
  verifies) resets its budget; a confirmed peer's retransmissions are never
  charged. The honest-dial cost is one window: a dial whose first volley spends
  the budget and loses all its PACKs waits out ≤ 10 s before the next volley —
  a normal dial validates inside its first RTT and never notices.
3. **The per-source ledger.** One fixed 64-entry table (the `CookieArmor`
  pattern: coldest-window eviction, byte-keyed by the arrival's source socket
  address) prices every stranger-reply path — direct-UDP PUNC answers on every
  socket the engine owns, and (as the same class) each LAN-discovery unicast
  query answer, capped at 3 per source per 10 s window. The sequencing decision
  is the machine's (`PricedReplyBlocked` → `RejectPricedReply`, ordered after
  mac1 and after the cookie demand, so a refused PUNC is silent with no state
  and no DH); `NodeEngine` owns the windows and tables. Counters:
  `StrangerLedgerRefused` sits beside `Mac1Refused`/`CookieDemanded`.

The same rules price the text-protocol introducer (`Pinhole.Rendezvous`,
[HOST_JOIN.md](HOST_JOIN.md)): the GETC cookie generalizes to WANT — records
(peer-id lookup records up to 1 KiB) never ride an INTRO to a source that has
not answered a challenge bound to its address; an unvalidated WANT earns a CHAL
plus endpoint-only INTROs (both priced ≤ 3x), never a record. And the raw
`PeerSocket` legacy layer now accepts OBS/INTRO signals only from its
configured rendezvous servers (audit C-12's source check).

## Canonical vs legacy divergences (normative list)

The canonical rule is normative in each case; the note records what the
existing production parser tolerates today.

1. **base64url padding** — connection string: unpadded, zero trailing bits
   only; legacy `Pinhole.Base64Url` accepts `=` and dirty bits. Blob ticket:
   both canonical and legacy tolerate padding/whitespace on read (documented
   above, deliberate).
2. **Non-minimal varints** — MoQ canonical rejects; `MoqReader` /
   `MoqStreamWire` accept padded forms.
3. **TURN tail bytes and clamped attributes** — canonical rejects overflow,
   tail bytes, non-zero padding, short LIFETIME forms, and over-long address
   values; `TurnClient` clamps and ignores all of them. `TurnClient` also
   never checks the type's top two bits.
4. **STUN padding** — canonical requires zero padding; `StunBindingMessage`
   ignores padding bytes.
5. **DNS strictness** — canonical: no trailing bytes, strict ASCII names,
   TXT strings tiling exactly, total UTF-8 for pkarr; `DnsCodec` is lenient
   on all four, `IrohDiscovery` throws instead of returning false on bad
   UTF-8.
6. **Address record v2** — an empty relayed list in a version-2 body is
   non-canonical; the legacy parser accepts it.
7. **Blob ticket flags/UTF-8** — canonical rejects unknown flag bits,
   non-UTF-8 names, non-ASCII connection strings; the legacy parser ignores
   flag bits and decodes lossily.
8. **Manifest UTF-8** — canonical rejects invalid UTF-8 (which would silently
   change the hash preimage); legacy `GetString` substitutes U+FFFD.
9. **Blob frame writers** — readers agree exactly (canonical acceptance was
   copied from `BlobWire.Frame.TryParse`); the canonical writers refuse
   non-canonical values (a Head whose chunk count is not ⌈bytes/1024⌉, a Req
   out of 1..64) that the legacy writers would emit and only the peer's
   parser would catch.
