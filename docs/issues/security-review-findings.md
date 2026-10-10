# Security review findings — issue #24

The user requested a separate strong AI reviewer. That reviewer inspected
`378031c16a69d40a05255ef956042c9ab1f6de64` and reported the findings below, but an
automatic content filter stopped both its initial and resumed review before it
produced a complete report. These findings are useful evidence; they do not
establish that the rest of the protocol, concurrency, recovery or compatibility
requirements passed independent review. Issue #24 remains open.

## Handshake tokens and confirmation races

The PACK confirmation authenticates the key transcript, not the token fields or
source address. Confirming a provisional token from a first PACK can block later
genuine traffic when that token was edited. Opening a sealed frame outside the
connection lock also permits its key generation to change before confirmation.
Malformed PUNCs previously recorded token state before validating their keys.

Fixed in `1914a88`: the first successfully opened sealed frame authenticates its
peer token through AAD. Once authenticated, that token cannot change through
handshake flights. Opening, token adoption and key confirmation share `c.Gate`.
PUNC mode/key checks precede provisional token adoption. HSCK does not authenticate
its token; it supplies key confirmation only. Plaintext handshake replies do not
select a UDP path.

`CryptoTests` contains regressions for edited first-PACK tokens, confirmed-session
token/key/confirm/downgrade retries and source changes, plus both lo/hi roles for
proof-gated stale-latch replacement. Real sealed traffic must still flow after
rejected inputs. Kotlin has the matching token fix and an actual .NET↔Kotlin proxy
case in the isolated phone worktree.

## TURN control responses

The client previously matched only 64 of the transaction ID's 96 bits and accepted
responses without verifying MESSAGE-INTEGRITY. An unverified response could supply
allocation metadata or a supposedly definitive allocation-mismatch verdict.

Fixed in `ed7bed9`: transactions match all 96 bits and their response method,
verification uses the key captured when that request was built, and control
attributes after the integrity attribute are excluded. Invalid protection does
not complete the transaction or install addresses. Unsigned 401/438 challenges
can initiate only bounded authentication retries; they do not prove that an
existing allocation should be retired. A repeated stale nonce remains transient.

The independent fake server now signs authenticated responses. Loopback regressions
send invalid/missing integrity, mismatched method/transaction suffix, unsigned
denials and trailing unprotected attributes before a valid response. The client
must still adopt the genuine address. The empty-grant fixture supplies a valid
challenge and signed response, proving that a verified response without an
allocation address fails honestly.

These changes follow the response and integrity rules in
[RFC 8489 sections 9.2.5 and 14.5](https://www.rfc-editor.org/rfc/rfc8489.html).
A complete independent final-candidate review, real TURN interoperability and the full
issue checklist still need verification; focused tests do not replace them.
