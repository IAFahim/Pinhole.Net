using Pinhole.Crypto;

namespace Pinhole.Core;

public enum HandshakeInputKind : byte
{
    PuncBegin = 0, // first pass over a PUNC: every check that needs no crypto call
    PuncKeys = 1,  // second pass: the shell ran key agreement and reports the verdict
    PackBegin = 2, // first pass over a PACK: every check that needs no crypto call
    PackKeys = 3,  // second pass: key agreement and confirm-MAC verdicts
}

public struct HandshakeInput
{
    public HandshakeInputKind Kind;
    public bool CryptoBody;  // PuncBegin/PackBegin: the frame carried the v2 key body
    public bool PinMatches;  // PuncBegin/PackBegin: the static key matches the pin (true when unpinned)
    public bool BodyPlausible; // PackBegin: length at least a legacy PACK body
    public bool LengthClassOk; // PackBegin: length is exactly legacy or exactly crypto
    public bool Accepted;   // PuncKeys/PackKeys: key agreement (fresh, repeat, or supersede) verdict
    public bool ConfirmOk;  // PackKeys: the confirm MAC verified under the agreed keys
    public uint FrameToken; // PuncBegin/PuncKeys: the PUNC's token; PackBegin/PackKeys: the echo of ours
    public uint PeerToken;  // PackBegin/PackKeys: the responder's own token (second slot)
}

// The token side of the PUNC/PACK/HSCK exchange: which token the peer's frames must
// carry, when a learned token may be replaced, which reply each inbound frame earns,
// and the reject kind for every refusal. The KEY side (agreement, confirm MACs,
// sealers) stays in the shell's crypto object — this machine sequences around it and
// never touches key material. The HSCK third flight is a pure crypto verdict with no
// sequencing state and stays in the shell entirely.
public struct HandshakeState
{
    public uint SelfToken;
    public uint RemoteToken;
    public bool RemoteTokenKnown;
    public bool RemoteTokenAuthenticated; // set by the sealed-frame path, honored here
    public bool HsckSent;
    public bool OfferedCrypto;

    public static HandshakeState Create(uint selfToken, bool offeredCrypto)
    {
        HandshakeState s = default;
        s.SelfToken = selfToken;
        s.OfferedCrypto = offeredCrypto;
        return s;
    }
}

public static class HandshakeMachine
{
    // Replies ride Transmit effects (Value selects the frame); rejects and the two
    // progress signals ride Notify (Value selects the kind). Numbers 1..8 are the
    // engine's stable reject codes — diagnostics print them by kind.
    public const long ReplyPackLegacy = 0;
    public const long ReplyPackCrypto = 1;
    public const long ReplyHsck = 2;

    public const long RejectPackEcho = 1;
    public const long RejectPackLength = 2;
    public const long RejectPuncToken = 3;
    public const long RejectPuncKeys = 4;
    public const long RejectPin = 5;
    public const long RejectMixedMode = 6;
    public const long RejectPackConfirm = 7;
    public const long RejectPackPeerToken = 8;

    public const long NeedKeys = 63;       // the shell runs key agreement, then steps *Keys
    public const long PeerConfirmed = 64;  // the shell marks the crypto object confirmed

    public static int Step(ref HandshakeState state, in HandshakeInput input, Tick now, Span<Effect> effects)
    {
        switch (input.Kind)
        {
            case HandshakeInputKind.PuncBegin:
                return StepPuncBegin(ref state, in input, effects);
            case HandshakeInputKind.PuncKeys:
                return StepPuncKeys(ref state, in input, effects);
            case HandshakeInputKind.PackBegin:
                return StepPackBegin(ref state, in input, effects);
            case HandshakeInputKind.PackKeys:
                return StepPackKeys(ref state, in input, effects);
            default:
                return 0; // unknown input values are a no-op, never an exception
        }
    }

    private static int StepPuncBegin(ref HandshakeState s, in HandshakeInput input, Span<Effect> effects)
    {
        if (input.CryptoBody && !input.PinMatches)
        {
            return Reject(effects, RejectPin);
        }

        // Stale frames from an older connection to the same peer ID. A token learned
        // only from plaintext handshakes may still be replaced by the real one; a
        // token authenticated by a sealed frame is settled.
        if (s.RemoteTokenKnown && s.RemoteToken != input.FrameToken && (!s.OfferedCrypto || s.RemoteTokenAuthenticated))
        {
            return Reject(effects, RejectPuncToken);
        }

        // A plaintext PUNC on a connection that offered crypto, or a crypto PUNC on a
        // plaintext one: neither is a state any honest peer produces.
        if (s.OfferedCrypto != input.CryptoBody)
        {
            return Reject(effects, RejectMixedMode);
        }

        if (s.OfferedCrypto)
        {
            return Reject(effects, NeedKeys); // run key agreement, then step PuncKeys
        }

        s.RemoteToken = input.FrameToken;
        s.RemoteTokenKnown = true;
        int count = 0;
        Effects.Add(effects, ref count, EffectKind.Transmit, 0, 0, ReplyPackLegacy);
        return count;
    }

    private static int StepPuncKeys(ref HandshakeState s, in HandshakeInput input, Span<Effect> effects)
    {
        if (!input.Accepted)
        {
            return Reject(effects, RejectPuncKeys);
        }

        s.RemoteToken = input.FrameToken;
        s.RemoteTokenKnown = true;
        int count = 0;
        Effects.Add(effects, ref count, EffectKind.Transmit, 0, 0, ReplyPackCrypto);
        return count;
    }

    private static int StepPackBegin(ref HandshakeState s, in HandshakeInput input, Span<Effect> effects)
    {
        if (!input.BodyPlausible)
        {
            return Reject(effects, RejectPackLength);
        }

        if (input.FrameToken != s.SelfToken)
        {
            return Reject(effects, RejectPackEcho); // not an echo of our handshake token
        }

        if (!input.LengthClassOk)
        {
            return 0; // neither a legacy nor a crypto body: silently ignored
        }

        if (!input.CryptoBody && s.OfferedCrypto)
        {
            // We dialed with a key the string vouches for; a plaintext PACK means
            // someone stripped the handshake. Fail, never fall back to plaintext.
            int count = Reject(effects, RejectMixedMode);
            Effects.Add(effects, ref count, EffectKind.Close, 0, 0, RejectMixedMode);
            return count;
        }

        if (input.CryptoBody && !s.OfferedCrypto)
        {
            return 0; // we never offered crypto; a crypto PACK is bogus
        }

        if (input.CryptoBody && !input.PinMatches)
        {
            int count = Reject(effects, RejectPin);
            Effects.Add(effects, ref count, EffectKind.Close, 0, 0, RejectPin);
            return count;
        }

        // Confirmation binds the keys, not these token fields. A replayed PACK with an
        // edited token must not change an authenticated session's token.
        if (s.RemoteTokenAuthenticated && input.PeerToken != s.RemoteToken)
        {
            return Reject(effects, RejectPackPeerToken);
        }

        if (input.CryptoBody)
        {
            return Reject(effects, NeedKeys); // run key agreement, then step PackKeys
        }

        // Only verified keys may replace a token latched by an earlier PUNC — the
        // legacy path has none, and latches the plaintext token as-is.
        s.RemoteToken = input.PeerToken;
        s.RemoteTokenKnown = true;
        return 0;
    }

    private static int StepPackKeys(ref HandshakeState s, in HandshakeInput input, Span<Effect> effects)
    {
        if (!input.Accepted)
        {
            return Reject(effects, RejectPuncKeys);
        }

        if (!input.ConfirmOk)
        {
            int written = Reject(effects, RejectPackConfirm);
            Effects.Add(effects, ref written, EffectKind.Close, 0, 0, RejectPackConfirm);
            return written;
        }

        s.RemoteToken = input.PeerToken;
        s.RemoteTokenKnown = true;
        int count = 0;
        if (!s.HsckSent)
        {
            s.HsckSent = true;
            // Third flight: our confirm back, exactly once — retries ride the same MAC.
            Effects.Add(effects, ref count, EffectKind.Transmit, 0, 0, ReplyHsck);
        }

        Effects.Add(effects, ref count, EffectKind.Notify, 0, 0, PeerConfirmed);
        return count;
    }

    private static int Reject(Span<Effect> effects, long kind)
    {
        int written = 0;
        Effects.Add(effects, ref written, EffectKind.Notify, 0, 0, kind);
        return written;
    }
}
