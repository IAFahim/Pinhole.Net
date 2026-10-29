using Pinhole.Crypto;

namespace Pinhole.Core;

public enum HandshakeInputKind : byte
{
    PuncBegin = 0,
    PuncKeys = 1,
    PackBegin = 2,
    PackKeys = 3,
}

public struct HandshakeInput
{
    public HandshakeInputKind Kind;
    public bool CryptoBody;
    public bool PinMatches;
    public bool BodyPlausible;
    public bool LengthClassOk;
    public bool Mac1Present;
    public bool Mac1Ok;
    public bool CookieRequired;
    public bool CookieOk;
    public bool PricedReplyBlocked;
    public bool Accepted;
    public bool ConfirmOk;
    public uint FrameToken;
    public uint PeerToken;
}

public struct HandshakeState
{
    public uint SelfToken;
    public uint RemoteToken;
    public bool RemoteTokenKnown;
    public bool RemoteTokenAuthenticated;
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

    public const long ReplyPackLegacy = 0;
    public const long ReplyPackCrypto = 1;
    public const long ReplyHsck = 2;
    public const long ReplyCookie = 3;

    public const long RejectPackEcho = 1;
    public const long RejectPackLength = 2;
    public const long RejectPuncToken = 3;
    public const long RejectPuncKeys = 4;
    public const long RejectPin = 5;
    public const long RejectMixedMode = 6;
    public const long RejectPackConfirm = 7;
    public const long RejectPackPeerToken = 8;

    public const long RejectMac1 = 9;

    public const long RejectPricedReply = 10;

    public const long NeedKeys = 63;
    public const long PeerConfirmed = 64;

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
                return 0;
        }
    }

    private static int StepPuncBegin(ref HandshakeState s, in HandshakeInput input, Span<Effect> effects)
    {

        if (input.Mac1Present && !input.Mac1Ok)
        {
            return Reject(effects, RejectMac1);
        }

        if (input.CookieRequired && !input.CookieOk)
        {
            int written = 0;
            Effects.Add(effects, ref written, EffectKind.Transmit, 0, 0, ReplyCookie);
            return written;
        }

        if (input.PricedReplyBlocked)
        {
            return Reject(effects, RejectPricedReply);
        }

        if (input.CryptoBody && !input.PinMatches)
        {
            return Reject(effects, RejectPin);
        }

        if (s.RemoteTokenKnown && s.RemoteToken != input.FrameToken && (!s.OfferedCrypto || s.RemoteTokenAuthenticated))
        {
            return Reject(effects, RejectPuncToken);
        }

        if (s.OfferedCrypto != input.CryptoBody)
        {
            return Reject(effects, RejectMixedMode);
        }

        if (s.OfferedCrypto)
        {
            return Reject(effects, NeedKeys);
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

        if (input.Mac1Present && !input.Mac1Ok)
        {
            return Reject(effects, RejectMac1);
        }

        if (!input.BodyPlausible)
        {
            return Reject(effects, RejectPackLength);
        }

        if (input.FrameToken != s.SelfToken)
        {
            return Reject(effects, RejectPackEcho);
        }

        if (!input.LengthClassOk)
        {
            return 0;
        }

        if (!input.CryptoBody && s.OfferedCrypto)
        {

            int count = Reject(effects, RejectMixedMode);
            Effects.Add(effects, ref count, EffectKind.Close, 0, 0, RejectMixedMode);
            return count;
        }

        if (input.CryptoBody && !s.OfferedCrypto)
        {
            return 0;
        }

        if (input.CryptoBody && !input.PinMatches)
        {
            int count = Reject(effects, RejectPin);
            Effects.Add(effects, ref count, EffectKind.Close, 0, 0, RejectPin);
            return count;
        }

        if (s.RemoteTokenAuthenticated && input.PeerToken != s.RemoteToken)
        {
            return Reject(effects, RejectPackPeerToken);
        }

        if (input.CryptoBody)
        {
            return Reject(effects, NeedKeys);
        }

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
