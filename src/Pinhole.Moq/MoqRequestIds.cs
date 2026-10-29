namespace Pinhole.Moq;

internal sealed class MoqRequestIds(ulong maximum)
{
    private ulong _maximum = maximum;
    public ulong Next { get; private set; }
    public ulong Maximum => Volatile.Read(ref _maximum);
    public ulong Allocate()
    {
        if (Next >= Maximum) throw new InvalidOperationException("MoQ relay request credit exhausted");
        var id = Next; Next += 2; return id;
    }
    public void Extend(ulong maximum)
    {
        if (maximum < Maximum) throw new MoqProtocolException("Decreasing request credit");
        Volatile.Write(ref _maximum, maximum);
    }
}

internal sealed class MoqPeerRequestIds(ulong maximum)
{
    private const ulong Margin = 32;
    private const ulong Step = 256;
    private ulong _maximum = maximum;

    public ulong NextExpected { get; private set; } = 1;
    public ulong Maximum => Volatile.Read(ref _maximum);

    public void Admit(ulong id)
    {
        if (id != NextExpected || id >= Maximum) throw new MoqProtocolException("Invalid relay request ID");
        NextExpected += 2;
    }

    public ulong? ExtensionDue()
    {
        if (Maximum - NextExpected >= Margin)
        {
            return null;
        }

        _maximum += Step;
        return _maximum;
    }
}
