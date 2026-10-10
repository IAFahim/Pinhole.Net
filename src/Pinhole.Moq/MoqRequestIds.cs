namespace Pinhole.Moq;

// Draft16 section9.5: MAX_REQUEST_ID is the first excluded ID, not inclusive credit.
// Sender allocation is serialized by the client's control-stream gate.
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
