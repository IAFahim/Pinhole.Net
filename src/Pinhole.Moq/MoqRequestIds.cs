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

// Relay-originated request IDs: the relay numbers its requests 1, 3, 5… inside the
// credit we granted at setup. Our grant must grow as the relay consumes it — a session
// otherwise dies at the 128th relay-originated request (C-14c), because the client
// never sent MAX_REQUEST_ID for the direction it receives on.
internal sealed class MoqPeerRequestIds(ulong maximum)
{
    private const ulong Margin = 32;       // extend while this many ids remain unspent
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
