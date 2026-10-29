namespace Pinhole;

internal interface IKeyedRelay : IDisposable
{
    Uri Url { get; }
    CandidateKind Kind { get; }
    byte[] PublicKey { get; }
    bool IsAlive { get; }
    event Action<IKeyedRelay, byte[], byte[]>? Received;
    event Action<IKeyedRelay>? Changed;
    Task StartAsync(CancellationToken ct = default);
    bool Send(ReadOnlySpan<byte> destination, ReadOnlySpan<byte> payload);
}
