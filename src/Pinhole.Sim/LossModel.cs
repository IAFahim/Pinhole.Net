namespace Pinhole.Sim;

internal abstract class LossModel
{
    private readonly object _gate = new();

    public bool LoseNext()
    {
        lock (_gate)
        {
            return LoseNextCore();
        }
    }

    protected abstract bool LoseNextCore();
}

internal sealed class IndependentLoss(double probability, int seed) : LossModel
{
    private readonly Random _rng = new(seed);

    protected override bool LoseNextCore() => _rng.NextDouble() < probability;
}

internal sealed class GilbertElliottLoss(double meanLossRate, double meanBurstPackets, int seed) : LossModel
{
    private readonly Random _rng = new(seed);
    private readonly double _enterBad = meanLossRate / meanBurstPackets;
    private readonly double _exitBad = 1.0 / meanBurstPackets;
    private readonly double _lossInGood = Math.Min(meanLossRate * 0.1, 0.005);
    private readonly double _lossInBad = Math.Min(0.5 + meanLossRate * 0.5, 1.0);
    private bool _bad;

    protected override bool LoseNextCore()
    {
        _bad = _bad ? _rng.NextDouble() >= _exitBad : _rng.NextDouble() < _enterBad;
        return _rng.NextDouble() < (_bad ? _lossInBad : _lossInGood);
    }
}

internal sealed class ToggleLoss : LossModel
{
    private volatile bool _dropping;

    public void Enable() => _dropping = true;

    public void Disable() => _dropping = false;

    protected override bool LoseNextCore() => _dropping;
}

internal abstract class DuplicationModel
{
    private readonly object _gate = new();

    public bool DuplicateNext()
    {
        lock (_gate)
        {
            return DuplicateNextCore();
        }
    }

    protected abstract bool DuplicateNextCore();
}

internal sealed class IndependentDuplication(double probability, int seed) : DuplicationModel
{
    private readonly Random _rng = new(seed);

    protected override bool DuplicateNextCore() => _rng.NextDouble() < probability;
}

internal abstract class CorruptionModel
{
    private readonly object _gate = new();

    public int FlipOffset(int length)
    {
        lock (_gate)
        {
            return FlipOffsetCore(length);
        }
    }

    protected abstract int FlipOffsetCore(int length);
}

internal sealed class IndependentCorruption(double probability, int seed) : CorruptionModel
{
    private readonly Random _rng = new(seed);

    protected override int FlipOffsetCore(int length) =>
        _rng.NextDouble() < probability ? _rng.Next(length) : -1;
}
