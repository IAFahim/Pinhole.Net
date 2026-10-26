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

// A loss model the fixture flips at run time. Blackouts built this way live
// inside an existing rule — the network consults only the first MATCHING
// rule, so a dedicated blackout rule added after a shaper would never fire.
internal sealed class ToggleLoss : LossModel
{
    private volatile bool _dropping;

    public void Enable() => _dropping = true;

    public void Disable() => _dropping = false;

    protected override bool LoseNextCore() => _dropping;
}
