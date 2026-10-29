using Pinhole.Core;
using Pinhole.Sim;

namespace Pinhole.Tests.Sim;

internal static class MachineSimScenarios
{
    public const int TickStepMs = 10;

    internal sealed record PmtuRun(byte[] Hash, long ConfirmedAtTickMs, int ProbesSent, int PongsDelivered);

    internal static PmtuRun Pmtu(int seed, int ticks, double pongLoss = 0.3, long lossStopsAtMs = long.MaxValue)
    {
        SimClock clock = new();
        MachineSim<PmtuState, PmtuInput> sim = new(
            PmtuState.Create(1200, 128, 3, 1472, 1452, 60_000, 500),
            PmtuMachine.Step, clock, new SimRandom(seed));

        List<(long DueMs, long Nonce)> pongs = [];
        long confirmedAt = -1;
        int probes = 0;
        int delivered = 0;

        for (int tick = 0; tick < ticks; tick++)
        {
            long now = clock.NowMs;
            for (int i = pongs.Count - 1; i >= 0; i--)
            {
                if (pongs[i].DueMs > now)
                {
                    continue;
                }

                PmtuInput ack = Ack(pongs[i].Nonce);
                sim.Step(in ack);
                pongs.RemoveAt(i);
                delivered++;
            }

            PmtuInput input = Tick();
            sim.Step(in input);
            foreach (ref readonly Effect effect in sim.LastEffects)
            {
                if (effect.Kind != EffectKind.Transmit)
                {
                    continue;
                }

                probes++;
                double loss = now < lossStopsAtMs ? pongLoss : 0;
                if (!sim.Random.Chance(loss))
                {
                    pongs.Add((now + 30 + sim.Random.NextLong(170), effect.Value));
                }
            }

            if (confirmedAt < 0 && sim.State.Wire == 1472)
            {
                confirmedAt = now;
            }

            clock.Advance(TickStepMs);
        }

        return new PmtuRun(sim.Log.Hash(), confirmedAt, probes, delivered);

        static PmtuInput Tick()
        {
            PmtuInput input = default;
            input.Kind = PmtuInputKind.Tick;
            input.PathEligible = true;
            input.IPv4 = true;
            return input;
        }

        static PmtuInput Ack(long nonce)
        {
            PmtuInput input = default;
            input.Kind = PmtuInputKind.PongAcked;
            input.Nonce = nonce;
            return input;
        }
    }

    internal sealed record KeepaliveRun(byte[] Hash, int ProbesSent, int PongsDelivered, int PathLostNotifications);

    internal static KeepaliveRun Keepalive(int seed, int ticks, double pongLoss = 0.35)
    {
        SimClock clock = new();
        MachineSim<KeepaliveState, KeepaliveInput> sim = new(
            KeepaliveState.Create(1000, 300, 3), KeepaliveMachine.Step, clock, new SimRandom(seed));

        List<(long DueMs, long Echo)> pongs = [];
        int probes = 0;
        int delivered = 0;
        int notifications = 0;

        for (int tick = 0; tick < ticks; tick++)
        {
            long now = clock.NowMs;
            for (int i = pongs.Count - 1; i >= 0; i--)
            {
                if (pongs[i].DueMs > now)
                {
                    continue;
                }

                KeepaliveInput ack = Ack(pongs[i].Echo);
                sim.Step(in ack);
                pongs.RemoveAt(i);
                delivered++;
            }

            KeepaliveInput maintain = Maintain();
            sim.Step(in maintain);
            KeepaliveInput probeTick = Probe();
            sim.Step(in probeTick);
            foreach (ref readonly Effect effect in sim.LastEffects)
            {
                if (effect.Kind == EffectKind.Notify)
                {
                    notifications++;
                }

                if (effect.Kind == EffectKind.Transmit && effect.Value != 0)
                {
                    probes++;
                    if (!sim.Random.Chance(pongLoss))
                    {
                        pongs.Add((now + 30 + sim.Random.NextLong(90), effect.Value));
                    }
                }
            }

            clock.Advance(TickStepMs);
        }

        return new KeepaliveRun(sim.Log.Hash(), probes, delivered, notifications);

        static KeepaliveInput Maintain()
        {
            KeepaliveInput input = default;
            input.Kind = KeepaliveInputKind.MaintainTick;
            input.PathEligible = true;
            return input;
        }

        static KeepaliveInput Probe()
        {
            KeepaliveInput input = default;
            input.Kind = KeepaliveInputKind.ProbeTick;
            input.PathEligible = true;
            input.RecentActivity = false;
            input.Path = EffectPath.Direct;
            return input;
        }

        static KeepaliveInput Ack(long echo)
        {
            KeepaliveInput input = default;
            input.Kind = KeepaliveInputKind.ProbeAcked;
            input.Echo = echo;
            return input;
        }
    }
}
