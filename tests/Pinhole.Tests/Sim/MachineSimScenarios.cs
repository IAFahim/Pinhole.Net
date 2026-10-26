using Pinhole.Core;
using Pinhole.Sim;

namespace Pinhole.Tests.Sim;

// Seeded, tick-driven scenarios over the Sim machine driver. A run is a pure
// function of its seed: logical time comes from SimClock, every stochastic
// decision from the handed-in IRandom. Each scenario plays the shell for one
// machine — it interprets Transmit effects, decides the reply's fate from the
// seeded RNG, and feeds PongAcked/ProbeAcked back at the drawn delay.
internal static class MachineSimScenarios
{
    public const int TickStepMs = 10;

    // ------------------------------------------------------------------ PMTU
    // Probes climb the engine's numbers (base 1200, step 128, attempts 3,
    // ceilings 1472/1452, reprobe 60 s, timeout 500 ms — the same profile as
    // MachineTests and the shells). Each probe's pong is lost with probability
    // pongLoss while loss is active, else delivered 30..199 ms later.

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

    // ------------------------------------------------------------- Keepalive
    // Maintenance keepalives every 1000 ms plus a continuous validation-probe
    // cadence on the direct path (timeout 300 ms, 3 unanswered => Notify).
    // Nonce-carrying probes get a pong with probability 1 - pongLoss, delivered
    // 30..119 ms later; every other probe's reply is eaten by the path.

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

                // Nonce-carrying Transmit = a validation probe the pong must echo.
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
