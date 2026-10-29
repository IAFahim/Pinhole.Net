using System.Threading.Channels;

namespace Pinhole.Moq;

internal static class MoqSessionPump
{
    public static async Task ProcessSubgroupStreamAsync(
        Stream stream,
        Func<ulong, CancellationToken, Task<MoqSubscription>> resolveAlias,
        CancellationToken session,
        TimeSpan idleTimeout)
    {
        using var idle = CancellationTokenSource.CreateLinkedTokenSource(session);
        CancellationToken Arm()
        {
            idle.CancelAfter(idleTimeout);
            return idle.Token;
        }

        ulong type = await MoqStreamWire.RequiredIntegerAsync(stream, Arm()).ConfigureAwait(false);
        if ((type & ~0x3fUL) != 0 || (type & 0x10) == 0 || (type & 0x6) == 0x6)
        {
            throw new MoqProtocolException("Invalid MoQ subgroup header");
        }

        ulong alias = await MoqStreamWire.RequiredIntegerAsync(stream, Arm()).ConfigureAwait(false);
        ulong group = await MoqStreamWire.RequiredIntegerAsync(stream, Arm()).ConfigureAwait(false);
        if ((type & 0x6) == 4)
        {
            await MoqStreamWire.RequiredIntegerAsync(stream, Arm()).ConfigureAwait(false);
        }

        if ((type & 0x20) == 0)
        {
            var priority = new byte[1];
            await stream.ReadExactlyAsync(priority, Arm()).ConfigureAwait(false);
        }

        MoqSubscription subscription = await resolveAlias(alias, Arm()).ConfigureAwait(false);

        ulong? previous = null;
        while (await MoqStreamWire.ReadIntegerAsync(stream, Arm()).ConfigureAwait(false) is { } delta)
        {
            ulong objectId = previous.HasValue ? checked(previous.Value + delta + 1) : delta;
            previous = objectId;
            if ((type & 1) != 0)
            {
                ulong extensionLength = await MoqStreamWire.RequiredIntegerAsync(stream, Arm()).ConfigureAwait(false);
                if (extensionLength > ushort.MaxValue) throw new MoqProtocolException("Object extensions too large");
                var extensions = new byte[(int)extensionLength];
                await stream.ReadExactlyAsync(extensions, Arm()).ConfigureAwait(false);
                new MoqReader(extensions).Extensions();
            }

            ulong length = await MoqStreamWire.RequiredIntegerAsync(stream, Arm()).ConfigureAwait(false);
            if (length > CloudflareMoqClient.MaximumObjectBytes) throw new MoqProtocolException("Object payload too large");
            if (length == 0)
            {
                ulong status = await MoqStreamWire.RequiredIntegerAsync(stream, Arm()).ConfigureAwait(false);
                if (status != 0) continue;
            }

            var payload = new byte[(int)length];
            await stream.ReadExactlyAsync(payload, Arm()).ConfigureAwait(false);
            if (Volatile.Read(ref subscription.Disposed) != 0) continue;

            try
            {
                await subscription.EnqueueAsync(new MoqObject(group, objectId, payload), session).ConfigureAwait(false);
            }
            catch (ChannelClosedException)
            {
                return;
            }
        }
    }
}
