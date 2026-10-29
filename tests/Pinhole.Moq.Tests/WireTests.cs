using System.Text;
using Pinhole.Moq;
using Xunit;

namespace Pinhole.Moq.Tests;

public sealed class WireTests
{
    [Fact]
    public void ZeroCredit_ExcludesRequestZero_WithoutConsumingIt()
    {
        var ids = new MoqRequestIds(0);
        Assert.Throws<InvalidOperationException>(() => ids.Allocate());
        Assert.Equal(0UL, ids.Next);
        ids.Extend(2);
        Assert.Equal(0UL, ids.Allocate());
        Assert.Throws<InvalidOperationException>(() => ids.Allocate());
    }

    [Fact]
    public void CloudflareCredit100_Excludes100_ThenExtendingCreditAllowsIt()
    {
        var ids = new MoqRequestIds(100);
        var permitted = Enumerable.Range(0, 50).Select(_ => ids.Allocate()).ToArray();
        Assert.Equal(Enumerable.Range(0, 50).Select(index => (ulong)index * 2), permitted);
        Assert.Throws<InvalidOperationException>(() => ids.Allocate());
        Assert.Equal(100UL, ids.Next);
        ids.Extend(102);
        Assert.Equal(100UL, ids.Allocate());
        Assert.Throws<InvalidOperationException>(() => ids.Allocate());
    }

    [Fact]
    public void DecreasingCredit_RejectsWithoutChangingTheExistingLimit()
    {
        var ids = new MoqRequestIds(100);
        Assert.Throws<MoqProtocolException>(() => ids.Extend(99));
        Assert.Equal(100UL, ids.Maximum);
    }

    [Fact]
    public void SetupVector_HasSixteenBitLength_AndDeltaEncodedParameters()
    {
        var writer = new MoqWriter();
        writer.Parameters((1, Encoding.UTF8.GetBytes("testpath")), (2, 100UL));
        Assert.Equal(Convert.FromHexString("20000E0201087465737470617468014064"), writer.Message(0x20));
    }

    [Theory]
    [InlineData("00", 0UL)]
    [InlineData("3F", 63UL)]
    [InlineData("4040", 64UL)]
    [InlineData("7FFF", 16383UL)]
    [InlineData("80004000", 16384UL)]
    [InlineData("BFFFFFFF", 1073741823UL)]
    [InlineData("C000000040000000", 1073741824UL)]
    [InlineData("FFFFFFFFFFFFFFFF", 4611686018427387903UL)]
    public void QuicVarintVectors_ParseWithoutTruncation(string hex, ulong expected)
    {
        var reader = new MoqReader(Convert.FromHexString(hex));
        Assert.Equal(expected, reader.Integer()); reader.End();
    }

    [Theory]
    [InlineData("40")]
    [InlineData("800000")]
    [InlineData("C0000000000000")]
    public void TruncatedVarint_Rejects(string hex) =>
        Assert.Throws<MoqProtocolException>(() => new MoqReader(Convert.FromHexString(hex)).Integer());

    [Fact]
    public void PeerSuppliedBlobLength_CannotExceedPayload() =>
        Assert.Throws<MoqProtocolException>(() => new MoqReader(Convert.FromHexString("4040")).Blob());

    [Fact]
    public void ParameterCount_IsBoundedBeforeAllocation() =>
        Assert.Throws<MoqProtocolException>(() => new MoqReader(Convert.FromHexString("4081")).Parameters());

    [Fact]
    public void DuplicateNonrepeatableParameter_Rejects() =>
        Assert.Throws<MoqProtocolException>(() => new MoqReader(Convert.FromHexString("0202010002")).Parameters());

    [Fact]
    public void MultiElementNamespace_CannotAliasSingleElementWithSlash()
    {
        var writer = new MoqWriter(); writer.Integer(2); writer.Text("a"); writer.Text("b");
        Assert.Throws<MoqProtocolException>(() => new MoqReader(writer.ToArray()).Namespace());
    }

    [Fact]
    public async Task ControlMessage_ReadsFragmentedTypeLengthAndBody()
    {
        await using var stream = new FragmentedStream(Convert.FromHexString("21000401024064"));
        var message = await MoqStreamWire.ReadMessageAsync(stream, CancellationToken.None);
        Assert.Equal(0x21UL, message.Type);
        var reader = new MoqReader(message.Payload); var parameters = reader.Parameters(); reader.End();
        Assert.Equal(100UL, parameters[2]);
    }

    [Fact]
    public async Task ControlMessage_PrematureFinIsFailure()
    {
        await using var stream = new MemoryStream(Convert.FromHexString("2100040102"));
        await Assert.ThrowsAsync<EndOfStreamException>(() => MoqStreamWire.ReadMessageAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task Integer_PartialFinIsFailure()
    {
        await using var stream = new MemoryStream(Convert.FromHexString("40"));
        await Assert.ThrowsAsync<EndOfStreamException>(async () => await MoqStreamWire.ReadIntegerAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task Integer_CleanFinBetweenObjectsIsAllowed()
    {
        await using var stream = new MemoryStream();
        Assert.Null(await MoqStreamWire.ReadIntegerAsync(stream, CancellationToken.None));
    }

    [Fact]
    public async Task InvalidTokenFailsBeforeNetwork()
    {
        var exception = await Assert.ThrowsAsync<ArgumentException>(() => CloudflareMoqClient.ConnectAsync("do/not/log/this-secret"));
        Assert.DoesNotContain("do/not/log/this-secret", exception.Message);
    }

    private sealed class FragmentedStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default) =>
            base.ReadAsync(buffer[..Math.Min(1, buffer.Length)], token);
    }
}
