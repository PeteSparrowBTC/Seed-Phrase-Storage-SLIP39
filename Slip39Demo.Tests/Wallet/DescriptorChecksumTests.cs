using FluentAssertions;
using Slip39Demo.Core.Wallet;
using Xunit;

namespace Slip39Demo.Tests.Wallet;

// The published BIP-380 descriptor checksum vector, plus the properties the checksum is
// specified to have. Bitcoin Core's importdescriptors refuses a descriptor with no
// checksum, so this is not decoration: without it the computed descriptor cannot be
// imported at all.
public class DescriptorChecksumTests
{
    // BIP-380, Test Vectors: "Valid checksum: raw(deadbeef)#89f8spxm".
    [Fact]
    public void The_published_vector_reproduces()
    {
        DescriptorChecksum.Append("raw(deadbeef)").Value.Should().Be("raw(deadbeef)#89f8spxm");
    }

    // BIP-380: "A case error always counts as 1 symbol error", and any single symbol
    // error is always detected. Both spellings are valid descriptors, so a checksum that
    // ignored case would hand back the same 8 characters for two different wallets.
    [Fact]
    public void A_case_change_changes_the_checksum()
    {
        var lower = DescriptorChecksum.Append("raw(deadbeef)").Value;
        var upper = DescriptorChecksum.Append("raw(DEADBEEF)").Value;

        upper.Should().NotBe(lower);
    }

    // The BIP's character set is what the checksum is defined over. A character outside
    // it has no symbol value, so there is no checksum to compute; emitting one anyway
    // would produce a descriptor that fails validation somewhere else, later.
    [Fact]
    public void A_character_outside_the_published_set_is_refused()
    {
        var result = DescriptorChecksum.Append("raw(Ü)");

        result.IsFailure.Should().BeTrue();
        result.Error.Should().Contain("character");
    }

    // Eight characters from the bech32 alphabet, following a single octothorpe.
    [Fact]
    public void The_checksum_is_eight_characters_after_an_octothorpe()
    {
        var checksummed = DescriptorChecksum.Append("wsh(sortedmulti(2,x,y))").Value;

        var parts = checksummed.Split('#');
        parts.Should().HaveCount(2);
        parts[1].Should().HaveLength(8);
        parts[1].Should().MatchRegex("^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{8}$");
    }
}
