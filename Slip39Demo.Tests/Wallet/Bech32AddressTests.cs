using FluentAssertions;
using Slip39Demo.Core.Wallet;
using Xunit;

namespace Slip39Demo.Tests.Wallet;

// The published BIP-173 address vectors. Transcribed rather than vendored, because the
// BIP carries two of them and both appear here in full: the program hex and the address
// are each written out, so a reader can check them against the BIP by eye.
//
// Both witness program sizes matter to this tool even though it only ever emits one of
// them. 20 bytes is P2WPKH and 32 is P2WSH, and the encoder must not care which; a
// length-dependent bug would show up as a wrong multisig address and nothing else.
public class Bech32AddressTests
{
    // BIP-173: "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4: 0014751e76e8199196d454941c45d1b3a323f1433bd6"
    // The BIP prints it uppercase (valid, and what a QR code should carry). Lowercase is
    // the canonical form an encoder produces, so the published string is folded here.
    [Fact]
    public void The_published_mainnet_p2wpkh_vector_encodes()
    {
        var address = Bech32Address.EncodeSegwitV0(
            "bc", Convert.FromHexString("751e76e8199196d454941c45d1b3a323f1433bd6"));

        address.Value.Should().Be("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4".ToLowerInvariant());
    }

    // BIP-173: "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7:
    //           00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"
    // A 32-byte program, which is the shape every address this tool computes will have.
    // The hrp is tb because that is the vector the BIP publishes at this length; the
    // encoder takes the hrp as an argument precisely so a published vector can be run.
    [Fact]
    public void The_published_p2wsh_vector_encodes()
    {
        var address = Bech32Address.EncodeSegwitV0(
            "tb", Convert.FromHexString("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"));

        address.Value.Should().Be("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7");
    }

    // Witness v0 has exactly two valid program lengths. Anything else is not an address
    // this tool can compute, and guessing would produce a string that looks like one.
    [Theory]
    [InlineData(19)]
    [InlineData(21)]
    [InlineData(31)]
    [InlineData(33)]
    public void A_program_that_is_not_twenty_or_thirty_two_bytes_is_refused(int length)
    {
        var result = Bech32Address.EncodeSegwitV0("bc", new byte[length]);

        result.IsFailure.Should().BeTrue();
        result.Error.Should().Contain($"{length}");
    }
}
