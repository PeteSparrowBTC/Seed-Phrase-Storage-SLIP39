using FluentAssertions;
using Slip39Demo.Core.Payload;
using Xunit;

namespace Slip39Demo.Tests.Payload;

// A computed descriptor through the payload format, guarding one specific hazard.
//
// THE HAZARD. A descriptor ends in its BIP-380 checksum, introduced by an octothorpe:
// wsh(sortedmulti(2,...))#68nqsuv4. The payload parser treats a line that STARTS with #
// as a comment, which is fine, but a rule that stripped everything from the first # on a
// line, the way most config formats do, would silently drop the checksum. Bitcoin Core's
// importdescriptors refuses a descriptor with no checksum, so the failure would surface
// at recovery, in the executor's hands, as a descriptor that cannot be imported.
//
// PayloadRoundTrip.EmitChecked would catch it at generation, which is exactly what it is
// for; this pins the parser's behaviour directly, so a future change to comment handling
// fails here with the reason named rather than as a mysterious refusal.
public class PayloadDescriptorTests
{
    // The 2-of-2 descriptor MultisigWalletTests pins, shortened in the middle. The
    // checksum and the bracket, slash and asterisk characters are what matter.
    const string Descriptor =
        "wsh(sortedmulti(2,[73c5da0a/48h/0h/0h/2h]xpub6DkFAXWQ2dHxq/0/*,"
        + "[b8688df1/48h/0h/0h/2h]xpub6FQya7zGhR92k/0/*))#68nqsuv4";

    static PayloadV1_1 WithDescriptor(string? descriptor) =>
        new("1.1", "2026-08-11T00:00:00Z", "Main wallet", null,
            [
                new Cosigner("a", "bip39", null, "m/48'/0'/0'/2'",
                    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                    "73c5da0a"),
                new Cosigner("b", "bip39", null, "m/48'/0'/0'/2'",
                    "legal winner thank year wave sausage worth useful legal winner thank yellow",
                    "b8688df1"),
            ],
            descriptor, "3-of-5", true, null);

    [Fact]
    public void The_checksum_survives_the_round_trip()
    {
        var emitted = PayloadEmitter.Emit(WithDescriptor(Descriptor));

        var parsed = PayloadParser.Parse(emitted);

        parsed.IsSuccess.Should().BeTrue(parsed.IsFailure ? parsed.Error : "");
        parsed.Value.Descriptor.Should().Be(Descriptor);
        parsed.Value.Descriptor.Should().EndWith("#68nqsuv4");
    }

    // The gate that would refuse rather than ship a truncated descriptor, exercised on
    // the value this feature actually produces.
    [Fact]
    public void The_checked_emitter_accepts_a_computed_descriptor()
    {
        var emitted = PayloadRoundTrip.EmitChecked(WithDescriptor(Descriptor));

        emitted.IsSuccess.Should().BeTrue(emitted.IsFailure ? emitted.Error : "");
        emitted.Value.Should().Contain(Descriptor);
    }
}
