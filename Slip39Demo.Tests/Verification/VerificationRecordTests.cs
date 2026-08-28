using FluentAssertions;
using Slip39Demo.Core.Bip32;
using Slip39Demo.Core.Verification;
using Slip39Demo.Core.Wallet;
using Xunit;

namespace Slip39Demo.Tests.Verification;

public class VerificationRecordTests
{
    [Fact]
    public void Build_ContainsAllRequiredSections()
    {
        var mnemonics = new[]
        {
            "abandon ability able about above absent absorb abstract absurd abuse",
            "across action actor actress actual adapt add addict address adjust",
            "admit adult advance advice aerobic affair afford afraid again age",
        };
        var payloadBytes = "fake-ciphertext-content"u8.ToArray();
        var masterFp = Bip32Fingerprint.From(new byte[] { 0x7a, 0x3f, 0x9c, 0x2d });

        var rec = VerificationRecord.Build(
            createdDate: "2026-05-21",
            toolVersion: "2.0.0",
            label: "Main wallet 2026",
            mnemonicsInOrder: mnemonics,
            payloadAgeBytes: payloadBytes,
            walletMasterFingerprint: masterFp);

        rec.Should().Contain("slip39-backup Verification Record");
        rec.Should().Contain("Created:       2026-05-21");
        rec.Should().Contain("Tool version:  2.0.0");
        rec.Should().Contain("Label:         Main wallet 2026");
        rec.Should().Contain("Wallet master fingerprint (BIP-32):  7a3f9c2d");
        rec.Should().Contain("share-1-of-3:");
        rec.Should().Contain("share-2-of-3:");
        rec.Should().Contain("share-3-of-3:");
        rec.Should().Contain("Payload integrity (SHA256 of payload.age):");
        rec.Should().Contain("DO NOT distribute to share-holders");
    }

    [Fact]
    public void ShareFingerprint_IsTruncatedSha256OfMnemonic_8HexChars()
    {
        var fp = ShareFingerprint.Compute("abandon ability able");

        fp.Should().HaveLength(8);
        fp.Should().MatchRegex("^[0-9a-f]{8}$");
    }

    // The first receive address is what makes a dry-run check meaningful for a multisig
    // wallet: the master fingerprint above cannot catch a wrong derivation path, script
    // type, key ordering or threshold, and the address catches all four.
    [Fact]
    public void A_computed_descriptor_puts_the_first_receive_address_in_the_record()
    {
        var rec = Record(DescriptorProvenance.Computed,
            "bc1qsks3qr92vdnr80q6y9vv6h4qwlzza9w8ts2pjp74wjj6ahvud5dsc3vhxe");

        rec.Should().Contain("First receive address:");
        rec.Should().Contain("bc1qsks3qr92vdnr80q6y9vv6h4qwlzza9w8ts2pjp74wjj6ahvud5dsc3vhxe");
    }

    // Which of the two it was, because a pasted descriptor was never checked by anything
    // here and the owner reading this years later cannot tell otherwise.
    [Fact]
    public void A_computed_descriptor_says_it_was_derived_here()
    {
        var rec = Record(DescriptorProvenance.Computed, "bc1qexample");

        rec.Should().Contain("computed by this tool");
    }

    [Fact]
    public void A_pasted_descriptor_says_so_and_carries_no_address()
    {
        var rec = Record(DescriptorProvenance.Pasted, firstReceiveAddress: null);

        rec.Should().Contain("entered by you");
        rec.Should().NotContain("First receive address:");
    }

    // A single-signature backup has no descriptor, and the record keeps the shape it has
    // always had rather than gaining a section that says "none".
    [Fact]
    public void No_descriptor_leaves_the_section_out_entirely()
    {
        var rec = Record(DescriptorProvenance.NotRecorded, firstReceiveAddress: null);

        rec.Should().NotContain("First receive address:");
        rec.Should().NotContain("Wallet descriptor:");
    }

    // The record tells the owner to print it and to keep a copy in a password manager.
    // A serialised xpub there would reveal every address the wallet will ever use, and
    // their balances, permanently. The descriptor and its xpubs belong in the encrypted
    // payload; the address is the one part that may appear here.
    //
    // Matched as key material rather than as the word: the prose is free to explain what
    // an xpub is, and what must never appear is 111 base58 characters of one.
    [Fact]
    public void The_record_never_carries_a_serialised_xpub()
    {
        var rec = Record(DescriptorProvenance.Computed, "bc1qexample");

        rec.Should().NotMatchRegex("xpub[1-9A-HJ-NP-Za-km-z]{20,}");
    }

    static string Record(DescriptorProvenance provenance, string? firstReceiveAddress) =>
        VerificationRecord.Build(
            createdDate: "2026-05-21",
            toolVersion: "2.0.0",
            label: "Main wallet",
            mnemonicsInOrder: ["a b c"],
            payloadAgeBytes: "x"u8.ToArray(),
            walletMasterFingerprint: Bip32Fingerprint.From([0x7a, 0x3f, 0x9c, 0x2d]),
            descriptorProvenance: provenance,
            firstReceiveAddress: firstReceiveAddress);

    [Fact]
    public void Build_PayloadSha256_MatchesExpected()
    {
        var bytes = "hello"u8.ToArray();
        var rec = VerificationRecord.Build(
            "2026-05-21", "2.0.0", "x",
            ["a b c"], bytes,
            Bip32Fingerprint.From(new byte[] { 0, 0, 0, 0 }));

        // Sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        rec.Should().Contain("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }
}
