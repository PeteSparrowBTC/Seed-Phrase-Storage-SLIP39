using FluentAssertions;
using Slip39Demo.Core.Wallet;
using Xunit;

namespace Slip39Demo.Tests.Wallet;

// Seeds to descriptor to first receive address.
//
// WHERE THE EXPECTED VALUES COME FROM, which is the only thing that makes this test
// worth anything: not from this implementation. Every descriptor and address below was
// computed by @scure/bip32 (derivation and xpub serialisation) and @scure/btc-signer
// (multisig script and bech32 address), the audited JavaScript stack by the author of
// noble/scure, driven by tools/descriptor-crosscheck. That stack shares no code with
// Slip39Demo.Core. Re-derive them with:
//
//     cd tools/descriptor-crosscheck && npm install && node crosscheck.mjs
//
// The seed words are published BIP-39 test vectors, so the seed half of the chain is
// pinned by the BIP-39 vector file this suite already runs, and only the BIP-32 and
// script half is new here.
public class MultisigWalletTests
{
    // BIP-39 published vector, entropy 00000000000000000000000000000000.
    const string SeedA =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // BIP-39 published vector, entropy 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f.
    const string SeedB =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    // BIP-39 published vector, entropy 80808080808080808080808080808080.
    const string SeedC =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

    const string Bip48 = "m/48'/0'/0'/2'";

    static MultisigCosigner Cosigner(string id, string seedWords, string? passphrase = null, string path = Bip48) =>
        new(Id: id, SeedWords: seedWords, Passphrase: passphrase, DerivationPath: path);

    [Fact]
    public void Two_of_two_produces_the_descriptor_the_independent_stack_produces()
    {
        var wallet = MultisigWallet.Describe([Cosigner("a", SeedA), Cosigner("b", SeedB)], signaturesRequired: 2);

        wallet.Value.Descriptor.Should().Be(
            "wsh(sortedmulti(2,"
            + "[73c5da0a/48h/0h/0h/2h]xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf/0/*,"
            + "[b8688df1/48h/0h/0h/2h]xpub6FQya7zGhR92kacYsNnjreouvnHJMpXYsUXnW6NJJAJRCKsa26TzDy4LdnGhEurr3d6y1J8PJ7EEMKQp74XTqYvmGJNogYXSKDszYHtF8mX/0/*"
            + "))#68nqsuv4");
    }

    [Fact]
    public void Two_of_two_produces_the_first_address_the_independent_stack_produces()
    {
        var wallet = MultisigWallet.Describe([Cosigner("a", SeedA), Cosigner("b", SeedB)], signaturesRequired: 2);

        wallet.Value.FirstReceiveAddress.Should()
            .Be("bc1qsks3qr92vdnr80q6y9vv6h4qwlzza9w8ts2pjp74wjj6ahvud5dsc3vhxe");
    }

    // The reason the record carries an address rather than a fingerprint. A master
    // fingerprint is identical whatever is derived afterwards, so it cannot catch a
    // wrong path; the address changes completely. Both wallets below share both seeds
    // and differ only in cosigner b's account index.
    [Fact]
    public void A_different_account_index_gives_a_completely_different_address()
    {
        var account0 = MultisigWallet.Describe(
            [Cosigner("a", SeedA), Cosigner("b", SeedB)], signaturesRequired: 2);
        var account1 = MultisigWallet.Describe(
            [Cosigner("a", SeedA), Cosigner("b", SeedB, path: "m/48'/0'/1'/2'")], signaturesRequired: 2);

        account1.Value.FirstReceiveAddress.Should()
            .Be("bc1qape6xeexx335klk2prt0pcsztyftxe688uwcrzctq4lwydascavsh6duer");
        account1.Value.FirstReceiveAddress.Should().NotBe(account0.Value.FirstReceiveAddress);
    }

    // sortedmulti orders the DERIVED public keys, so the wallet a recoverer rebuilds
    // must not depend on which cosigner they happened to type first. For these two seeds
    // the sorted order is b then a, the reverse of both input orders below, so a builder
    // that just used input order would fail this.
    [Fact]
    public void The_wallet_is_the_same_whichever_order_the_cosigners_are_entered_in()
    {
        var oneWay = MultisigWallet.Describe(
            [Cosigner("a", SeedA), Cosigner("b", SeedB)], signaturesRequired: 2);
        var otherWay = MultisigWallet.Describe(
            [Cosigner("b", SeedB), Cosigner("a", SeedA)], signaturesRequired: 2);

        otherWay.Value.FirstReceiveAddress.Should().Be(oneWay.Value.FirstReceiveAddress);
        otherWay.Value.Descriptor.Should().Be(oneWay.Value.Descriptor);
    }

    [Fact]
    public void Two_of_three_produces_what_the_independent_stack_produces()
    {
        var wallet = MultisigWallet.Describe(
            [Cosigner("a", SeedA), Cosigner("b", SeedB), Cosigner("c", SeedC)], signaturesRequired: 2);

        wallet.Value.Descriptor.Should().StartWith("wsh(sortedmulti(2,").And.EndWith("))#kp9wmyws");
        wallet.Value.FirstReceiveAddress.Should()
            .Be("bc1qm43n7nnev58aj3nrznz2xscgv98t7gxycq5pmp20a5vzfp5t0q2s7r6twa");
    }

    // A passphrase changes the seed, so it must change the wallet. A build that dropped
    // it would produce a descriptor for a wallet the owner does not have, and the
    // address is the only thing that would show it.
    [Fact]
    public void A_cosigners_passphrase_reaches_the_derivation()
    {
        var withPassphrase = MultisigWallet.Describe(
            [Cosigner("a", SeedA, passphrase: "TREZOR"), Cosigner("b", SeedB)], signaturesRequired: 2);

        withPassphrase.Value.FirstReceiveAddress.Should()
            .Be("bc1qn2d8rveja5hg62ppv8zg65zsm723ajsxpe22y8gwfkl96r8rsvmsydwyef");
    }

    [Fact]
    public void One_cosigner_is_not_a_multisig_and_is_refused()
    {
        var wallet = MultisigWallet.Describe([Cosigner("a", SeedA)], signaturesRequired: 1);

        wallet.IsFailure.Should().BeTrue();
        wallet.Error.Should().Contain("two");
    }

    // 2-of-2 or better. A 1-of-N wallet is a policy where any single share-holder spends
    // alone, which is what the threshold split exists to prevent.
    [Fact]
    public void One_signature_of_two_is_refused()
    {
        var wallet = MultisigWallet.Describe([Cosigner("a", SeedA), Cosigner("b", SeedB)], signaturesRequired: 1);

        wallet.IsFailure.Should().BeTrue();
        wallet.Error.Should().Contain("2 signatures");
    }

    [Fact]
    public void Requiring_more_signatures_than_there_are_cosigners_is_refused()
    {
        var wallet = MultisigWallet.Describe([Cosigner("a", SeedA), Cosigner("b", SeedB)], signaturesRequired: 3);

        wallet.IsFailure.Should().BeTrue();
        wallet.Error.Should().Contain("3").And.Contain("2 cosigners");
    }

    // Script type 1h is P2SH-wrapped multisig, which needs sh(wsh(...)) and a base58
    // address. Computing a bech32 address for it would produce a string that is not the
    // wallet's address, so the path is refused instead.
    [Fact]
    public void The_p2sh_wrapped_script_type_is_refused_rather_than_guessed()
    {
        var wallet = MultisigWallet.Describe(
            [Cosigner("a", SeedA, path: "m/48'/0'/0'/1'"), Cosigner("b", SeedB, path: "m/48'/0'/0'/1'")],
            signaturesRequired: 2);

        wallet.IsFailure.Should().BeTrue();
        wallet.Error.Should().Contain("2h");
    }

    // The single-sig purpose. Reachable by adding a second cosigner and leaving the path
    // field at what a single-sig wallet uses, which is exactly the mistake worth naming.
    [Theory]
    [InlineData("m/84'/0'/0'")]
    [InlineData("m/44'/0'/0'")]
    [InlineData("m/49'/0'/0'")]
    public void A_non_bip48_purpose_is_refused(string path)
    {
        var wallet = MultisigWallet.Describe(
            [Cosigner("a", SeedA, path: path), Cosigner("b", SeedB, path: path)], signaturesRequired: 2);

        wallet.IsFailure.Should().BeTrue();
        wallet.Error.Should().Contain("48h");
    }

    // Mainnet only. A tpub-shaped wallet would need different version bytes and a tb1
    // address, and silently emitting an xpub and a bc1 address for it would describe a
    // wallet on the wrong chain.
    [Fact]
    public void A_coin_type_other_than_bitcoin_mainnet_is_refused()
    {
        var wallet = MultisigWallet.Describe(
            [Cosigner("a", SeedA, path: "m/48'/1'/0'/2'"), Cosigner("b", SeedB, path: "m/48'/1'/0'/2'")],
            signaturesRequired: 2);

        wallet.IsFailure.Should().BeTrue();
        wallet.Error.Should().Contain("mainnet");
    }

    // BIP-48 specifies every element hardened. An unhardened account is a different key,
    // and one whose xpub lets anyone walk sideways to the other accounts.
    [Fact]
    public void An_unhardened_element_is_refused()
    {
        var wallet = MultisigWallet.Describe(
            [Cosigner("a", SeedA, path: "m/48'/0'/0/2'"), Cosigner("b", SeedB)], signaturesRequired: 2);

        wallet.IsFailure.Should().BeTrue();
        wallet.Error.Should().Contain("hardened");
    }

    [Fact]
    public void A_path_that_does_not_parse_is_refused_with_the_parser_message()
    {
        var wallet = MultisigWallet.Describe(
            [Cosigner("a", SeedA, path: "48'/0'/0'/2'"), Cosigner("b", SeedB)], signaturesRequired: 2);

        wallet.IsFailure.Should().BeTrue();
        wallet.Error.Should().Contain("must start with m");
    }

    // The refusal names the cosigner, because a form with three of them needs to say
    // which one to fix. Seed words never appear in any of these messages: they land in
    // an on-screen banner, which is the same reason PayloadRoundTrip's refusals do not
    // echo values.
    [Fact]
    public void A_refusal_names_the_cosigner_and_never_the_seed_words()
    {
        var wallet = MultisigWallet.Describe(
            [Cosigner("a", SeedA), Cosigner("trezor-two", SeedB, path: "m/84'/0'/0'")], signaturesRequired: 2);

        wallet.IsFailure.Should().BeTrue();
        wallet.Error.Should().Contain("trezor-two");
        wallet.Error.Should().NotContain("abandon").And.NotContain("legal winner");
    }

    // Seed words that are not BIP-39 cannot be derived from. The Owner page already
    // refuses a pasted backup key against unreadable seeds; this is the same fact
    // reaching the descriptor, and it must not produce an address computed from
    // whatever bytes the words happened to hash to.
    [Fact]
    public void Seed_words_that_are_not_valid_bip39_are_refused()
    {
        var wallet = MultisigWallet.Describe(
            [Cosigner("a", SeedA), Cosigner("b", "not a valid mnemonic at all")], signaturesRequired: 2);

        wallet.IsFailure.Should().BeTrue();
        wallet.Error.Should().Contain("BIP-39");
    }
}
