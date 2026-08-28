using System.IO.Compression;
using System.Text;
using Bunit;
using CSharpFunctionalExtensions;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Slip39Demo.Core.Age;
using Slip39Demo.Core.Bundle;
using Slip39Demo.Core.Pgp;
using Slip39Demo.UI.Pages;
using Slip39Demo.UI.Services;
using Slip39Demo.Web.Services;
using Xunit;

namespace Slip39Demo.Tests.Web;

// The Owner page computing the wallet descriptor instead of asking for one.
//
// MultisigWalletTests pins the derivation against an independent stack; this file proves
// the page is wired to it: that the computed descriptor is what lands in the encrypted
// payload, that the first receive address reaches the verification record, that a pasted
// descriptor still wins, and that a path the builder cannot describe stops generation
// rather than shipping a guess.
public class OwnerDescriptorTests : TestContext
{
    const string TopLevelSeedSelector =
        "input[placeholder='abandon ability able about above absent absorb abstract absurd abuse access accident']";

    const string CosignerSeedSelector = "input[placeholder='abandon ability able about ...']";

    const string DescriptorSelector = "input[placeholder='wsh(sortedmulti(2, ...))']";

    const string PathSelector = "input[placeholder=\"m/48'/0'/0'/2'\"]";

    const string SignaturesSelector = "input[placeholder='signatures required']";

    // Published BIP-39 vectors, the same two MultisigWalletTests uses, so the expected
    // descriptor and address here are the ones the independent stack computed.
    const string SeedA =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    const string SeedB =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";

    const string ExpectedTwoOfTwoAddress =
        "bc1qsks3qr92vdnr80q6y9vv6h4qwlzza9w8ts2pjp74wjj6ahvud5dsc3vhxe";

    public OwnerDescriptorTests()
    {
        Services.AddSingleton<IIndependentVerifier>(new FakeVerifier());
        Services.AddSingleton<IConnectivityProbe>(new FakeProbe());
        Services.AddSingleton<IPayloadEncryptor>(new AgeSharpPayloadEncryptor());
        Services.AddSingleton<IOuterLockVerifier>(new FakeOuterLockVerifier());
        Services.AddSingleton<IFileDownloader>(new NoopDownloader());
    }

    [Fact]
    public void With_one_cosigner_there_is_nothing_to_ask_about_signatures()
    {
        var cut = RenderComponent<Owner>();

        cut.FindAll(SignaturesSelector).Should().BeEmpty();
    }

    [Fact]
    public void Adding_a_second_cosigner_asks_how_many_signatures_the_wallet_needs()
    {
        var cut = RenderComponent<Owner>();

        AddCosigner(cut);

        cut.FindAll(SignaturesSelector).Should().ContainSingle();
    }

    // A second cosigner makes this a multisig wallet, and multisig has its own BIP-32
    // purpose field. Leaving both cosigners on the single-sig default would refuse at
    // Generate for a reason the owner did not cause, so the untouched default moves.
    [Fact]
    public void Adding_a_second_cosigner_moves_untouched_paths_to_the_bip48_default()
    {
        var cut = RenderComponent<Owner>();

        AddCosigner(cut);

        var paths = cut.FindAll(PathSelector).Select(input => input.GetAttribute("value")).ToList();
        paths.Should().HaveCount(2);
        paths.Should().AllBe("m/48'/0'/0'/2'");
    }

    // A path the owner edited is theirs. Moving it would overwrite a deliberate choice,
    // and the one thing worse than refusing a path is silently substituting another.
    [Fact]
    public void Adding_a_second_cosigner_leaves_an_edited_path_alone()
    {
        var cut = RenderComponent<Owner>();
        cut.FindAll(PathSelector).First().Change("m/48'/0'/7'/2'");

        AddCosigner(cut);

        cut.FindAll(PathSelector).Select(input => input.GetAttribute("value"))
            .Should().Contain("m/48'/0'/7'/2'");
    }

    // The load-bearing one: the descriptor inside the shipped, doubly-encrypted payload is
    // the computed one, matching what the independent stack produced.
    [Fact]
    public void The_computed_descriptor_is_what_lands_in_the_encrypted_payload()
    {
        var downloader = TwoCosignerBackup(out var cut);

        cut.Find("button.btn-primary").Click();
        cut.WaitForAssertion(() => downloader.Calls.Should().ContainSingle(),
            timeout: TimeSpan.FromSeconds(20));

        var payloadText = DecryptPayload(downloader.Calls[0].Bytes, cut);

        payloadText.Should().Contain(
            "wsh(sortedmulti(2,"
            + "[73c5da0a/48h/0h/0h/2h]xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf/0/*,"
            + "[b8688df1/48h/0h/0h/2h]xpub6FQya7zGhR92kacYsNnjreouvnHJMpXYsUXnW6NJJAJRCKsa26TzDy4LdnGhEurr3d6y1J8PJ7EEMKQp74XTqYvmGJNogYXSKDszYHtF8mX/0/*"
            + "))#68nqsuv4");
    }

    [Fact]
    public void The_first_receive_address_reaches_the_verification_record()
    {
        var downloader = TwoCosignerBackup(out var cut);

        cut.Find("button.btn-primary").Click();
        cut.WaitForAssertion(() => downloader.Calls.Should().ContainSingle(),
            timeout: TimeSpan.FromSeconds(20));

        var record = Encoding.UTF8.GetString(
            ReadBundleEntry(downloader.Calls[0].Bytes, "verification-record.txt"));

        record.Should().Contain("First receive address:");
        record.Should().Contain(ExpectedTwoOfTwoAddress);
        record.Should().Contain("computed by this tool");
    }

    // The record is a file the owner is told to print and to keep in a password manager,
    // so the descriptor's xpubs must not follow the address into it.
    [Fact]
    public void The_verification_record_carries_the_address_but_not_the_descriptor()
    {
        var downloader = TwoCosignerBackup(out var cut);

        cut.Find("button.btn-primary").Click();
        cut.WaitForAssertion(() => downloader.Calls.Should().ContainSingle(),
            timeout: TimeSpan.FromSeconds(20));

        var record = Encoding.UTF8.GetString(
            ReadBundleEntry(downloader.Calls[0].Bytes, "verification-record.txt"));

        record.Should().NotMatchRegex("xpub[1-9A-HJ-NP-Za-km-z]{20,}");
        record.Should().NotContain("sortedmulti");
    }

    // The address is the thing the owner is supposed to compare against their wallet, so
    // it appears where they will see it and not only in a file inside the zip.
    [Fact]
    public void The_result_panel_shows_the_first_receive_address()
    {
        var downloader = TwoCosignerBackup(out var cut);

        cut.Find("button.btn-primary").Click();
        cut.WaitForAssertion(() => downloader.Calls.Should().ContainSingle(),
            timeout: TimeSpan.FromSeconds(20));

        cut.Markup.Should().Contain(ExpectedTwoOfTwoAddress);
    }

    // Shared-seed multisig: one seed at the top, cosigners distinguished by passphrase.
    // The cosigner seed fields are empty, so the descriptor has to be computed from the
    // top-level seed rather than from nothing.
    [Fact]
    public void A_shared_seed_multisig_computes_from_the_top_level_seed()
    {
        var downloader = new NoopDownloader();
        Services.AddSingleton<IFileDownloader>(downloader);

        var cut = RenderComponent<Owner>();
        cut.FindAll(TopLevelSeedSelector).First().Change(SeedA);
        AddCosigner(cut);
        cut.FindAll("input[placeholder='Leave empty if no passphrase']").Last().Change("second-context");

        cut.Find("button.btn-primary").Click();
        cut.WaitForAssertion(() => downloader.Calls.Should().ContainSingle(),
            timeout: TimeSpan.FromSeconds(20));

        DecryptPayload(downloader.Calls[0].Bytes, cut).Should().Contain("wsh(sortedmulti(2,");
    }

    // Pasted still wins, for a wallet that already exists on a path this tool does not
    // compute. The record then says the descriptor was not derived here.
    [Fact]
    public void A_pasted_descriptor_overrides_the_computed_one_and_the_record_says_so()
    {
        var downloader = TwoCosignerBackup(out var cut);
        cut.FindAll(DescriptorSelector).First().Change("wsh(sortedmulti(2,[deadbeef/45h]xpubFAKE/0/*))");

        cut.Find("button.btn-primary").Click();
        cut.WaitForAssertion(() => downloader.Calls.Should().ContainSingle(),
            timeout: TimeSpan.FromSeconds(20));

        DecryptPayload(downloader.Calls[0].Bytes, cut).Should().Contain("xpubFAKE");

        var record = Encoding.UTF8.GetString(
            ReadBundleEntry(downloader.Calls[0].Bytes, "verification-record.txt"));
        record.Should().Contain("entered by you");
        record.Should().NotContain("First receive address:");
    }

    // A path the builder will not describe stops generation with the reason named, rather
    // than shipping a backup whose descriptor field is empty or wrong. Nothing downloads.
    [Fact]
    public void A_single_sig_path_on_a_multisig_wallet_refuses_generation()
    {
        var downloader = TwoCosignerBackup(out var cut);
        cut.FindAll(PathSelector).First().Change("m/84'/0'/0'");

        cut.Find("button.btn-primary").Click();

        cut.WaitForAssertion(() =>
        {
            cut.FindAll(".banner-loud").Should().Contain(el => el.TextContent.Contains("48h"));
        }, timeout: TimeSpan.FromSeconds(20));

        downloader.Calls.Should().BeEmpty();
    }

    // The refusal must not be reachable for the single-cosigner case, which never had a
    // computed descriptor and must keep working exactly as it did.
    [Fact]
    public void A_single_cosigner_backup_still_generates_with_no_descriptor()
    {
        var downloader = new NoopDownloader();
        Services.AddSingleton<IFileDownloader>(downloader);

        var cut = RenderComponent<Owner>();
        cut.FindAll(TopLevelSeedSelector).First().Change(SeedA);

        cut.Find("button.btn-primary").Click();
        cut.WaitForAssertion(() => downloader.Calls.Should().ContainSingle(),
            timeout: TimeSpan.FromSeconds(20));

        var record = Encoding.UTF8.GetString(
            ReadBundleEntry(downloader.Calls[0].Bytes, "verification-record.txt"));
        record.Should().NotContain("First receive address:");
        record.Should().NotContain("Wallet descriptor:");
    }

    // Selected by its text rather than its class: the class is shared with the home link
    // and the transcript toggle, and a test that clicks the wrong button fails for a
    // reason that has nothing to do with descriptors.
    static void AddCosigner(IRenderedComponent<Owner> cut) =>
        cut.FindAll("button").First(button => button.TextContent.Contains("Add cosigner")).Click();

    // Two cosigners with their own published seeds, both on the BIP-48 default.
    NoopDownloader TwoCosignerBackup(out IRenderedComponent<Owner> cut)
    {
        var downloader = new NoopDownloader();
        Services.AddSingleton<IFileDownloader>(downloader);

        cut = RenderComponent<Owner>();
        AddCosigner(cut);

        var seeds = cut.FindAll(CosignerSeedSelector);
        seeds[0].Change(SeedA);
        cut.FindAll(CosignerSeedSelector)[1].Change(SeedB);

        return downloader;
    }

    // Takes both locks off the shipped artifact with the key the shares carry, so the
    // assertion is about the file the owner actually holds.
    static string DecryptPayload(byte[] bundle, IRenderedComponent<Owner> cut)
    {
        var key = RecoverKeyFromShares(bundle);
        var shipped = ReadBundleEntry(bundle, $"payload/{OutputBundleBuilder.PayloadFileName}");

        var unwrapped = PgpEnvelope.Decrypt(shipped, key);
        unwrapped.IsSuccess.Should().BeTrue(unwrapped.IsFailure ? unwrapped.Error : "");

        var decrypted = AgePassphrase.Decrypt(unwrapped.Value, key);
        decrypted.IsSuccess.Should().BeTrue(decrypted.IsFailure ? decrypted.Error : "");

        return Encoding.UTF8.GetString(decrypted.Value);
    }

    static byte[] RecoverKeyFromShares(byte[] bundle)
    {
        var mnemonics = ShareMnemonics(bundle).Take(3).ToList();
        var recovered = Slip39Demo.Core.Slip39.Slip39Wrapping.CombineMnemonics(mnemonics);

        recovered.IsSuccess.Should().BeTrue(recovered.IsFailure ? recovered.Error : "");
        return recovered.Value;
    }

    static List<string> ShareMnemonics(byte[] bundle)
    {
        using var outer = new ZipArchive(new MemoryStream(bundle), ZipArchiveMode.Read);

        return outer.Entries
            .Where(entry => entry.FullName.StartsWith("shares/"))
            .Select(entry =>
            {
                using var shareStream = new MemoryStream();
                using (var opened = entry.Open())
                    opened.CopyTo(shareStream);

                using var share = new ZipArchive(new MemoryStream(shareStream.ToArray()), ZipArchiveMode.Read);
                var mnemonicEntry = share.Entries.Single(e => e.FullName.EndsWith("share.slip39"));

                using var reader = new StreamReader(mnemonicEntry.Open());
                return reader.ReadToEnd().Trim();
            })
            .ToList();
    }

    static byte[] ReadBundleEntry(byte[] bundle, string entryName)
    {
        using var archive = new ZipArchive(new MemoryStream(bundle), ZipArchiveMode.Read);
        var entry = archive.GetEntry(entryName);
        entry.Should().NotBeNull($"the bundle should contain {entryName}");

        using var stream = entry!.Open();
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    sealed class FakeProbe : IConnectivityProbe
    {
        public Task<bool> IsOnlineAsync() => Task.FromResult(false);
    }

    sealed class FakeVerifier : IIndependentVerifier
    {
        public Task<Result> VerifyAsync(
            IReadOnlyList<IReadOnlyList<string>> subsets, byte[] payloadAge, string expectedPayloadText) =>
            Task.FromResult(Result.Success());

        public Task<Result> VerifyForeignReadableAsync() => Task.FromResult(Result.Success());
    }

    sealed class NoopDownloader : IFileDownloader
    {
        public List<(string Filename, byte[] Bytes, string Mime)> Calls { get; } = new();

        public ValueTask<bool> DownloadAsync(string filename, byte[] bytes, string mimeType)
        {
            Calls.Add((filename, bytes, mimeType));
            return ValueTask.FromResult(true);
        }
    }
}
