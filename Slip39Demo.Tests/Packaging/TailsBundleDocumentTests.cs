using FluentAssertions;
using Slip39Demo.Core.Bundle;
using Slip39Demo.Tests.Ui;
using Xunit;

namespace Slip39Demo.Tests.Packaging;

// The Tails bundle's launcher and instructions, pinned where they name something another
// file owns.
//
// WHY THESE ARE C# TESTS FOR SHELL AND TEXT FILES. packaging/tails-bundle/build-bundle.sh
// asserts what it can see for itself: that its checker refuses a corrupted AppImage, that
// the zip stores the right modes, that no placeholder survived substitution. What it cannot
// see is whether the words in READ-THIS-FIRST.txt still describe this application. That
// document names the ciphertext the backup ships and the two documents inside it, and those
// names live in C#. ShippedDocumentConsistencyTests exists for exactly this class of drift
// in the documents shipped INSIDE a backup; this is the same argument one layer out.
//
// The names have changed before. Three payload files became one, and every document that
// named them had to be rewritten. A document that quietly keeps naming the old one is worse
// than no document, because it is read at the moment somebody is looking for that file.
public class TailsBundleDocumentTests
{
    static string BundlePath(string name) =>
        Path.Combine(StylesheetContractTests.RepoRootPath(), "packaging", "tails-bundle", name);

    static string Instructions() => File.ReadAllText(BundlePath("READ-THIS-FIRST.txt"));

    static string Launcher() => File.ReadAllText(BundlePath("start-here.sh"));

    static string Workflow() =>
        File.ReadAllText(Path.Combine(
            StylesheetContractTests.RepoRootPath(), ".github", "workflows", "appimage.yml"));

    [Fact]
    public void The_instructions_name_the_ciphertext_that_actually_ships() =>
        Instructions().Should().Contain(OutputBundleBuilder.PayloadFileName,
            "the instructions send the reader looking for this file by name");

    [Fact]
    public void The_instructions_name_the_owner_documents_they_point_at()
    {
        var text = Instructions();

        text.Should().Contain(VerifyGuide.FileName);
        text.Should().Contain("IMPORTANT-READ-FIRST.txt");
    }

    // build-bundle.sh fails if a placeholder SURVIVES substitution. It cannot fail if a
    // placeholder was never there: the fingerprint would simply stop being printed in the
    // instructions, and the reader who wanted to check it by hand would find nothing to
    // compare against. So the placeholders are pinned here.
    [Theory]
    [InlineData("@VERSION@")]
    [InlineData("@SHA256@")]
    public void The_instructions_still_carry_the_placeholder_the_build_substitutes(string placeholder) =>
        Instructions().Should().Contain(placeholder);

    // Read on paper beside the stick, by somebody who does not use a terminal. Same limit
    // the other printed documents hold, and for the same reason: a line wider than the page
    // wraps somewhere the author did not choose.
    [Fact]
    public void The_instructions_stay_within_a_printable_width() =>
        Instructions().Split('\n').Should().OnlyContain(line => line.TrimEnd().Length <= 82,
            "READ-THIS-FIRST.txt is printed and read on paper");

    // The launcher globs for the app rather than naming a version, and the glob has to match
    // what the workflow actually builds. If the artifact were renamed, the launcher would
    // find no app and every bundle would refuse to open with a message about extracting the
    // zip again, which is not what went wrong.
    [Fact]
    public void The_launchers_glob_matches_the_appimage_the_workflow_builds()
    {
        Launcher().Should().Contain("slip39-backup-*-x86_64.AppImage");
        Workflow().Should().Contain("appimage=slip39-backup-${VERSION}-x86_64.AppImage");
    }

    // The zip the workflow publishes and the zip the script writes are named in two places,
    // and a release that attached a file nobody built would fail late, in the publish step
    // of a tagged run, which is the worst moment to find out.
    [Fact]
    public void The_workflow_publishes_the_bundle_the_script_writes()
    {
        File.ReadAllText(BundlePath("build-bundle.sh"))
            .Should().Contain("bundle_name=\"slip39-backup-${version}-tails\"");

        Workflow().Should().Contain("slip39-backup-${{ steps.version.outputs.value }}-tails.zip");
    }

    // The launcher must never imply the check establishes authenticity. It is the file a
    // non-technical reader is most likely to take at face value, and the whole design
    // depends on that limit being stated rather than glossed.
    [Fact]
    public void Both_files_say_what_the_check_cannot_do()
    {
        Launcher().Should().Contain("cannot prove the download itself was genuine");
        Instructions().Should().Contain("does not tell you the download itself was genuine");
    }
}
