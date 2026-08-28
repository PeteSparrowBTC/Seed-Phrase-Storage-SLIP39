using System.Security.Cryptography;
using System.Text.RegularExpressions;
using FluentAssertions;
using Slip39Demo.Core.Bip32;
using Xunit;

namespace Slip39Demo.Tests.Bip32;

// The published BIP-32 test vectors, run against our own derivation and xpub
// serialisation. The vectors are not transcribed into this file: bip-0032.mediawiki
// is vendored byte for byte as bitcoin/bips publishes it, its SHA-256 is asserted
// below, and the chains are read out of it at runtime. That is the same bar
// Bip39MnemonicTests holds, and for the same reason: a hand-copied table can be
// quietly adjusted until the tests go green, and then it is evidence of nothing.
//
// Vector 5 (invalid extended keys) is deliberately not exercised. Those cases are
// about REJECTING malformed xpubs on parse, and nothing here parses one: the tool
// derives keys from seed words it already holds and serialises them outward.
//
// Only ext pub is checked, never ext prv. Serialising an xprv would double the
// vector coverage and put a function that prints a private key into a wallet-backup
// tool, which is a trade this file declines: depth, parent fingerprint, child
// number, chain code and the public key all appear in the xpub, so a mistake in any
// of them fails here anyway.
public class Bip32VectorTests
{
    // sha256sum of bip-0032.mediawiki as fetched from
    // raw.githubusercontent.com/bitcoin/bips/master/bip-0032.mediawiki on 2026-08-28.
    // .gitattributes pins the path to eol=lf, so a Windows clone hashes the same.
    const string VectorFileSha256 =
        "e5e00a8289db2f681052cf24a745320afc225e66b25d1e489a7c884d2fc7f11f";

    // Vector 1 has six chains, vector 2 six, vector 3 two, vector 4 three. Asserted so
    // a parser that silently stops reading cannot look like a pass.
    const int ExpectedChainCount = 17;

    static string VectorFilePath =>
        Path.Combine(AppContext.BaseDirectory, "Bip32", "Vectors", "bip-0032.mediawiki");

    [Fact]
    public void The_vendored_vector_file_is_the_published_one()
    {
        var bytes = File.ReadAllBytes(VectorFilePath);

        Convert.ToHexStringLower(SHA256.HashData(bytes)).Should().Be(VectorFileSha256);
    }

    [Fact]
    public void Every_published_chain_serialises_to_the_published_xpub()
    {
        var chains = ReadChains();

        chains.Should().HaveCount(ExpectedChainCount);

        chains.ForEach(chain =>
            Bip32ExtendedKey.FromSeed(Convert.FromHexString(chain.SeedHex))
                .Derive(Bip32Path.Parse(chain.Path).Value)
                .ToXpub()
                .Should().Be(chain.ExpectedXpub, $"chain {chain.Path} of seed {chain.SeedHex[..8]}..."));
    }

    // One chain of one vector: the seed it starts from, the path, the published xpub.
    sealed record Chain(string SeedHex, string Path, string ExpectedXpub);

    // The file's shape, per vector:
    //   Seed (hex): 000102030405060708090a0b0c0d0e0f
    //   * Chain m/0<sub>H</sub>/1
    //   ** ext pub: xpub6ASuArnXK...
    //   ** ext prv: xprv9wTYmMFdV...
    // A "* Chain" line names the path; the "** ext pub" line that follows carries the
    // expectation. Vector 5's lines start "* xpub", which is why the chain pattern
    // requires the word Chain.
    static List<Chain> ReadChains()
    {
        var seedHex = "";
        var path = "";
        var chains = new List<Chain>();

        foreach (var line in File.ReadAllLines(VectorFilePath))
        {
            var seed = Regex.Match(line, @"^Seed \(hex\): ([0-9a-f]+)$");
            if (seed.Success)
            {
                seedHex = seed.Groups[1].Value;
                continue;
            }

            var chain = Regex.Match(line, @"^\* Chain (m[^\s]*)$");
            if (chain.Success)
            {
                // <sub>H</sub> is the BIP's rendering of the hardened marker.
                path = chain.Groups[1].Value.Replace("<sub>H</sub>", "'");
                continue;
            }

            var xpub = Regex.Match(line, @"^\*\* ext pub: (xpub[1-9A-HJ-NP-Za-km-z]+)$");
            if (xpub.Success && path.Length > 0)
                chains.Add(new Chain(seedHex, path, xpub.Groups[1].Value));
        }

        return chains;
    }
}
