using CSharpFunctionalExtensions;

namespace Slip39Demo.Core.Wallet;

// The BIP-380 descriptor checksum: eight characters after an octothorpe, computed over
// the descriptor's own character set.
//
// Not decoration. Bitcoin Core's importdescriptors refuses a descriptor that arrives
// without one, so a computed descriptor with no checksum could be read by a human and
// not imported by the software the human is trying to import it into.
//
// Transcribed from the Python reference in BIP-380 (descsum_expand, descsum_polymod,
// descsum_create), and pinned by the BIP's published vector: raw(deadbeef)#89f8spxm.
// The constants below are the BIP's, not this project's.
public static class DescriptorChecksum
{
    // The input character set, written as the BIP writes it: three groups of 32, in that
    // exact order. The order is load-bearing, not cosmetic. A character's group number
    // feeds the symbol expansion below, and the grouping is what makes a case error cost
    // one symbol error rather than slipping through.
    const string InputCharset =
        "0123456789()[],'/*abcdefgh@:$%{}"
        + "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
        + "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

    const string ChecksumCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    static readonly ulong[] Generator =
        [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd];

    public static Result<string> Append(string descriptor) =>
        Expand(descriptor).Map(symbols =>
        {
            var checksum = Polymod(symbols.Concat(new byte[8]).ToArray()) ^ 1;

            var characters = Enumerable.Range(0, 8)
                .Select(i => ChecksumCharset[(int)((checksum >> (5 * (7 - i))) & 31)]);

            return $"{descriptor}#{string.Concat(characters)}";
        });

    // Character to symbol expansion. Each character contributes its low 5 bits directly;
    // its group number (the high bits) is held back and folded in after every third
    // character. That is what gives the checksum its stated error-detection properties,
    // so the trailing partial group has to be handled exactly as the BIP does it.
    static Result<byte[]> Expand(string descriptor)
    {
        var groups = new List<int>();
        var symbols = new List<byte>();

        foreach (var character in descriptor)
        {
            var value = InputCharset.IndexOf(character);

            // A character outside the set has no symbol value, so there is no checksum
            // to compute. Everything this tool composes is hex, base58, brackets and
            // digits, all inside the set; reaching this is a bug in the composition, and
            // a refusal names it rather than emitting eight characters that mean nothing.
            if (value < 0)
                return Result.Failure<byte[]>(
                    $"the descriptor contains a character BIP-380 does not define a checksum "
                    + $"symbol for (U+{(int)character:X4}), so no checksum can be computed.");

            symbols.Add((byte)(value & 31));
            groups.Add(value >> 5);

            if (groups.Count == 3)
            {
                symbols.Add((byte)(groups[0] * 9 + groups[1] * 3 + groups[2]));
                groups.Clear();
            }
        }

        if (groups.Count == 1)
            symbols.Add((byte)groups[0]);
        else if (groups.Count == 2)
            symbols.Add((byte)(groups[0] * 3 + groups[1]));

        return symbols.ToArray();
    }

    static ulong Polymod(byte[] symbols) =>
        symbols.Aggregate(1UL, (checksum, value) =>
        {
            var top = checksum >> 35;
            var next = ((checksum & 0x7ffffffff) << 5) ^ value;

            return Enumerable.Range(0, 5)
                .Aggregate(next, (acc, i) => ((top >> i) & 1) == 1 ? acc ^ Generator[i] : acc);
        });
}
