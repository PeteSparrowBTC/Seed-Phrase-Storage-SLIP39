using CSharpFunctionalExtensions;

namespace Slip39Demo.Core.Wallet;

// Bech32 encoding of a witness version 0 address, per BIP-173.
//
// Version 0 only, which is P2WPKH (20-byte program) and P2WSH (32-byte program). Later
// witness versions use bech32m (BIP-350) with a different checksum constant, and taproot
// is not something this tool describes: BIP-48 has no script type for it. So rather than
// take a version argument and quietly compute a bech32 checksum for a v1 program, which
// would produce a string that looks like an address and is not one, this encoder does
// v0 and says so in its name.
//
// The hrp is a parameter rather than a constant so the published BIP-173 vectors can be
// run: the BIP's only 32-byte-program vector is a testnet one. Production callers pass
// "bc", because the descriptor builder refuses any coin type other than 0h.
public static class Bech32Address
{
    const string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    // BIP-173's generator, used by the checksum polynomial.
    static readonly uint[] Generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    public static Result<string> EncodeSegwitV0(string hrp, byte[] witnessProgram)
    {
        // BIP-141 fixes these two lengths for version 0, and a program of any other
        // length is not a v0 output at all. Refusing beats encoding: an address computed
        // from a mis-sized program would be checked against a wallet, not match, and
        // send the owner looking for the fault in their wallet rather than here.
        if (witnessProgram.Length is not (20 or 32))
            return Result.Failure<string>(
                $"a witness version 0 program is 20 bytes (P2WPKH) or 32 bytes (P2WSH); "
                + $"this one is {witnessProgram.Length}.");

        // The data part is the witness version, then the program regrouped from 8-bit
        // bytes into 5-bit symbols.
        var data = ConvertBits(witnessProgram).Prepend((byte)0).ToArray();
        var checksum = Checksum(hrp, data);

        return hrp + "1" + string.Concat(data.Concat(checksum).Select(symbol => Charset[symbol]));
    }

    // 8-bit bytes to 5-bit groups, zero-padded at the end. Both v0 lengths divide into
    // whole numbers of quantums only after padding (20 bytes is 32 symbols, 32 bytes is
    // 52), which is why pad is unconditional here rather than a parameter.
    static byte[] ConvertBits(byte[] bytes)
    {
        var symbols = new List<byte>();
        var accumulator = 0;
        var bits = 0;

        foreach (var b in bytes)
        {
            accumulator = (accumulator << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                symbols.Add((byte)((accumulator >> bits) & 31));
            }
        }

        if (bits > 0)
            symbols.Add((byte)((accumulator << (5 - bits)) & 31));

        return symbols.ToArray();
    }

    // The 6 checksum symbols: polymod over the expanded hrp, the data, and six zeros,
    // xored with 1.
    static byte[] Checksum(string hrp, byte[] data)
    {
        var values = ExpandHrp(hrp).Concat(data).Concat(new byte[6]).ToArray();
        var polymod = Polymod(values) ^ 1;

        return Enumerable.Range(0, 6)
            .Select(i => (byte)((polymod >> (5 * (5 - i))) & 31))
            .ToArray();
    }

    // BIP-173: the high bits of every hrp character, a zero separator, then the low bits.
    static byte[] ExpandHrp(string hrp) =>
        hrp.Select(ch => (byte)(ch >> 5))
            .Append((byte)0)
            .Concat(hrp.Select(ch => (byte)(ch & 31)))
            .ToArray();

    static uint Polymod(byte[] values) =>
        values.Aggregate(1u, (checksum, value) =>
        {
            var top = checksum >> 25;
            var next = ((checksum & 0x1ffffff) << 5) ^ value;

            return Enumerable.Range(0, 5)
                .Aggregate(next, (acc, i) => ((top >> i) & 1) == 1 ? acc ^ Generator[i] : acc);
        });
}
