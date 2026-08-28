using System.Security.Cryptography;
using Org.BouncyCastle.Math;

namespace Slip39Demo.Core.Bip32;

// Base58Check encoding, which is how BIP-32 serialises an extended key (xpub).
//
// Encode only. Nothing in this tool reads an xpub back: keys are derived from seed
// words the tool already holds and written outward into a descriptor, so a decoder
// would be code with no caller, and one that has to reject malformed input safely.
//
// The checksum is the first 4 bytes of SHA-256(SHA-256(payload)), appended before
// the base58 conversion, exactly as Bitcoin has always done it.
public static class Base58Check
{
    const string Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    public static string Encode(byte[] payload)
    {
        var checksum = SHA256.HashData(SHA256.HashData(payload)).AsSpan(0, 4);
        var withChecksum = payload.Concat(checksum.ToArray()).ToArray();

        // Big-endian integer conversion. The leading 1 in the BigInteger constructor is
        // the sign, so the bytes are read as a positive number whatever the high bit is.
        var value = new BigInteger(1, withChecksum);
        var fiftyEight = BigInteger.ValueOf(58);
        var digits = new Stack<char>();

        while (value.SignValue > 0)
        {
            var divided = value.DivideAndRemainder(fiftyEight);
            digits.Push(Alphabet[divided[1].IntValue]);
            value = divided[0];
        }

        // Leading zero BYTES carry no value in the integer, so they have to be restored
        // as leading '1' characters. This is the part naive implementations drop, and it
        // is why BIP-32 test vectors 3 and 4 exist.
        var leadingZeros = withChecksum.TakeWhile(b => b == 0).Count();

        return new string('1', leadingZeros) + new string(digits.ToArray());
    }
}
