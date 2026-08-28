using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;

namespace Slip39Demo.Core.Bip32;

// A BIP-32 extended PRIVATE key: the 32-byte key, its chain code, and the three
// serialisation fields that identify where in the tree it sits.
//
// Private because that is what derivation needs. Hardened derivation (every element of
// a BIP-48 path) cannot be done from a public key at all, which is the whole reason a
// wallet exports an account xpub rather than a master one.
//
// What leaves this class is public: ToXpub, PublicKeyCompressed, Fingerprint. There is
// deliberately no ToXprv. Nothing in this tool needs to print a private key, and a
// backup tool that can print one has a way to leak the wallet that no test will notice.
//
// Chain of operations (BIP-32):
//   master:   I = HMAC-SHA512("Bitcoin seed", seed)   -> key = I[0..32], chain = I[32..64]
//   hardened: I = HMAC-SHA512(chain, 0x00 || key || ser32(i + 2^31))
//   normal:   I = HMAC-SHA512(chain, serP(K) || ser32(i))
//   child key = (I[0..32] + parent key) mod n,  child chain = I[32..64]
//
// secp256k1 point multiplication and RIPEMD160 come from BouncyCastle, which is already
// a first-class dependency of this project (see Slip39Demo.Core.csproj).
public sealed class Bip32ExtendedKey
{
    static readonly Org.BouncyCastle.Asn1.X9.X9ECParameters Secp256k1 =
        SecNamedCurves.GetByName("secp256k1");

    // Version bytes for a mainnet extended PUBLIC key, 0x0488B21E, which is what makes
    // the serialised string start with "xpub". Testnet (tpub) is not offered: the
    // descriptor builder refuses any coin type other than 0h, so a tpub would be a key
    // for a wallet this tool has already declined to describe.
    static readonly byte[] MainnetPublicVersion = [0x04, 0x88, 0xB2, 0x1E];

    readonly byte[] key;
    readonly byte[] chainCode;
    readonly byte depth;
    readonly byte[] parentFingerprint;
    readonly uint childNumber;

    Bip32ExtendedKey(byte[] key, byte[] chainCode, byte depth, byte[] parentFingerprint, uint childNumber)
    {
        this.key = key;
        this.chainCode = chainCode;
        this.depth = depth;
        this.parentFingerprint = parentFingerprint;
        this.childNumber = childNumber;
    }

    // The master key from a BIP-39 seed. "Bitcoin seed" is the HMAC KEY here, not a
    // salt: this step is HMAC-SHA512, not PBKDF2, and confusing the two produces a
    // wallet that looks fine and is wrong.
    public static Bip32ExtendedKey FromSeed(byte[] seed)
    {
        using var hmac = new HMACSHA512(Encoding.UTF8.GetBytes("Bitcoin seed"));
        var i = hmac.ComputeHash(seed);

        return new Bip32ExtendedKey(
            key: i.AsSpan(0, 32).ToArray(),
            chainCode: i.AsSpan(32, 32).ToArray(),
            depth: 0,
            parentFingerprint: [0, 0, 0, 0],
            childNumber: 0);
    }

    public Bip32ExtendedKey Derive(Bip32Path path) =>
        path.Elements.Aggregate(this, (parent, element) => parent.DeriveChild(element));

    // The compressed public key, 33 bytes, which is what goes into a script and into a
    // serialised xpub.
    public byte[] PublicKeyCompressed =>
        Secp256k1.G.Multiply(new BigInteger(1, key)).Normalize().GetEncoded(compressed: true);

    // HASH160 of the public key, first 4 bytes: the identifier a descriptor's key origin
    // starts with, and what wallets display as the fingerprint.
    public Bip32Fingerprint Fingerprint =>
        Bip32Fingerprint.From(Hash160(PublicKeyCompressed).AsSpan(0, 4).ToArray());

    // BIP-32 serialisation of the matching extended PUBLIC key:
    //   4 version | 1 depth | 4 parent fingerprint | 4 child number | 32 chain code | 33 key
    public string ToXpub()
    {
        var childNumberBytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(childNumberBytes, childNumber);

        var serialised = MainnetPublicVersion
            .Append(depth)
            .Concat(parentFingerprint)
            .Concat(childNumberBytes)
            .Concat(chainCode)
            .Concat(PublicKeyCompressed)
            .ToArray();

        return Base58Check.Encode(serialised);
    }

    Bip32ExtendedKey DeriveChild(Bip32PathElement element)
    {
        // A hardened child is derived from the private key, prefixed with 0x00 so the
        // data is 37 bytes either way. A normal child is derived from the public key,
        // which is what lets a watch-only wallet walk the same branch.
        var childNumberBytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(childNumberBytes, element.ChildNumber);

        var data = element.Hardened
            ? new byte[] { 0x00 }.Concat(key).Concat(childNumberBytes).ToArray()
            : PublicKeyCompressed.Concat(childNumberBytes).ToArray();

        using var hmac = new HMACSHA512(chainCode);
        var i = hmac.ComputeHash(data);

        var offset = new BigInteger(1, i.AsSpan(0, 32).ToArray());
        var childKey = offset.Add(new BigInteger(1, key)).Mod(Secp256k1.N);

        // BIP-32: "In case parse256(IL) >= n or ki = 0, the resulting key is invalid, and
        // one should proceed with the next value for i." Implemented because the spec
        // says so, not because it can be reached: it needs an HMAC-SHA512 output at or
        // above the curve order, a probability around 2^-128. No test constructs this
        // case, because constructing it is the same problem as breaking SHA-512.
        if (offset.CompareTo(Secp256k1.N) >= 0 || childKey.SignValue == 0)
            return DeriveChild(element with { Index = element.Index + 1 });

        return new Bip32ExtendedKey(
            key: ToFixed32(childKey),
            chainCode: i.AsSpan(32, 32).ToArray(),
            depth: (byte)(depth + 1),
            parentFingerprint: Fingerprint.Bytes,
            childNumber: element.ChildNumber);
    }

    // A child key at index 0 or 1 on the receive branch, which is all the descriptor
    // work needs: account -> change -> index, both unhardened.
    public Bip32ExtendedKey DeriveUnhardened(uint index) =>
        DeriveChild(new Bip32PathElement(index, Hardened: false));

    // BouncyCastle's BigInteger drops leading zero bytes and can add a sign byte, so a
    // key has to be laid into a fixed 32-byte buffer. Getting this wrong shifts every
    // subsequent byte and produces a different wallet, which is what BIP-32 test
    // vectors 3 and 4 exist to catch.
    static byte[] ToFixed32(BigInteger value)
    {
        var bytes = value.ToByteArrayUnsigned();
        var fixed32 = new byte[32];
        bytes.CopyTo(fixed32, 32 - bytes.Length);
        return fixed32;
    }

    static byte[] Hash160(byte[] data)
    {
        var sha = SHA256.HashData(data);
        var ripe = new RipeMD160Digest();
        ripe.BlockUpdate(sha, 0, sha.Length);
        var output = new byte[20];
        ripe.DoFinal(output, 0);
        return output;
    }
}
