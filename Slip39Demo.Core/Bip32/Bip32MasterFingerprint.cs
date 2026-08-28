namespace Slip39Demo.Core.Bip32;

// Derives the BIP-32 master fingerprint from BIP-39 seed words + optional
// passphrase. The fingerprint is 4 bytes of HASH160 of the compressed master
// public key — non-secret, identifies which wallet was reconstructed.
//
// Used by the verification record so a dry-run recovery can confirm the right
// wallet was rebuilt without ever showing seed words on screen.
//
// What a fingerprint CANNOT do, which is why the record also carries a first receive
// address for multisig wallets: it is taken at the master key, so it is identical no
// matter what is derived below. Two wallets on different derivation paths, different
// script types or different key orderings share a fingerprint and share no addresses.
// See MultisigWallet.
//
// Chain of operations (BIP-32):
//   1. bip39_seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048, 64B)
//   2. I = HMAC-SHA512("Bitcoin seed", bip39_seed)  -> (priv, chain_code)
//   3. pubkey_compressed = secp256k1 * priv          (33 bytes)
//   4. fingerprint = HASH160(pubkey_compressed)[0..4]
//
// Steps 2 to 4 live in Bip32ExtendedKey, which is also what the descriptor work derives
// with; this class is the name the verification record calls it by. Keeping one
// implementation of the root HMAC matters more than the two lines it saves: the BIP-32
// test vectors run against that one, so they cover this too.
public static class Bip32MasterFingerprint
{
    public static Bip32Fingerprint Compute(string seedWords, string? passphrase) =>
        Bip32ExtendedKey.FromSeed(Bip39Seed.Derive(seedWords, passphrase)).Fingerprint;
}
