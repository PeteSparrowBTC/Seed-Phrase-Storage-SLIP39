using System.Security.Cryptography;
using CSharpFunctionalExtensions;
using Slip39Demo.Core.Bip32;
using Slip39Demo.Core.Bip39;

namespace Slip39Demo.Core.Wallet;

// One cosigner of the wallet being described: the seed words that cosigner signs with
// (its own, or the shared top-level ones), its optional BIP-39 passphrase, and the
// account path its wallet derives from. Id is the label the owner gave it, used only to
// name the cosigner in a refusal.
public sealed record MultisigCosigner(string Id, string SeedWords, string? Passphrase, string DerivationPath);

// What Describe produces: the descriptor, checksummed and ready to import, and the first
// receive address.
//
// No xpubs. Deliberately: the descriptor goes into the encrypted payload, and the address
// is the only part that may appear in verification-record.txt, which the record itself
// tells the owner to print and to keep in a password manager. An xpub there would reveal
// every address the wallet will ever use, and their balances, permanently.
public sealed record ComputedWallet(string Descriptor, string FirstReceiveAddress);

// Deriving the wallet's descriptor and first receive address from the cosigner seeds the
// tool is already holding.
//
// WHY THE TOOL DOES THIS AT ALL. Owner mode used to ask the owner to paste a descriptor.
// That meant either a third program in an offline session or a hand-typed string, and it
// left the payload's most operationally important non-secret field to transcription. The
// tool already holds every cosigner seed and passphrase at once, which nothing else in
// the room does, so it can compute the descriptor without anything else learning a seed.
// This reverses the design spec's section 10.2 ("Not implemented in this tool"); the
// decision record carries the argument.
//
// WHY THE FIRST ADDRESS AND NOT AN XPUB. The verification record already carries the
// master fingerprint, and a master fingerprint cannot catch a wrong derivation path: it
// is HASH160 of the master public key and is identical no matter what is derived
// afterwards. Walk 1h instead of 2h and the fingerprint still matches while every
// address differs. An account xpub catches the path but not the script type, the key
// ordering or the threshold. The first receive address catches all of it, in one string
// the owner can compare against any wallet software without understanding xpubs.
//
// MULTISIG ONLY, 2-of-2 or better. A single cosigner is refused rather than described as
// wpkh(...), and so is a 1-of-N policy, where one share-holder spends alone and the
// threshold split protects nothing.
//
// FAILS CLOSED. Every path this cannot describe exactly is a refusal naming the reason,
// never a best guess: a descriptor or address that is subtly wrong is worse than none,
// because the owner checks it, sees a mismatch, and goes looking for the fault in their
// wallet. The owner can still paste a descriptor, which overrides this entirely.
public static class MultisigWallet
{
    // BIP-48: purpose 48h, then coin type, account, script type, all hardened.
    const uint Bip48Purpose = 48;
    const uint BitcoinMainnet = 0;
    const uint NativeSegwitScriptType = 2;
    const int Bip48PathElements = 4;

    // OP_1 through OP_16 encode the two numbers in a witness script. Above 16 the script
    // needs a pushed number, which no backup form is going to reach: it would be a
    // 17-cosigner wallet.
    const int MaxCosigners = 16;

    public static Result<ComputedWallet> Describe(
        IReadOnlyList<MultisigCosigner> cosigners, int signaturesRequired)
    {
        if (cosigners.Count < 2)
            return Result.Failure<ComputedWallet>(
                "a descriptor is computed for multisig wallets only, which needs at least two "
                + "cosigners with seed words. Paste a descriptor instead if this wallet is not "
                + "one of those.");

        if (cosigners.Count > MaxCosigners)
            return Result.Failure<ComputedWallet>(
                $"this builds descriptors for up to {MaxCosigners} cosigners; this wallet has "
                + $"{cosigners.Count}.");

        if (signaturesRequired < 2)
            return Result.Failure<ComputedWallet>(
                "a computed descriptor requires at least 2 signatures. A 1-of-N wallet lets any "
                + "single cosigner spend alone, which is what splitting the key into shares "
                + "exists to prevent.");

        if (signaturesRequired > cosigners.Count)
            return Result.Failure<ComputedWallet>(
                $"the wallet cannot require {signaturesRequired} signatures when it has "
                + $"{cosigners.Count} cosigners.");

        var wordList = Bip39WordList.Load();

        // Same reasoning as BackupKeyEntry: without the list nothing can be checked, and
        // a descriptor that was not checked must not be handed out.
        if (wordList.IsFailure)
            return Result.Failure<ComputedWallet>(
                $"the BIP-39 wordlist in this build is unusable, so no seed can be read. {wordList.Error}");

        var keys = cosigners
            .Select(cosigner => KeyOf(cosigner, wordList.Value))
            .ToList();

        // The first cosigner that cannot be derived stops the whole descriptor: a
        // wsh(sortedmulti(...)) missing one of its keys is a different wallet.
        if (keys.Any(key => key.IsFailure))
            return Result.Failure<ComputedWallet>(keys.First(key => key.IsFailure).Error);

        var resolved = keys.Select(key => key.Value).ToList();

        return Descriptor(resolved, signaturesRequired)
            .Bind(descriptor => FirstReceiveAddress(resolved, signaturesRequired)
                .Map(address => new ComputedWallet(descriptor, address)));
    }

    // One cosigner's account key: the fingerprint the descriptor's key origin starts
    // with, the path, the account xpub, and the public key at the first receive index.
    sealed record CosignerKey(
        string CosignerId, Bip32Fingerprint MasterFingerprint, Bip32Path Path, string AccountXpub, byte[] FirstReceiveKey);

    static Result<CosignerKey> KeyOf(MultisigCosigner cosigner, Bip39WordList wordList)
    {
        var named = $"cosigner \"{cosigner.Id}\": ";

        // Seed words that are not valid BIP-39 cannot be restored by any wallet, so an
        // address derived from them would describe a wallet that does not exist. The
        // message never repeats the words back: it lands in an on-screen banner.
        var entropy = Bip39Mnemonic.ToEntropy(cosigner.SeedWords, wordList);
        if (entropy.IsFailure)
            return Result.Failure<CosignerKey>(
                named + $"the seed words do not read as BIP-39, so no key can be derived from "
                + $"them. {entropy.Error}");

        var path = Bip32Path.Parse(cosigner.DerivationPath);
        if (path.IsFailure)
            return Result.Failure<CosignerKey>(named + path.Error);

        var bip48 = RequireBip48(path.Value);
        if (bip48.IsFailure)
            return Result.Failure<CosignerKey>(named + bip48.Error);

        // The words are re-joined from Split so the derivation runs on the same
        // normalisation the entropy check just passed, rather than on whatever spacing
        // the field held.
        var mnemonic = string.Join(' ', Bip39Mnemonic.Split(cosigner.SeedWords));
        var master = Bip32ExtendedKey.FromSeed(Bip39Seed.Derive(mnemonic, cosigner.Passphrase));
        var account = master.Derive(path.Value);

        return new CosignerKey(
            CosignerId: cosigner.Id,
            MasterFingerprint: master.Fingerprint,
            Path: path.Value,
            AccountXpub: account.ToXpub(),
            // Receive branch 0, first index 0: the address a wallet shows first.
            FirstReceiveKey: account.DeriveUnhardened(0).DeriveUnhardened(0).PublicKeyCompressed);
    }

    // BIP-48 is what multisig wallets have settled on, and each element carries meaning
    // that cannot be inferred from anything else in the form. A path this does not
    // recognise is refused by name rather than derived from anyway.
    static Result RequireBip48(Bip32Path path)
    {
        if (path.Elements.Count != Bip48PathElements)
            return Result.Failure(
                $"the derivation path {path} does not have the four elements of a BIP-48 multisig "
                + "path, m/48h/0h/<account>h/2h.");

        if (path.Elements.Any(element => !element.Hardened))
            return Result.Failure(
                $"the derivation path {path} has an unhardened element. BIP-48 specifies every "
                + "element hardened, and an unhardened one is a different key.");

        if (path.Elements[0].Index != Bip48Purpose)
            return Result.Failure(
                $"the derivation path {path} is not a multisig path: multisig has its own purpose "
                + $"field, so the first element must be 48h. A path starting "
                + $"{path.Elements[0].Index}h describes a single-signature wallet, and this tool "
                + "computes descriptors for multisig only.");

        if (path.Elements[1].Index != BitcoinMainnet)
            return Result.Failure(
                $"the derivation path {path} is not on Bitcoin mainnet (coin type 0h). Only "
                + "mainnet is described here, because an xpub and a bc1 address for another "
                + "chain would name the wrong wallet.");

        if (path.Elements[3].Index != NativeSegwitScriptType)
            return Result.Failure(
                $"the derivation path {path} asks for BIP-48 script type "
                + $"{path.Elements[3].Index}h. Only 2h, native segwit, is described here: "
                + "P2SH-wrapped multisig needs a different script and a different address form, "
                + "and computing a bech32 address for it would produce a string that is not this "
                + "wallet's address.");

        return Result.Success();
    }

    // wsh(sortedmulti(k,KEY,...)) with the BIP-380 checksum.
    //
    // sortedmulti rather than multi so the wallet sorts the keys itself, which is what
    // makes the descriptor independent of the order the cosigners were entered in. The
    // key expressions are also emitted in a stable order, so the descriptor STRING does
    // not change either; a wallet would accept any order, but a record the owner compares
    // by eye should not shuffle between runs.
    static Result<string> Descriptor(IReadOnlyList<CosignerKey> keys, int signaturesRequired)
    {
        var expressions = keys
            .Select(key => $"[{key.MasterFingerprint}/{key.Path.DescriptorForm}]{key.AccountXpub}/0/*")
            .OrderBy(expression => expression, StringComparer.Ordinal);

        return DescriptorChecksum.Append(
            $"wsh(sortedmulti({signaturesRequired},{string.Join(',', expressions)}))");
    }

    // The address at receive index 0.
    //
    // BIP-67 is the part worth reading twice: sortedmulti orders the DERIVED public keys
    // lexicographically, not the xpubs and not the input. So the witness script has to be
    // built from the sorted 33-byte keys, or the address will not be the one the wallet
    // shows.
    static Result<string> FirstReceiveAddress(IReadOnlyList<CosignerKey> keys, int signaturesRequired)
    {
        var sorted = keys
            .Select(key => key.FirstReceiveKey)
            .Order(LexicographicBytes.Comparer)
            .ToList();

        // OP_k <33-byte key> ... <33-byte key> OP_m OP_CHECKMULTISIG
        var witnessScript = sorted
            .SelectMany(key => key.Prepend((byte)key.Length))
            .Prepend(OpN(signaturesRequired))
            .Append(OpN(keys.Count))
            .Append(OpCheckMultisig)
            .ToArray();

        // P2WSH: the witness program is SHA-256 of the witness script, not HASH160.
        return Bech32Address.EncodeSegwitV0("bc", SHA256.HashData(witnessScript));
    }

    const byte OpCheckMultisig = 0xae;

    // OP_1 is 0x51, and OP_2 through OP_16 follow it.
    static byte OpN(int n) => (byte)(0x50 + n);

    // Byte-string ordering, which is what BIP-67 means by lexicographic.
    static class LexicographicBytes
    {
        public static IComparer<byte[]> Comparer { get; } = Comparer<byte[]>.Create(
            (left, right) => left.AsSpan().SequenceCompareTo(right.AsSpan()));
    }
}
