using System.Security.Cryptography;
using System.Text;
using Slip39Demo.Core.Bip32;
using Slip39Demo.Core.Wallet;

namespace Slip39Demo.Core.Verification;

// Builds the non-secret slip39-backup verification record. Stored alongside
// payload.age and consumed by the dry-run recovery flow (spec §6.5) so the
// owner can periodically confirm their backup chain still works without
// ever displaying the seed words on screen.
//
// Contents are all one-way derivations — knowing them gives an attacker zero
// information that helps reconstruct the wallet:
//   - Wallet master fingerprint: HASH160 of the master public key, 4 bytes.
//   - Per-share fingerprints: truncated SHA-256 of each mnemonic.
//   - Payload integrity: full SHA-256 of payload.age bytes.
//   - For a multisig wallet whose descriptor this tool computed, the first
//     receive address.
//
// WHY THE ADDRESS IS HERE AND THE DESCRIPTOR IS NOT. The fingerprint above is taken at
// the master key, so it is the same whatever is derived below it: it cannot catch a wrong
// derivation path, script type, key ordering or threshold. The first receive address
// catches all four, and an owner can compare it against any wallet software without
// understanding what an xpub is. The descriptor itself stays in the encrypted payload,
// because it carries account xpubs, and this file is one the record itself tells the
// owner to print and to keep in a password manager. An xpub there would expose every
// address the wallet will ever use, and their balances, permanently.
public static class VerificationRecord
{
    public static string Build(
        string createdDate,
        string toolVersion,
        string label,
        IReadOnlyList<string> mnemonicsInOrder,
        byte[] payloadAgeBytes,
        Bip32Fingerprint walletMasterFingerprint,
        // Defaulted so the two call sites that describe a backup with no descriptor (and
        // the tests that predate this section) read unchanged.
        DescriptorProvenance descriptorProvenance = DescriptorProvenance.NotRecorded,
        string? firstReceiveAddress = null)
    {
        // Number of shares is needed both for the "share-i-of-N" labels and
        // for sizing the per-share list — captured once for clarity.
        var n = mnemonicsInOrder.Count;

        // Per-share fingerprint lines, rendered functionally via Select+Join.
        // Each line: "   share-{i}-of-{n}:  {8-hex-fingerprint}"
        var shareLines = string.Join(Environment.NewLine,
            mnemonicsInOrder.Select((m, i) => $"   share-{i + 1}-of-{n}:  {ShareFingerprint.Compute(m)}"));

        // Full SHA-256 of the payload.age ciphertext bytes — gives the owner
        // a way to confirm the ciphertext on disk hasn't been silently
        // corrupted (bitrot, bad USB, etc.) without needing to decrypt.
        var payloadHash = Convert.ToHexString(SHA256.HashData(payloadAgeBytes)).ToLowerInvariant();

        var sb = new StringBuilder();
        sb.AppendLine("slip39-backup Verification Record");
        sb.AppendLine("================================================================");
        sb.AppendLine($"Created:       {createdDate}");
        sb.AppendLine($"Tool version:  {toolVersion}");
        sb.AppendLine($"Label:         {label}");
        sb.AppendLine();
        // Bip32Fingerprint.ToString() returns 8 lowercase hex chars — exactly
        // the canonical display form used by Sparrow/Electrum/etc.
        sb.AppendLine($"Wallet master fingerprint (BIP-32):  {walletMasterFingerprint}");
        sb.AppendLine("   This is the fingerprint of the recovered wallet's master");
        sb.AppendLine("   public key — derivable from the seed but reveals NO secret");
        sb.AppendLine("   data. Knowing it does not help an attacker.");
        sb.AppendLine();
        // The descriptor section, present only when there is a descriptor to describe.
        // A single-signature backup keeps the record's older shape rather than gaining a
        // section that says "none".
        if (descriptorProvenance is DescriptorProvenance.Computed)
        {
            sb.AppendLine("Wallet descriptor:  computed by this tool from the cosigner seeds");
            sb.AppendLine("   The descriptor itself is inside the encrypted payload, not here: it");
            sb.AppendLine("   carries each cosigner's extended public key, and one of those would");
            sb.AppendLine("   reveal every address this wallet will ever use.");
            sb.AppendLine();

            // Only the computed case has an address, because nothing here parses a
            // descriptor somebody else wrote.
            if (firstReceiveAddress is not null)
            {
                sb.AppendLine("First receive address:");
                sb.AppendLine($"   {firstReceiveAddress}");
                sb.AppendLine("   Rebuild the wallet from the recovered seeds in any wallet software");
                sb.AppendLine("   and compare its first receive address with this one. The master");
                sb.AppendLine("   fingerprint above cannot catch a wrong derivation path, script type,");
                sb.AppendLine("   key ordering or threshold. This can: change any of them and this");
                sb.AppendLine("   address changes completely.");
                sb.AppendLine();
            }
        }
        else if (descriptorProvenance is DescriptorProvenance.Pasted)
        {
            sb.AppendLine("Wallet descriptor:  entered by you, stored as given");
            sb.AppendLine("   This tool did not derive it, so it computed no address from it and");
            sb.AppendLine("   nothing here has checked that it matches the seeds in this backup.");
            sb.AppendLine();
        }

        sb.AppendLine("Per-share fingerprints (SHA256 of mnemonic words, truncated):");
        sb.AppendLine(shareLines);
        sb.AppendLine();
        sb.AppendLine("Payload integrity (SHA256 of payload.age):");
        sb.AppendLine($"   {payloadHash}");
        sb.AppendLine();
        sb.AppendLine("────────────────────────────────────────────────────────────────");
        sb.AppendLine("This record is non-secret. Store it where you can find it for");
        sb.AppendLine("dry-run verification. Suggested locations:");
        sb.AppendLine("  - Printed copy in your home safe");
        sb.AppendLine("  - Plain-text note inside the dedicated PM entry");
        sb.AppendLine("  - Separate text file on your encrypted USB");
        sb.AppendLine("DO NOT distribute to share-holders.");
        return sb.ToString();
    }
}
