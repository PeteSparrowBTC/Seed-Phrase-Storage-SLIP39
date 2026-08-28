# SLIP-39 + age Wallet Backup Tool

## 🔴 LIVE DEMO - DO NOT USE FOR REAL WALLETS 🔴

**Demo URL:** https://petesparrowbtc.github.io/slip39-backup

### ⚠️ CRITICAL: THIS ONLINE VERSION IS FOR DEMONSTRATION ONLY ⚠️

**DO NOT ATTEMPT ACTUAL WALLET BACKUPS FROM THIS GITHUB PAGES VERSION!**

**Why?**
- You should never enter real seed phrases in any online service
- Even though all crypto runs client-side, use offline for real wallets
- This demo is for learning and testing the flow only

**For actual wallet backup, you MUST:**
1. **Download** the latest release: [Releases](https://github.com/PeteSparrowBTC/slip39-backup/releases)
2. **Copy** the AppImage (and its `.sha256`) to a USB drive
3. **Run offline** on Tails Linux (see [TAILS_INSTRUCTIONS.md](TAILS_INSTRUCTIONS.md)); it opens a native window, no server involved
4. **No internet connection** - completely air-gapped

---

## About This Tool

A secure, offline-capable web application for backing up BIP-39 cryptocurrency wallet seed phrases. Phase 2 of this project replaces the legacy proprietary "seed + passphrase" encoding with a clean two-layer design:

1. **SLIP-39 splits a random 32-byte key `k`** into threshold shares.
2. **The wallet payload (seed words, optional BIP-39 passphrase, cosigner data, descriptor, notes) is encrypted with [age](https://age-encryption.org/) using `k`** as the recipient passphrase.

The output is a single zip, named after the wallet and the date
(`slip39-wallet-backup-<label>-<date>.zip`), that you save to a USB drive. Recovery only requires threshold-many share zips plus the encrypted `payload.age.gpg.asc` blob.

**Built with:** [Xecrets.Slip39](https://github.com/xecrets/xecrets-slip39) (SLIP-39 secret-sharing) and an in-tree age-passphrase implementation.

**New to all of this?** Start with the [complete backup framework](https://github.com/PeteSparrowBTC/bitcoin-backup-framework): a from-zero strategy for securing your seed, passphrase, password manager, and heir access, with this tool as the worked example.

## What is This?

This tool implements two roles that map directly to two routes in the app:

- **Owner mode** (`/owner`): you have the wallet seed and want to create a distributable backup.
- **Recoverer mode** (`/recoverer`): you (or your executor) have the shares and the encrypted payload and want to recover the wallet.

Landing page (`/`) lets you pick between the two.

## Why Use SLIP-39 + age?

Traditional BIP-39 seed phrases have a problem: if someone finds your 12/24 words, they have complete access to your wallet. The SLIP-39 + age design here gives you:

- **Threshold secret sharing**: split your wallet into multiple shares; only threshold-many can recover it.
- **Standard cryptography end-to-end**: SLIP-39 for the share split, age and OpenPGP for the payload encryption. No proprietary "concatenate seed and passphrase with padding" encoding.
- **One file to distribute, one file to keep online**: the backup zip is laid out so share zips go to physical/offline storage and `payload.age.gpg.asc` goes to a password-manager entry with Emergency Access for your executor.
- **Verifiable on recovery without exposing the seed**: a `verification-record.txt` lets you do periodic dry-run recovery checks against a stored fingerprint, plus the wallet's first receive address for a multisig backup. The address is what catches a wrong derivation path, script type, cosigner ordering or signature count; a master fingerprint cannot, because it is the same whatever is derived below it. The descriptor's xpubs stay inside the encrypted payload, since the record is a file you are meant to print.

## How this compares to other tools

Other projects solve a similar problem, and it is worth knowing what they do
before choosing any of them, including this one. The table below lists only
things that can be checked from each project's own repository, as of August 2026.
Follow the links and confirm rather than taking this page's word for it.

| | This tool | [Superbacked](https://github.com/superbacked/superbacked) | [Hyperbacked](https://github.com/Twometer/hyperbacked) |
| --- | --- | --- | --- |
| Licence | MIT | Custom end-user agreement | MIT |
| Built with | .NET, runs as an AppImage on Tails | Electron, desktop | Rust |
| Splitting scheme | SLIP-39 | Shamir's Secret Sharing | Shamir's Secret Sharing |
| Shares look like | 33 words per share | Encrypted QR code | Encrypted QR code in a PDF |

On licences, the difference is worth reading rather than summarising. Superbacked
publishes its source code, which is more than most paid software does, and its
licence states that building or using it is "allowed for personal use only" and
that "unauthorized distribution or usage of this software (including its source
code) is strictly prohibited". You can read it and build it; you cannot fork it
or ship it. This tool and Hyperbacked are both MIT, which permits all of that.

**What differs here.** Two things must come together to recover a wallet made
with this tool: threshold-many shares, and the separate encrypted `payload.age.gpg.asc`
file. Shares alone reveal nothing, and the encrypted file alone reveals nothing.
That is a deliberate trade. It resists a group of share-holders combining against
you, and it costs you a second item that has to survive.

The shares being words rather than a QR code is also a trade. Words can be copied
by hand, checked by eye, and stamped into metal, and they carry a checksum that
catches transcription mistakes. A QR code is more compact and faster to read
back, and it needs a working scanner at recovery time, possibly decades from now.

**Where other tools are ahead.** Superbacked offers plausible deniability: a
second passphrase that opens a decoy secret, so a person under duress can hand
over something that works. This tool has nothing equivalent, and that is a real
gap if coercion is a concern you have. It is tracked in
[issue #7](https://github.com/PeteSparrowBTC/slip39-backup/issues/7) rather than
quietly omitted.

None of these tools, this one included, publishes reproducible builds, which
means you cannot independently confirm that a released binary was built from the
source you can read. That limitation applies here too.

Other projects exist in this space, including seQRets. They are not covered here
because they have not been examined closely enough to describe fairly.

## How the New Design Works

### Two-layer encryption

```
   Wallet payload (seed words, passphrase, cosigners, descriptor, notes)
                              │
                              │  1. age encrypt, passphrase = k
                              ▼
                     payload.age  (inner file, never shipped)
                              │
                              │  2. OpenPGP AES-256 encrypt, same passphrase k
                              ▼
                    payload.age.gpg.asc  (the one file that ships)
                              ▲
                              │  k is the only thing SLIP-39 protects
                              │
   Random 32-byte key k ──► SLIP-39 split ──► share-1.zip … share-N.zip
```

Both locks take the same `k`, so recovery is `gpg -d` and then `age -d` with one
key typed twice rather than a derivation an heir cannot perform by hand. What that
hedges, and what it does not, is set out in the decision record.

No part of the wallet seed leaves the encrypted payload. SLIP-39 only protects `k`. There is **no** SLIP-39 passphrase to remember. The security boundary is the threshold of share zips plus possession of the `payload.age.gpg.asc` file.

### Groups and thresholds

**Shares**: Individual SLIP-39 mnemonics (20-33 words).
**Groups**: Optional grouping of shares with their own thresholds (e.g. "Personal", "Family", "Friends").
**Group threshold**: How many groups are required to recover.

Default setup: **single group, 3-of-5**. You can change the threshold/count or add additional groups in the Owner UI.

## Features

### The app itself

- **Two routes**: `/owner` for creating a backup, `/recoverer` for recovering one. `/` is the chooser.
- **Single download**: Owner mode emits one zip (share zips + `payload.age.gpg.asc` + verification record + read-me).
- **Drop-zone recovery**: Recoverer mode accepts share `.zip` files dropped directly, or pasted mnemonics one-per-line.
- **Dark theme**: Easy on the eyes for extended use.
- **100% client-side**: All crypto runs in WebAssembly, in a browser tab (demo) or the AppImage's own window. No network calls.

### Security

✅ **No server processing**: The same Blazor WebAssembly runs in a browser tab for the demo, or in the AppImage's own native window with no server and no port bound
✅ **No data transmission**: Verifiable in browser DevTools (Network tab) for the demo
✅ **Offline capable**: Works completely offline on Tails Linux
✅ **Standard primitives**: SLIP-39 for sharing, age and OpenPGP for encryption, no custom encoding
✅ **Tails-optimized**: RAM-only operation, everything wiped on shutdown

## Usage

### ⚠️ IMPORTANT SECURITY WARNING ⚠️

**DO NOT ENTER YOUR REAL SEED PHRASE ON THE ONLINE DEMO!**

The GitHub Pages version is for **DEMONSTRATION AND TESTING ONLY**.

**For real wallet backups:**
- Download the AppImage (Option 2 below)
- Run it offline on Tails Linux: it opens its own window, no server and no browser involved
- Or build from source and run locally

### Option 1: Online Demo (GitHub Pages) - FOR TESTING ONLY

**Demo app:** https://petesparrowbtc.github.io/slip39-backup

**⚠️ WARNING: DO NOT USE WITH REAL SEED PHRASES!**

This is a demonstration version. While all crypto runs client-side:
- ❌ **DO NOT** enter your actual wallet seed phrase
- ❌ **DO NOT** use this for real wallet backups
- ✅ **DO** use it to understand how the flow works
- ✅ **DO** test with dummy/test seed phrases only

**For real use, download and run offline on Tails (Option 2).**

### Option 2: Offline on Tails Linux (Recommended)

One file, one window: no browser, no server, no Tor configuration.

**Download from GitHub Releases:**
1. Go to [Releases](https://github.com/PeteSparrowBTC/slip39-backup/releases)
2. Download the AppImage and its `.sha256`. The filename carries the version, for
   example `slip39-backup-2.0.0-x86_64.AppImage`, and the app shows the same number in
   its footer
3. Copy both to a USB drive

**On Tails 7 or later** (older Tails is EOL and unsupported):
```bash
# 1. Verify and run. A native window opens directly.
sha256sum -c slip39-backup-2.0.0-x86_64.AppImage.sha256
chmod +x slip39-backup-2.0.0-x86_64.AppImage
./slip39-backup-2.0.0-x86_64.AppImage
```

See [TAILS_INSTRUCTIONS.md](TAILS_INSTRUCTIONS.md) for the complete guide.

### Option 3: Build from Source

**Requirements (Linux, matching CI's `ubuntu-latest`):**
- .NET 10 SDK
- A stable Rust toolchain (`cargo`)
- Git
- `libwebkit2gtk-4.1-dev libsoup-3.0-dev libssl-dev librsvg2-dev patchelf build-essential file`
  (the exact list `.github/workflows/appimage.yml` installs before building the shell)

The Rust shell (`src-tauri/`) embeds Tails's own WebKitGTK at build time, so
`cargo build` for this target has to run on Linux; it will not link on Windows or
macOS. A Windows machine can still compile `src-tauri` for its own host triple to
develop and run `cargo test` (see `src-tauri/icons/README.md` for why that needs
`icon.ico`), but the AppImage itself has to be built on Linux, WSL included.

**Build the Tails AppImage** (same commands `.github/workflows/appimage.yml` runs):
```bash
git clone https://github.com/PeteSparrowBTC/slip39-backup.git
cd slip39-backup
dotnet publish Slip39Demo.Tauri -c Release -o publish-tauri
cargo build --release --manifest-path src-tauri/Cargo.toml
bash packaging/appimage/build-appimage.sh src-tauri/target/release/slip39-backup slip39-backup-2.0.0-x86_64.AppImage
```

## How It Works

### Creating a backup (Owner mode)

1. Start on `/` (the page the app opens on, whether that is a browser tab on the
   demo or the AppImage's own window). Click **Start backup** (or go straight to
   `/owner`).
2. In the Owner page:
   - Enter your BIP-39 seed words in the **Top-level seed words** field (single-sig / shared-seed case). For multisig with distinct per-cosigner seeds, leave this empty and fill the per-cosigner seed fields instead.
   - (Optional) Set a label for the wallet.
   - (Optional) Add a BIP-39 passphrase to a cosigner.
   - (Optional) Adjust derivation path, group threshold, or group shape. Default is 3-of-5 single-group.
   - For multisig (two or more cosigners), set how many **signatures** the wallet requires and leave the **descriptor** field empty: the tool derives `wsh(sortedmulti(k,...))` from the cosigner seeds at their BIP-48 paths, and puts the wallet's first receive address in `verification-record.txt` so you can check the backup describes the right wallet. Paste a descriptor instead to record a wallet that already exists on a path this tool does not compute.
3. Click **Generate**.
4. Save the resulting zip (a browser download on the demo, the native save
   dialog on the AppImage). It contains:
   - `shares/share-1-of-5.zip` ... `share-5-of-5.zip`: distribute to your storage locations (paper, metal, or trusted holders).
   - `payload/payload.age.gpg.asc`: the one ciphertext file. The age-encrypted payload wrapped a second time in OpenPGP AES-256 and ASCII armored, so it is plain text you can paste into a password-manager entry with Emergency Access for your executor, or print. Both locks open with the same key, which your shares rebuild.
   - `payload/VERIFY-THIS-BACKUP.txt` and `payload/IMPORTANT-READ-FIRST.txt`: owner-only notes about how to use and verify what's in the zip.
   - `verification-record.txt` and `MANUAL-RECOVERY.txt`: keep alongside the payload for periodic dry-run verification and tool-independent recovery.

The backup zip itself is **not** something you store long-term: it's a one-shot distribution package. Split its contents to their respective homes immediately, then delete the zip.

### Recovering a wallet (Recoverer mode)

1. Start on `/`, then click **Start recovery** (or go straight to `/recoverer`).
2. In the Recoverer page:
   - Drop threshold-many share `.zip` files into the mnemonics file picker (or paste the mnemonics one per line).
   - Drop `payload.age.gpg.asc` into the ciphertext picker, or paste its text. Both locks come off in-process, so nothing external is required. Files from older backups (`payload.age`, `payload.age.txt`) are still accepted.
3. Click **Recover**. The recovered wallet payload appears with a reveal-on-click for the seed words.

The recoverer never needs a SLIP-39 passphrase or any out-of-band secret: threshold-many shares plus `payload.age.gpg.asc` is sufficient.

## Technical Details

### File layout in the backup zip

```
slip39-wallet-backup-main-wallet-2026-08-13.zip
├── shares/
│   ├── share-1-of-5.zip   (or {group}-share-1-of-N.zip when multi-group)
│   ├── share-2-of-5.zip
│   ├── …
│   └── share-5-of-5.zip
├── payload/
│   ├── payload.age.gpg.asc          (the only ciphertext: age inside OpenPGP, armored)
│   ├── IMPORTANT-READ-FIRST.txt
│   └── VERIFY-THIS-BACKUP.txt
├── verification-record.txt
└── MANUAL-RECOVERY.txt
```

`payload.age.gpg.asc` is the one file needed to recover, alongside
threshold-many shares. It has two locks, age on the inside and OpenPGP AES-256
outside it, and the key your shares rebuild opens both. Earlier versions shipped
the unwrapped age file beside it, which handed anyone who obtained the folder the
weaker of the two files and so cancelled the reason for wrapping at all. See
[the design decision record](docs/decisions/2026-08-09-envelope-entropy-and-implementations.md)
for that reversal and its limits.

Each individual `share-K-of-N.zip` contains the SLIP-39 mnemonic for that share plus a per-share README explaining what it is and how it's used.

### Dependencies

- [Xecrets.Slip39](https://www.nuget.org/packages/Xecrets.Slip39/) - SLIP-39 implementation
- In-tree age-passphrase encryption (scrypt + ChaCha20-Poly1305), see `Slip39Demo.Core/Age/`
- Blazor WebAssembly (.NET 8)

## Development

### Project Structure

```
slip39-backup/
├── Slip39Demo.Core/             # Pure C# core: SLIP-39, age, payload, bundle
├── Slip39Demo.UI/               # Shared Blazor UI (pages, components, assets)
│   └── Pages/
│       ├── Index.razor          # Owner / Recoverer chooser
│       ├── Owner.razor          # /owner, backup creation
│       └── Recoverer.razor      # /recoverer, wallet recovery
├── Slip39Demo.Web/              # WASM shell, hosted online demo only
├── Slip39Demo.Tauri/            # Blazor WASM frontend the Tauri shell embeds
├── src-tauri/                   # Rust shell: window, save dialog, age subprocess
├── Slip39Demo.Tests/            # xUnit tests
├── packaging/appimage/          # AppRun, .desktop, build-appimage.sh
├── .github/workflows/
│   ├── pages.yml                # deploys the online demo to GitHub Pages only
│   └── appimage.yml             # builds the AppImage, checksums it, publishes the release
├── TAILS_INSTRUCTIONS.md        # Complete Tails guide
└── README.md                    # This file
```

### Running Locally

```bash
cd Slip39Demo.Web
dotnet run
```

Open: `http://localhost:5259`

## Releases

GitHub Actions automatically creates releases when version tags are pushed:

```bash
git tag v2.0.0
git push origin v2.0.0
```

This triggers:
- Build and publish
- Create GitHub Release
- Attach `slip39-backup-<version>-x86_64.AppImage` + `.sha256` for download (smoke-tested
  in CI under xvfb against the same WebKitGTK stack Tails ships)

## Security Considerations

### What This Tool Does

✅ **Client-side only**: All operations run in WebAssembly, whether that is a browser tab (demo) or the AppImage's own webview
✅ **No external requests**: Zero network traffic (verify in DevTools, or in the AppImage's build-time check that it references no external origin)
✅ **Your wallet is never written to disk**: the unencrypted seed and passphrase touch disk only if you choose to save the backup zip. The webview that renders the AppImage's window does create its own small local-data folder, the way any browser engine does; that folder holds no wallet data and is wiped along with the rest of a default Tails session
✅ **Tails compatible**: Works on RAM-only OS with offline mode

### What You Must Do

⚠️ **Split the backup zip immediately**: move share zips and `payload.age.gpg.asc` to their long-term homes, then delete the zip.
⚠️ **Store shares offline** - Paper, metal, or trusted holders. Never digital storage on internet-connected devices.
⚠️ **Distribute shares securely** - Never all in one place!
⚠️ **Test recovery** - Always do a dry-run recovery before relying on the backup.
⚠️ **No screenshots** - Don't screenshot shares or the recovered seed.

### Privacy on Tails

When using on Tails Linux:
- Everything runs in RAM
- Full system wipe on shutdown
- The AppImage opens a native window (system WebKitGTK): no browser, no
  local server, no open ports, nothing for another process to connect to

## FAQ

**Q: Is my seed phrase transmitted to a server?**
A: No. All cryptography runs in your browser via WebAssembly. Check browser DevTools Network tab to verify.

**Q: Can I use this without internet?**
A: Yes, that's the point. The AppImage is fully self-contained; run it on an airgapped Tails machine. No internet is required after the file is on the USB, and backups generated while online are watermarked INSECURE-TEST.

**Q: Do I need to remember a SLIP-39 passphrase?**
A: No. The new design has no SLIP-39 passphrase. The security boundary is "threshold-many shares **and** the `payload.age.gpg.asc` file". Anything inside it (including any BIP-39 passphrase you set on a cosigner) is recovered automatically once you have both.

**Q: What if I lose some shares?**
A: As long as you have threshold-many shares and `payload.age.gpg.asc`, you can recover. With the default 3-of-5 single-group setup, losing up to 2 shares is fine.

**Q: What if I lose `payload.age.gpg.asc`?**
A: The shares alone are not enough: they only reveal the random key `k`, not the wallet payload. That's why `payload.age.gpg.asc` should be stored with redundancy (e.g. password-manager Emergency Access plus an offline copy).

**Q: Is this better than just writing down my BIP-39 seed?**
A: Yes, because:
- Single point of failure eliminated
- Distributable to multiple locations/people
- Configurable redundancy (you choose thresholds)
- Cleanly separates "what shares protect" (`k`) from "what's in the wallet payload" (seed + passphrase + descriptor + notes)

**Q: Can I recover my wallet with this tool?**
A: Yes. The Recoverer page reconstructs the payload and shows the seed words (revealed on click). To actually access funds, import the recovered BIP-39 seed into your wallet application.

## License

See [LICENSE](LICENSE) file.

## Contributing

This is a security-focused tool. All contributions should prioritize:
- Client-side processing (no server dependencies)
- Offline capability
- Tails Linux compatibility
- Clear security documentation

## Acknowledgments

- [Xecrets.Slip39](https://github.com/xecrets/xecrets-slip39) by Svante Seleborg - SLIP-39 C# implementation
- [SLIP-0039 Specification](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) by SatoshiLabs
- [BIP-39 Specification](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [age encryption](https://age-encryption.org/) by Filippo Valsorda and Ben Cartwright-Cox

## Disclaimer

This tool is provided as-is for educational and personal use. Always:
- Test thoroughly before trusting with real funds
- Understand the cryptography before using
- Keep backups of backups
- Verify the source code yourself

**Use at your own risk. This is experimental software for handling sensitive cryptographic material.**

> Screenshots will be updated post-Phase-2 release.

---

*Collaboration by Claude*
