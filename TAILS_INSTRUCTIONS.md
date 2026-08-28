# Running slip39-backup on Tails

The tool ships as a single AppImage that opens a **native window**: no browser,
no local server, no Tor configuration. All cryptography runs locally; the window
is rendered by WebKitGTK, which Tails ships out of the box.

The app has two pages you'll use:
- **`/owner`**: create a backup. Saves one zip named after the wallet and the
  date, for example `slip39-wallet-backup-main-wallet-2026-08-13.zip`, holding
  the share zips, the single ciphertext `payload/payload.age.gpg.asc`, a
  verification record and the recovery documents.
- **`/recoverer`**: recover a wallet. Drop in threshold-many share zips and
  `payload.age.gpg.asc` (or paste its text), then click Recover. Older backups
  may hold `payload.age` or `payload.age.txt` instead, and those still work.

**The ciphertext has two locks, both opened by the same key.** age on the inside,
OpenPGP AES-256 on the outside, and your shares rebuild the one key that opens
both. One file ships rather than one per layer: an unwrapped copy sitting beside
the wrapped one would let anyone who found the folder break the weaker of the two
and ignore the other.

## Requirements

- **Tails 7.0 or later** (Debian 13 base). Tails 6 and older are end-of-life
  and unsupported: on them the app fails to start with a `GLIBC_2.38 not
  found` error. Check your version under Applications, Tails, About Tails.
- A USB drive with what you downloaded from GitHub Releases. The filenames carry the
  version, for example `slip39-backup-2.1.0-tails.zip` and
  `slip39-backup-2.1.0-x86_64.AppImage`. Substitute the version you downloaded in the
  commands below; the app shows the same number in its footer, so you can check the
  file you ran is the file you meant to run.

## Which download to take

**`slip39-backup-<version>-tails.zip`** if you are going to use this. It holds the
AppImage, a `SHA256SUMS` naming it, a `start-here.sh` that checks the app and opens it
only if the fingerprint matches, and a `READ-THIS-FIRST.txt` written for somebody who
does not use a terminal. Extract it into the home folder, right-click `start-here.sh`,
choose "Run as a Program". The AppImage inside is stored non-executable on purpose:
until the check has run, there is nothing to launch.

The loose AppImage plus `SHA256SUMS` if you would rather do it by hand, which is the
route the numbered steps below describe.

**What the fingerprint proves.** That the app is intact and unaltered where it sits:
not truncated, not damaged by the copy, not changed on the stick afterwards. It is not
a signature. It travels beside the file it describes, so anyone who could replace the
app could replace the fingerprint and the launcher too, and no check inside the zip can
tell you the download was genuine. Read the hashes from the release page and from the
tagged build log if you want two sources for them.

## Steps

1. **Boot Tails.** For real backups, do **not** connect to a network. The whole
   point is generating secrets on an airgapped machine, and the tool detects
   connectivity and watermarks anything generated while online as INSECURE-TEST.

2. **Copy the AppImage** from the USB into the home folder (`/home/amnesia`).
   Running from the home folder avoids filesystem quirks of FAT-formatted
   sticks (where the executable bit can't be set).

3. **Verify the download** (only needed if the file came from GitHub rather
   than your own build):
   ```bash
   sha256sum -c SHA256SUMS
   ```
   `sha256sum -c slip39-backup-3.0.0-x86_64.AppImage.sha256` does the same for the
   AppImage alone, and is what you still have if you kept the app and not the rest.
   Use `--ignore-missing` to check only the files you actually copied across.

4. **Run it** (in Files, right-click the folder and choose Open Terminal Here):
   ```bash
   chmod +x slip39-backup-3.0.0-x86_64.AppImage
   ./slip39-backup-3.0.0-x86_64.AppImage
   ```
   The app window opens directly.

   This used to say that double-clicking in the Files app does nothing, because
   GNOME refuses to launch raw executables. That is wrong on Tails 7, and the
   correction is field-tested rather than reasoned: on `nautilus 48.3` an AppImage
   carrying its executable bit launches on a plain double-click, with no terminal
   and no Properties step (see the org's
   [tails-appimage field notes](https://github.com/PeteSparrowBTC/tails-appimage),
   checked 2026-08-11). Scripts are the exception: an executable `.sh` opens in the
   text editor, which is why the bundle's launcher is run through right-click, "Run
   as a Program".

   That behaviour is also why the AppImage inside the Tails zip is stored
   non-executable. If it arrived ready to double-click, the fastest route into the
   app would be the one that skips the check.

5. **Create your backup** in the Owner page. Save the output where you choose
   via the native save dialog; print the recovery kit via the print dialog
   (print-to-PDF works out of the box).

6. **Shut down Tails.** Everything outside your explicit saves is wiped on a
   default (non-Persistent) session. The app itself never writes your seed or
   passphrase to disk unless you save it yourself; the WebKitGTK window does
   create its own small local-data folder, the way any browser engine does,
   holding no wallet data, and it is wiped along with the rest unless you have
   enabled Persistent Storage, in which case it is not.

## Troubleshooting

- **`GLIBC_2.38 not found`**: your Tails is version 6 or older. Upgrade the
  stick to Tails 7 or later (going from 6 to 7 needs a fresh install with Tails
  Cloner, not the automatic upgrader).
- **`Permission denied` when running**: the file is on a FAT-formatted stick
  where `chmod +x` silently does nothing. Copy it to the home folder first.
- **Window doesn't open, webkit errors in terminal**: you're not on Tails
  (the AppImage deliberately relies on Tails's system WebKitGTK; other distros
  need `libwebkit2gtk-4.1` installed).
