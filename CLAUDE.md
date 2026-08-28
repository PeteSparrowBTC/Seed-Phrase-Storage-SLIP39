# Working in this repository

## Settled design decisions: read before proposing changes to the crypto

The choices below were argued out in full and reached conclusions. The reasoning,
the rejected alternatives, and above all the **limits** of each are recorded in
[docs/decisions/2026-08-09-envelope-entropy-and-implementations.md](docs/decisions/2026-08-09-envelope-entropy-and-implementations.md).
Read that before reopening any of them. Several are correct only within a
boundary, and a change that ignores the boundary will look like an improvement
while removing the protection.

The short form:

- **The payload is wrapped twice**, age inside OpenPGP AES-256. Nesting composes:
  an attacker must break both. It lifts the post-quantum margin from 2^64 to
  2^128, because age's file key is 128 bits.
- **One payload artifact ships**: `payload.age.gpg.asc`, armored. This REVERSES an
  earlier decision that shipped the unwrapped forms alongside it, which handed
  anyone who obtained the folder the weaker file and so nullified the wrapper.
  Anything shipped beside it must be at least as strong as it.
- **Both layers take the same K.** This hedges a cipher or format break. It does
  NOT hedge a break that recovers the passphrase itself. Accepted deliberately:
  independent keys would make recovery a scripted derivation no heir can perform
  by hand.
- **Encryption runs the bundled official age binary; AgeSharp decrypts.**
  Encryption failures are silent, decryption failures are loud, so the invisible
  side gets the most-scrutinised implementation. **Fails closed** if the binary is
  missing. Do not add a fallback.
- **The OpenPGP layer is in-process on BouncyCastle**, so recovery never needs
  GnuPG installed. Keep handling gpg's compression: GnuPG compresses by default,
  so real files carry packets we never produce ourselves.
- **The system's GnuPG opens that layer before a real backup is released**, and
  must return the age file byte for byte. It is the one layer written by code from
  this repository, and BouncyCastle opening its own envelope agrees with itself
  whatever it wrote. A real backup **fails closed**, GnuPG missing included; an
  INSECURE-TEST backup continues but says in the transcript that nothing
  independent opened it. Do not make the browser build verify with BouncyCastle to
  turn that into a pass: a check that always passes reads as evidence.
- **The wallet payload goes out through `PayloadRoundTrip.EmitChecked`**, which
  reparses and compares before anything is encrypted, and refuses by name if a
  value does not survive. The format writes one value per line, so it cannot carry
  a line break, and the old parser also ate leading whitespace: a passphrase of
  `" hunter2"` recovered a different wallet with every check still passing.
  Refusals never echo the value, because the values are seed words and
  passphrases and the message lands in an on-screen banner.
- **Dice entropy for K is 50 rolls, not 99**, XORed with the system RNG, never
  replacing it. Never reuse the seed's rolls.
- **The multisig descriptor is computed, and the record carries the first receive
  address.** With two or more cosigners the tool derives each account key at that
  cosigner's BIP-48 path and assembles `wsh(sortedmulti(k,...))`; a pasted
  descriptor overrides it, and the record says which it was. The address is there
  because a master fingerprint cannot catch a wrong derivation path, and the
  xpubs stay out of the record because it is a file meant to be printed. Multisig
  only, 2-of-2 or better, mainnet only, native segwit only, and every path it
  cannot describe exactly is a refusal rather than a guess. This REVERSES design
  spec section 10.2.
- **Rejected:** a browser verifier shipped in our own bundle (it cannot verify
  its own producer), and zip password protection (the ubiquitous variant is
  ZipCrypto, which is broken, and our plaintext prefix is published).

**Where the real risk sits**, in order: operator error; key generation; supply
chain; implementation bugs; cryptanalysis last. The first is unfixed. Do not
propose work on the last while it remains open. The `PayloadParser`
leading-whitespace trap used to sit second on that list and was fixed on
2026-08-11; the decisions document records what made it worse than the trim
itself, which is the part worth reading before adding a field to the payload.

## CRITICAL: main moves only through a pull request

- **Never push to main.** Not `git push origin main`, not a bare `git push` while main
  is checked out, not `git push origin HEAD:main`, and no `--force` variant. Open a pull
  request instead.
- **Never merge a pull request.** Not `gh pr merge`, not the REST API, not the web UI.
  Opening the PR is the agent's job; merging is the human's.
- **A version tag is a release.** `.github/workflows/appimage.yml` builds the AppImage,
  checksums it and publishes a GitHub Release on `v*` tag push, and that artifact is what
  people run against real seed phrases. Push a tag only when explicitly asked, and only
  once the release commit is on main through a merged PR.
- Pushing feature branches (`git push -u origin <branch>`) is safe and expected.

### The three mechanisms, and what each actually does

| mechanism | what it actually does |
| --- | --- |
| The `main` **ruleset** on GitHub | **The real enforcement.** Server-side, survives a reclone, applies to every client and to the web UI. Already in place here (below), and it is a ruleset rather than legacy branch protection, which changes how you check it. |
| `.githooks/pre-push` | **Blocks locally**, so a mistake fails before the network round-trip and prints the way out. Opt in per clone: `git config core.hooksPath .githooks`. Bypassable with `--no-verify`, by design. |
| `.claude/settings.json` deny rules | Stops an agent from issuing the common main-targeting push and merge commands, plus the `gh api` verbs that could remove the protection itself. Matching is prefix-based and cannot cover every spelling, so it is a backstop for judgement, not a replacement. |

Deliberately **not** used: an `on: push` workflow that "prevents" direct pushes. Such a
workflow runs after the server has already accepted the push, so it can only report, never
block. A sibling repository had one that failed 39 of 39 runs, including every legitimate
merge, because `github.event.pull_request` is always null on a push event. A permanently red
check is worse than no check. This repository is public, so real server-side enforcement is
available and is used instead.

### How `main` is actually protected, and how to check it

**It is a ruleset, not legacy branch protection, and that distinction has already
produced one wrong answer.** The two features are separate systems with separate
APIs, and the legacy endpoint knows nothing about rulesets:

```bash
# Reports "Branch not protected" (HTTP 404) on this repository, which IS protected.
gh api repos/PeteSparrowBTC/slip39-backup/branches/main/protection
```

A review ran that command, took the 404 at face value, and was about to report the
repository as wide open. Check the ruleset instead:

```bash
gh api repos/PeteSparrowBTC/slip39-backup/rulesets \
  --jq '.[] | {name, enforcement}'
# main / active

# The rules themselves, and who may bypass them. An empty bypass list is the
# ruleset equivalent of enforce_admins: nobody, including the owner, gets round it.
gh api repos/PeteSparrowBTC/slip39-backup/rulesets/12211639 \
  --jq '{rules: [.rules[].type], bypass: [.bypass_actors[]?.actor_type]}'
# rules: ["deletion", "non_fast_forward", "pull_request"], bypass: []
```

Those three rules are what matter: a pull request is required, `main` cannot be
deleted, and it cannot be force-pushed. No approving review is required, because
GitHub does not allow self-approval and requiring one would make every pull
request unmergeable until a second maintainer exists.

Setting one up on a repository that has none is easiest in the UI: Settings, Rules,
Rulesets, New branch ruleset, target the default branch, tick "Restrict deletions",
"Block force pushes" and "Require a pull request before merging", and leave the
bypass list empty. Do not add legacy branch protection alongside a ruleset; two
overlapping mechanisms make it unclear which one is refusing a push. dice-to-seed
currently has both, which is how the legacy command above appears to work there.

### Enable the local hook after cloning

```bash
git config core.hooksPath .githooks
```

Tested behaviour: a push targeting `main` exits 1 with instructions, a feature branch exits
0 silently, a `v*` tag exits 0 with a release warning.

## Testing conventions

- `SLIP39_AGE_DIR` points at an unpacked age release and enables
  `the_real_age_program_produces_an_age_file` in `src-tauri/src/age.rs`, the one
  Rust test that runs the real `age` binary end to end. Locally, without the
  variable set, it prints a skip message and returns; Rust has no equivalent of
  `SkippableFact`, so a plain early return would look like a pass with nothing
  checked. To avoid that, the test also checks for a `CI` environment variable: if
  that is set and `SLIP39_AGE_DIR` is not, it fails outright rather than passing
  silently. CI sets `SLIP39_AGE_DIR` after fetching the pinned age release, so this
  path is not expected to trigger there.
- The gpg interop tests skip the same way when GnuPG is absent.
- Third-party binaries are never committed. They are fetched, pinned by version
  AND checksum, and verified at build time (`age` and `appimagetool`, in
  `packaging/appimage/build-appimage.sh`).
- **The one committed third-party artifact is
  `Slip39Demo.UI/wwwroot/js/independent-verify.min.js`**, because a browser cannot
  fetch and verify a bundle on an airgapped machine. It is held to the same standard
  by a different route: `appimage.yml` rebuilds it from `tools/independent-verify`
  with `npm ci` and fails if a single byte differs, so the committed bytes are
  derived from a pinned lockfile rather than trusted. Never hand-edit it, and never
  update it with `npm install`: `package.json` carries caret ranges, so only
  `npm ci` reproduces what CI will compare against.

## Writing style

No em dashes. Use a colon, semicolon, comma, parentheses, or a sentence break instead.
This applies to prose, comments, and commit messages.
