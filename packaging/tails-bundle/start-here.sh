#!/bin/bash
#
# Checks the AppImage against SHA256SUMS, and starts it only if they match.
#
# Adapted from the same file in PeteSparrowBTC/dice-to-seed, deliberately: two tools in the
# same organisation handed to the same person on the same kind of USB stick should not have
# two different launchers with two different failure messages. The differences here are the
# app's name and what it asks the user to do afterwards.
#
# WHO THIS IS FOR
# ===============
# Someone standing at an offline Tails machine who does not use a terminal, has been handed a
# USB stick, and has no documentation except READ-THIS-FIRST.txt beside this file. Every choice
# below follows from that.
#
# WHY A DIALOG AND NOT AN ECHO
# ============================
# Double-clicked from the file manager, this script has no terminal attached, so anything
# printed to stdout or stderr goes nowhere. A verification that fails silently is worse than
# none: it teaches the user that the check "worked" whenever nothing appeared. So results go
# through zenity, which Tails ships. If zenity is absent the messages fall back to stderr,
# which is also the path CI exercises, since the runner has no zenity.
#
# WHAT THIS CHECK IS AND IS NOT
# =============================
# SHA256SUMS travels in the same folder as the AppImage it describes, so this proves the file
# is the one that was packaged with these instructions: not truncated, not corrupted by the
# copy, not altered on the stick afterwards. It is NOT a signature and it cannot tell anyone
# the download was genuine, because whoever could replace the AppImage could replace SHA256SUMS
# and this script along with it. Whoever handed over the stick is who is being trusted for
# that. READ-THIS-FIRST.txt says so in plain words, and neither file may ever imply otherwise.
#
# WHY IT ALSO LAUNCHES THE APP
# ============================
# Because otherwise nobody runs it. The alternative is telling a non-technical user to verify
# by hand and then launch by hand, at which point the verification is the step that gets
# skipped. Launching here means the only route to the app is the one that checks it first.
#
# THE EXECUTABLE BIT, AND WHY THE APPIMAGE ARRIVES WITHOUT ONE
# ============================================================
# The AppImage is stored 644 in the zip. If it arrived at 755 it would open on a double-click,
# which is easier than right-clicking this script, so the quickest way into the app would be
# the way that skips the check. The chmod below is what makes it runnable, and it happens only
# after the hash matches. Bypassing that needs a deliberate trip through Properties.
#
# GNOME Files opens an executable .sh in the text editor on a double-click, so the instructions
# say to right-click and choose "Run as a Program".

set -u

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CHECK_ONLY="${1:-}"

TITLE="SLIP-39 backup"

# --------------------------------------------------------------------------------------------
# Reporting. Every message a non-technical reader sees has to say what happened, what it means
# and what to do next, in that order, without jargon.
# --------------------------------------------------------------------------------------------
have_zenity() { command -v zenity >/dev/null 2>&1; }

fail() {
    if have_zenity; then
        zenity --error --width=460 --title="$TITLE" --text="$1" 2>/dev/null
    else
        printf '%s\n' "ERROR: $1" >&2
    fi
    exit 1
}

tell() {
    if have_zenity; then
        # --question rather than --info, so the button that continues is a deliberate press
        # rather than a dismissal, and Cancel is a real way out.
        zenity --question --width=460 --title="$TITLE" \
               --ok-label="Start the app" --cancel-label="Not now" --text="$1" 2>/dev/null
    else
        printf '%s\n' "$1"
    fi
}

# --------------------------------------------------------------------------------------------
# Find what we are checking. Globbed rather than named, so the version can change without this
# script changing, and a missing or duplicated AppImage is reported rather than guessed at.
# --------------------------------------------------------------------------------------------
cd "$HERE" || fail "Could not open the folder this file is in."

[ -f SHA256SUMS ] || fail "SHA256SUMS is missing from this folder.

This folder should contain four files: the app, SHA256SUMS, start-here.sh and READ-THIS-FIRST.txt. Extract the whole zip again, and keep the files together."

shopt -s nullglob
apps=(slip39-backup-*-x86_64.AppImage)
shopt -u nullglob

if [ "${#apps[@]}" -eq 0 ]; then
    fail "The app is not in this folder.

Extract the whole zip file, then run this again from the extracted folder."
elif [ "${#apps[@]}" -gt 1 ]; then
    fail "There is more than one copy of the app in this folder, so it is not clear which one to check. Keep only the one that came with these instructions."
fi

app="${apps[0]}"

# --------------------------------------------------------------------------------------------
# The check itself. One line of coreutils, which is the same command the documentation gives
# for doing this by hand, so what runs here and what a reader can verify are not two different
# things.
# --------------------------------------------------------------------------------------------
if ! sha256sum --check --status SHA256SUMS 2>/dev/null; then
    expected="$(awk '{print $1}' SHA256SUMS | head -1)"
    actual="$(sha256sum "$app" 2>/dev/null | awk '{print $1}')"

    fail "DO NOT USE THIS FILE.

The app on this stick is not the file that was packaged with these instructions. It may have been damaged while copying, or changed by something else.

Expected: ${expected}
Found:    ${actual:-could not be read}

What to do: delete it, and get a fresh copy from the person who gave you this stick. Do not type your seed words into it."
fi

if [ "$CHECK_ONLY" = "--check-only" ]; then
    printf '%s\n' "OK: $app matches SHA256SUMS."
    exit 0
fi

# --------------------------------------------------------------------------------------------
# Launch. chmod first, because the executable bit does not survive a FAT or exFAT stick and
# without it nothing happens at all. If it still is not executable afterwards, the folder is on
# media mounted noexec, which is the normal state of removable media and needs the folder
# copied into Home. That is a different problem with a different fix, so it gets its own
# message.
# --------------------------------------------------------------------------------------------
chmod +x "$app" 2>/dev/null

if [ ! -x "$app" ]; then
    fail "The app cannot be started from where it is.

This usually means the folder is still on the USB stick, and Tails does not allow programs to run from a stick.

What to do: copy this whole folder into your Home folder, then open it there and run this file again."
fi

version="$(printf '%s' "$app" | sed -E 's/^slip39-backup-(.*)-x86_64\.AppImage$/\1/')"

tell "The app has been checked and is the file that came with these instructions.

Version ${version}

Reminder: this checks that the file was not damaged or altered. It cannot prove the download itself was genuine; that is what the person who gave you this stick vouched for.

Keep this machine offline while you work. Anything produced with an internet connection is stamped INSECURE-TEST, on every page and inside the backup, and is not a backup.

Press Start to open it." || exit 0

if ! ./"$app"; then
    fail "The app did not start.

If this folder is on the USB stick, copy it into your Home folder and try again from there."
fi
