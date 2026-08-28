#!/bin/bash
#
# Assembles the Tails bundle: the AppImage, its fingerprint, a checker that refuses to launch a
# file that does not match, and instructions written for someone who does not use a terminal.
#
# Adapted from the same file in PeteSparrowBTC/dice-to-seed. Two tools in the same organisation
# handed to the same person on the same kind of stick should package the same way, and the
# reasoning behind each decision below was argued out there rather than here.
#
# WHAT THE FINGERPRINT IN THE ZIP IS FOR, SINCE IT IS EASY TO OVERSTATE. It travels beside the
# file it describes, so it proves the AppImage was not damaged or altered after packaging: a
# truncated copy to a stick, bitrot over years in a drawer, one file replaced and not the other.
# It CANNOT establish that the download was genuine, because whoever can serve a different zip
# regenerates the fingerprint inside it and rewrites this script too. Nothing inside a container
# authenticates the container. The value beyond corruption detection is that the checking route
# is the easy route, so the check actually happens.
#
# Run by appimage.yml on every build, not only on a tag. The zip is an artifact people will run
# against real seed phrases, so it gets built and asserted on pull requests too; dice-to-seed
# learned that the other way round, where a defect in the zip would first have been found by
# whoever downloaded it.
#
# The assertions at the bottom are the point of doing this in a script rather than inline YAML.
# Three things must hold and none is obvious:
#
#   1. The zip must STORE the executable bit on start-here.sh, and must NOT store it on the
#      AppImage. Unix modes live in the zip's external attributes field and Info-ZIP writes
#      them, but that is a property of the tool doing the zipping, so it is asserted rather
#      than believed. Whether the extractor on Tails restores them is a separate question that
#      cannot be tested from CI: Tails has no unzip command, extraction goes through Archive
#      Manager or 7zip. So the instructions also tell the user how to set the bit themselves,
#      and this assertion only guarantees the bit is there to be restored.
#   2. The checker must refuse a file that does not match. A verification that cannot fail is
#      decoration, so a corrupted copy is fed to it here and a zero exit is a build failure.
#   3. The checker must refuse when it cannot tell what to check: no SHA256SUMS, or two
#      AppImages in the folder.
#
# Usage: build-bundle.sh <path-to-appimage> <version> [output-directory]

set -euo pipefail

appimage_path="${1:?path to the AppImage is required}"
version="${2:?version is required}"
outdir="${3:-.}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
appimage_name="$(basename "$appimage_path")"
bundle_name="slip39-backup-${version}-tails"
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT

echo "Assembling ${bundle_name}.zip from ${appimage_name}"

# A single top-level folder inside the zip, so extracting produces one folder rather than four
# loose files in whatever directory the user happened to be in. The instructions name that
# folder, so the two have to agree.
work="${staging}/${bundle_name}"
mkdir -p "$work"

cp "$appimage_path" "$work/$appimage_name"
cp "${script_dir}/start-here.sh" "$work/start-here.sh"

# The fingerprint is generated here rather than copied, from the file actually being shipped,
# and with a bare filename so `sha256sum -c` works from inside the folder wherever it lands.
( cd "$work" && sha256sum "$appimage_name" > SHA256SUMS )
sha256="$(awk '{print $1}' "$work/SHA256SUMS")"

# The instructions quote the version and the fingerprint. Substituted from the same two values
# the rest of the bundle is built from, so a reader comparing the printed hash against
# SHA256SUMS can never be shown two different numbers.
sed -e "s/@VERSION@/${version}/g" -e "s/@SHA256@/${sha256}/g" \
    "${script_dir}/READ-THIS-FIRST.txt" > "$work/READ-THIS-FIRST.txt"

if grep -q "@VERSION@\|@SHA256@" "$work/READ-THIS-FIRST.txt"; then
    echo "::error::A placeholder survived substitution in READ-THIS-FIRST.txt."
    exit 1
fi

# The AppImage is deliberately NOT executable. An AppImage stored 755 arrives ready to
# double-click, which reads as a convenience and is a hole: double-clicking the app is then
# easier than right-clicking start-here.sh, so the fastest route to the application is the one
# that skips the check, and the check is what this artifact exists for. At 644 the app cannot
# run until start-here.sh has verified it and set the bit.
chmod 755 "$work/start-here.sh"
chmod 644 "$work/$appimage_name" "$work/SHA256SUMS" "$work/READ-THIS-FIRST.txt"

# ---------------------------------------------------------------------------------------------
# Assertions on the staged folder, before anything is zipped.
#
# Run against the staging directory rather than an extraction, because Tails has no unzip and
# the runner's unzip is not the extractor that will be used. What is under test is the checker's
# logic, which is the same either way. There is no zenity on the runner, so the script's stderr
# fallback is what runs here, which is worth exercising for its own sake.
# ---------------------------------------------------------------------------------------------
tampered="${staging}/tampered"

# Refuses, AND refuses for the stated reason. A refusal test that only looks at the exit code
# passes when the script fails for an unrelated reason, which is how a check quietly stops
# covering the case it was written for. So each one greps the message that names its branch.
refuses_with() {
    local expected="$1"
    local output

    if output="$( cd "$tampered" && ./start-here.sh --check-only 2>&1 )"; then
        echo "::error::The checker accepted the folder. Expected a refusal saying: ${expected}"
        exit 1
    fi

    if ! printf '%s' "$output" | grep -qF "$expected"; then
        echo "::error::The checker refused, but not for the expected reason."
        echo "expected to see: ${expected}"
        echo "what it said:    ${output}"
        exit 1
    fi

    echo "It refused, as it must: ${expected}"
}

echo "--- the checker accepts the file it shipped with"
( cd "$work" && ./start-here.sh --check-only )

echo "--- the checker refuses a corrupted file"
cp -r "$work" "$tampered"
printf 'x' >> "${tampered}/${appimage_name}"
refuses_with "DO NOT USE THIS FILE"

echo "--- the checker refuses a second copy of the app, which it cannot choose between"
cp "${work}/${appimage_name}" "${tampered}/${appimage_name}"
cp "${work}/${appimage_name}" "${tampered}/slip39-backup-0.0.0-x86_64.AppImage"
refuses_with "more than one copy of the app"

echo "--- the checker refuses when the fingerprint is missing"
rm -f "${tampered}/slip39-backup-0.0.0-x86_64.AppImage" "${tampered}/SHA256SUMS"
refuses_with "SHA256SUMS is missing"

# ---------------------------------------------------------------------------------------------
# The zip, and the modes it stored.
# ---------------------------------------------------------------------------------------------
mkdir -p "$outdir"
outdir="$(cd "$outdir" && pwd)"
( cd "$staging" && zip -qr "${outdir}/${bundle_name}.zip" "$bundle_name" )

command -v zipinfo >/dev/null || { echo "::error::zipinfo is needed to verify the bundle."; exit 1; }

echo "--- stored modes"
zipinfo "${outdir}/${bundle_name}.zip"

# Both directions matter, and asserting only one of them would miss the defect that matters
# more. The launcher has to arrive runnable, or nothing can be started at all. The AppImage has
# to arrive NOT runnable, or it can be started without being checked.
if ! zipinfo "${outdir}/${bundle_name}.zip" | grep -qE "^-rwxr-xr-x.* ${bundle_name}/start-here\.sh$"; then
    echo "::error::start-here.sh is not stored as executable, so extracting it cannot produce a runnable file."
    exit 1
fi

if ! zipinfo "${outdir}/${bundle_name}.zip" | grep -qE "^-rw-r--r--.* ${bundle_name}/${appimage_name//./\\.}$"; then
    echo "::error::The AppImage is stored as executable, so it can be launched without being checked first."
    exit 1
fi

ls -lh "${outdir}/${bundle_name}.zip"
echo "${bundle_name}.zip is assembled and verified."
