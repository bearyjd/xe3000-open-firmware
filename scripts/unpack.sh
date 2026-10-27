#!/usr/bin/env bash
# Unpack a stock firmware image (or a rootfs tar) in a network-less, hardened container. Nothing from the image is
# executed: it is parsed (unblob) or tar-extracted by code that refuses traversal and symlink/hardlink escapes.
# Usage: unpack.sh INPUT_FILE NAME      (ROOT, PODMAN, UNPACK_IMAGE, HARDENING in the environment)
#   build/unpack/NAME/   staging tree: unredacted, binaries kept, gitignored, never sent anywhere
#   unpacked/NAME/       redacted rootfs text, kernel FIT, DTBs, layout.json (names only), reports
# NAME must be new: this script never deletes anything.
set -euo pipefail
: "${ROOT:?}" "${PODMAN:?}" "${UNPACK_IMAGE:?}" "${HARDENING:?}"
input="${1:?usage: unpack.sh INPUT_FILE NAME}"
name="${2:?usage: unpack.sh INPUT_FILE NAME}"
case "$name" in
  "" | . | .. | *[!A-Za-z0-9._-]*) echo "unpack: NAME must match [A-Za-z0-9._-]+ and not be . or .." >&2; exit 2 ;;
esac
case "$input" in *:* | *,*) echo "unpack: INPUT must not contain ':' or ','" >&2; exit 2 ;; esac
if [ -L "$input" ] || [ ! -f "$input" ]; then echo "unpack: INPUT must be a regular file (not a symlink): $input" >&2; exit 2; fi
input_real="$(cd -P -- "$(dirname -- "$input")" && pwd)/$(basename -- "$input")"
if [ -e "$ROOT/build/unpack/$name" ] || [ -e "$ROOT/unpacked/$name" ]; then
  echo "unpack: build/unpack/$name or unpacked/$name already exists; pick a new NAME (nothing is deleted here)" >&2
  exit 2
fi
mkdir -p "$ROOT/build/unpack" "$ROOT/unpacked" "$ROOT/cache/redact-state"
# The input is mounted as one read-only file (never its directory, so harvest/raw is never exposed as a tree).
# The staging mount is noexec,nosuid,nodev so bytes extracted from the image can never be run from it.
# shellcheck disable=SC2086
$PODMAN run --rm $HARDENING --network=none \
  -v "$ROOT/scripts:/work/scripts:ro,z" -v "$input_real:/in/image:ro,z" \
  -v "$ROOT/build/unpack:/work/build:z,noexec,nosuid,nodev" -v "$ROOT/unpacked:/work/unpacked:z" \
  -v "$ROOT/cache/redact-state:/work/cache:z" \
  "$UNPACK_IMAGE" python scripts/unpack.py --input /in/image --work "/work/build/$name" --out "/work/unpacked/$name"
