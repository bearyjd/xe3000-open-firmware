#!/usr/bin/env bash
# Disassemble the bounded list in scripts/decompile-targets.txt inside the hardened decompile container.
# Called by the justfile with ROOT, PODMAN, DECOMPILE_IMAGE and HARDENING in the environment.
# Usage: decompile.sh ROOTFS   (ROOTFS is a directory under build/unpack, e.g. the unblob root_extract directory)
# The firmware tree is mounted read-only, there is no network, nothing from it is executed, output goes to
# unpacked/decompiled/ (gitignored). Run `just preflight` afterwards: the text is scanned like any unpacked text.
set -euo pipefail
umask 077
: "${ROOT:?}" "${PODMAN:?}" "${DECOMPILE_IMAGE:?}" "${HARDENING:?}"
src="${1:?usage: decompile.sh ROOTFS (a directory under build/unpack)}"
base="$(cd "$ROOT/build/unpack" && pwd -P)"
real="$(cd "$src" && pwd -P)"
case "$real" in
  "$base"/*) rel="${real#"$base"/}" ;;
  *) echo "decompile: refused: $src is not under build/unpack" >&2; exit 2 ;;
esac
mkdir -p "$ROOT/unpacked/decompiled"
# shellcheck disable=SC2086  # PODMAN and HARDENING are intentionally word-split
$PODMAN run --rm $HARDENING --network=none -e HOME=/tmp \
  -v "$ROOT/build/unpack/$rel:/in:ro,z" \
  -v "$ROOT/scripts:/work/scripts:ro,z" \
  -v "$ROOT/unpacked/decompiled:/out:z" \
  "$DECOMPILE_IMAGE" python scripts/decompile.py --rootfs /in --targets /work/scripts/decompile-targets.txt --out /out
