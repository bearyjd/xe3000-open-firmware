#!/usr/bin/env bash
# Redact a raw tree in a network-less hardened container. Raw is mounted read-only into THIS container only.
# Usage: redact-container.sh [--allow-src-anywhere] SRC DST_REL REPORT_NAME
# (ROOT, PODMAN, IMAGE, HARDENING in the environment.) SRC must be a real directory under $ROOT/harvest/raw
# unless --allow-src-anywhere is given: the ":z" relabel below rewrites SELinux labels of SRC, so it must never be
# pointed at something like $HOME by accident.
set -euo pipefail
: "${ROOT:?}" "${PODMAN:?}" "${IMAGE:?}" "${HARDENING:?}"
allow_anywhere=0
if [ "${1:-}" = "--allow-src-anywhere" ]; then allow_anywhere=1; shift; fi
src="${1:?usage: redact-container.sh [--allow-src-anywhere] SRC DST_REL REPORT_NAME}"
dst_rel="${2:?}"
report="${3:?}"
case "$src" in *:* | *,*) echo "redact: SRC must not contain ':' or ','" >&2; exit 2 ;; esac
case "$dst_rel$report" in *:* | *,* | *..*) echo "redact: bad DST_REL or REPORT_NAME" >&2; exit 2 ;; esac
if [ ! -d "$src" ] || [ -L "$src" ]; then echo "redact: SRC is not a plain directory: $src" >&2; exit 2; fi
src_real="$(cd -P -- "$src" && pwd)"
if [ "$allow_anywhere" -ne 1 ]; then
  if ! raw_real="$(cd -P -- "$ROOT/harvest/raw" 2>/dev/null && pwd)"; then echo "redact: $ROOT/harvest/raw missing" >&2; exit 2; fi
  case "$src_real/" in
    "$raw_real"/?*) ;;
    *) echo "redact: SRC must be inside $ROOT/harvest/raw (or pass --allow-src-anywhere)" >&2; exit 2 ;;
  esac
fi
mkdir -p "$ROOT/$dst_rel" "$ROOT/harvest/reports" "$ROOT/cache/redact-state"
# shellcheck disable=SC2086
$PODMAN run --rm $HARDENING --network=none \
  -v "$ROOT/scripts:/work/scripts:ro,z" -v "$src_real:/in:ro,z" \
  -v "$ROOT/$dst_rel:/work/$dst_rel:z" -v "$ROOT/harvest/reports:/work/reports:z" \
  -v "$ROOT/cache/redact-state:/work/cache:z" \
  "$IMAGE" python scripts/redact.py --src /in --dst "/work/$dst_rel" --report "/work/reports/$report"
