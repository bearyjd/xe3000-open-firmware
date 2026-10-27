#!/usr/bin/env bash
# Redact a raw tree in a network-less hardened container. Raw is mounted read-only into THIS container only.
# Usage: redact-container.sh SRC DST_REL REPORT_NAME   (ROOT, PODMAN, IMAGE, HARDENING in the environment)
set -euo pipefail
: "${ROOT:?}" "${PODMAN:?}" "${IMAGE:?}" "${HARDENING:?}"
src="${1:?usage: redact-container.sh SRC DST_REL REPORT_NAME}"
dst_rel="${2:?}"
report="${3:?}"
mkdir -p "$ROOT/$dst_rel" "$ROOT/harvest/reports" "$ROOT/cache/redact-state"
# shellcheck disable=SC2086
$PODMAN run --rm $HARDENING --network=none \
  -v "$ROOT/scripts:/work/scripts:ro,z" -v "$src:/in:ro,z" \
  -v "$ROOT/$dst_rel:/work/$dst_rel:z" -v "$ROOT/harvest/reports:/work/reports:z" \
  -v "$ROOT/cache/redact-state:/work/cache:z" \
  "$IMAGE" python scripts/redact.py --src /in --dst "/work/$dst_rel" --report "/work/reports/$report"
