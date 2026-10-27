#!/usr/bin/env bash
# Run scripts/analyze.py in the hardened recon container. Called by the justfile with ROOT, PODMAN, IMAGE and
# HARDENING in the environment. Usage: analyze-container.sh RUN_ID [analyze.py flags...]
# The key enters only via a 0600 temp env-file holding just the three allowed lines; it is never printed and
# is deleted on exit. Pre-flight stamps are mounted read-only; only cache/responses is writable.
set -euo pipefail
umask 077
: "${ROOT:?}" "${PODMAN:?}" "${IMAGE:?}" "${HARDENING:?}"
run_id="${1:?usage: analyze-container.sh RUN_ID [flags...]}"
shift
mkdir -p "$ROOT/harvest/redacted" "$ROOT/unpacked" "$ROOT/cache/preflight" "$ROOT/cache/responses" \
         "$ROOT/findings/raw"
envf="$(mktemp)"
trap 'rm -f "$envf"' EXIT
trap 'rm -f "$envf"; exit 130' INT
trap 'rm -f "$envf"; exit 143' TERM
grep -E '^(ANTHROPIC_API_KEY|LLM_MODEL|LLM_MODEL_CHEAP)=' "$ROOT/.env" 2>/dev/null > "$envf" || true
# Known-secret canaries (if any) enter read-only; their values are never printed.
canary="${RECON_CANARY_FILE:-$HOME/.config/xe3000-open-firmware/canaries}"
canary_args=()
if [ -f "$canary" ]; then
  canary_args=(-v "$canary:/run/recon-canaries:ro,z" -e RECON_CANARY_FILE=/run/recon-canaries)
fi
# shellcheck disable=SC2086  # PODMAN and HARDENING are intentionally word-split
$PODMAN run --rm $HARDENING --env-file "$envf" ${canary_args[@]+"${canary_args[@]}"} \
  -v "$ROOT/scripts:/work/scripts:ro,z" -v "$ROOT/containers:/work/containers:ro,z" \
  -v "$ROOT/harvest/redacted:/work/harvest/redacted:ro,z" -v "$ROOT/unpacked:/work/unpacked:ro,z" \
  -v "$ROOT/cache/preflight:/work/cache/preflight:ro,z" -v "$ROOT/cache/responses:/work/cache/responses:z" \
  -v "$ROOT/findings/raw:/work/findings/raw:z" \
  "$IMAGE" python scripts/analyze.py --run-id "$run_id" "$@"
