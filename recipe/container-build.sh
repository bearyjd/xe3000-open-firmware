#!/usr/bin/env bash
# Run feeds / defconfig / downloads (default) or the full compile inside the pinned build container.
# Only build/ is mounted. Output stays under build/. Nothing is flashed.
#
#   recipe/container-build.sh [feeds|compile]
#
# PODMAN selects the podman command (on this host: PODMAN="distrobox-host-exec podman").
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PODMAN="${PODMAN:-podman}"
IMAGE="${IMAGE:-localhost/xe3000-open-firmware-build:0.1}"
step="${1:-feeds}"

case "$step" in
feeds) cmd='./scripts/feeds update -a && ./scripts/feeds install -a && make defconfig && make download -j4' ;;
compile) cmd="make -j\$(nproc) V=s" ;;
*)
	echo "usage: container-build.sh [feeds|compile]" >&2
	exit 2
	;;
esac

TREE="$ROOT/build/openwrt"
[ -f "$TREE/.xe3000-prepared" ] || { echo "build/openwrt is missing or not fully prepared: run recipe/prepare.sh first" >&2; exit 1; }
pinned=""
# the pin file is the single pins.* file next to this script
for pinfile in "$HERE"/pins.*; do
	while IFS='=' read -r key value; do
		if [ "$key" = "OPENWRT_COMMIT" ]; then pinned="$value"; fi
	done <"$pinfile"
done
stamped="$(tr -d '[:space:]' <"$TREE/.xe3000-prepared")"
head="$(git -C "$TREE" rev-parse HEAD 2>/dev/null || true)"
if [ -z "$pinned" ] || [ "$head" != "$pinned" ] || [ "$stamped" != "$pinned" ]; then
	echo "build/openwrt does not match the pinned commit (prepare.sh must be re-run on a fresh build/openwrt)" >&2
	exit 1
fi

# Network is needed for feeds and downloads. No capabilities, no privilege escalation, bounded pids.
# shellcheck disable=SC2086
exec $PODMAN run --rm --cap-drop=ALL --security-opt no-new-privileges --pids-limit 4096 \
	--userns=keep-id --tmpfs /tmp \
	-v "$ROOT/build:/home/build/work:z" -w /home/build/work/openwrt \
	"$IMAGE" bash -c "$cmd"
