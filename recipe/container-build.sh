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

[ -d "$ROOT/build/openwrt" ] || { echo "run recipe/prepare.sh first" >&2; exit 1; }

# Network is needed for feeds and downloads. No capabilities, no privilege escalation, bounded pids.
# shellcheck disable=SC2086
exec $PODMAN run --rm --cap-drop=ALL --security-opt no-new-privileges --pids-limit 4096 \
	--userns=keep-id --tmpfs /tmp \
	-v "$ROOT/build:/home/build/work:z" -w /home/build/work/openwrt \
	"$IMAGE" bash -c "$cmd"
