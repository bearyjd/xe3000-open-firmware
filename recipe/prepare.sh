#!/usr/bin/env bash
# Prepare an OpenWrt source tree for the GL-XE3000: pinned tag, patches, overlay, seed .config.
# Writes only under build/ (gitignored). Never flashes, never talks to a router. Needs network only for the clone.
#
#   recipe/prepare.sh [--print-plan] [--dest DIR]
#
# Environment (test hooks / overrides): BUILD_DIR, OPENWRT_REPO, OPENWRT_TAG, OPENWRT_COMMIT.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

usage() {
	echo "usage: prepare.sh [--print-plan] [--dest DIR]  (DIR must be inside the build directory)" >&2
	exit 2
}

read_pins() {
	local key value
	while IFS='=' read -r key value; do
		case "$key" in
		OPENWRT_REPO | OPENWRT_TAG | OPENWRT_COMMIT)
			if [ -z "${!key:-}" ]; then
				printf -v "$key" '%s' "$value"
			fi
			;;
		esac
	done <"$HERE/pins.env"
}

die() {
	echo "prepare.sh: $*" >&2
	exit 1
}

print_plan() {
	cat <<PLAN
upstream : $OPENWRT_REPO
tag      : $OPENWRT_TAG
commit   : $OPENWRT_COMMIT (checkout must match exactly)
dest     : $DEST
steps    :
  1. clone the tag, verify HEAD equals the pinned commit
  2. git apply recipe/patches/tree/*.patch (kernel cmdline: pcie_port_pm=off)
  3. copy recipe/patches/kernel/*.patch to target/linux/generic/pending-$KVER (MHI PCI ID 17cb:0308, subsystem 17cb:5201 = 0x5201)
  4. copy recipe/files to files/ and recipe/feeds/xe3000/* to package/xe3000/
  5. seed .config from recipe/config/xe3000.config (XE3000 + gl-puli-mcu)
nothing is flashed; feeds and compilation run later inside the build container
PLAN
}

PRINT_ONLY=0
DEST_ARG=""
while [ "$#" -gt 0 ]; do
	case "$1" in
	--print-plan) PRINT_ONLY=1 ;;
	--dest)
		[ "$#" -ge 2 ] || usage
		DEST_ARG="$2"
		shift
		;;
	*) usage ;;
	esac
	shift
done

OPENWRT_REPO="${OPENWRT_REPO:-}"
OPENWRT_TAG="${OPENWRT_TAG:-}"
OPENWRT_COMMIT="${OPENWRT_COMMIT:-}"
read_pins
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
DEST="${DEST_ARG:-$BUILD_DIR/openwrt}"
KVER="6.12"

case "$DEST" in
"$BUILD_DIR"/*) ;;
*)
	echo "prepare.sh: destination must be inside the build directory ($BUILD_DIR)" >&2
	exit 2
	;;
esac
case "$DEST" in *..*) echo "prepare.sh: '..' not allowed in destination (build directory only)" >&2; exit 2 ;; esac

if [ "$PRINT_ONLY" -eq 1 ]; then
	print_plan
	exit 0
fi

[ ! -e "$DEST" ] || die "destination exists: $DEST (remove it yourself to start fresh)"
mkdir -p "$BUILD_DIR"

git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$OPENWRT_TAG" "$OPENWRT_REPO" "$DEST"
head="$(git -C "$DEST" rev-parse HEAD)"
[ "$head" = "$OPENWRT_COMMIT" ] || die "tag $OPENWRT_TAG resolves to $head which does not match the pinned commit $OPENWRT_COMMIT"

for patch in "$HERE"/patches/tree/*.patch; do
	git -C "$DEST" apply --whitespace=nowarn "$patch"
done

pending="$DEST/target/linux/generic/pending-$KVER"
[ -d "$pending" ] || die "missing $pending (kernel version changed upstream?)"
cp "$HERE"/patches/kernel/*.patch "$pending/"

mkdir -p "$DEST/files" "$DEST/package/xe3000"
cp -a "$HERE/files/." "$DEST/files/"
cp -a "$HERE/feeds/xe3000/." "$DEST/package/xe3000/"
cp "$HERE/config/xe3000.config" "$DEST/.config"

echo "prepared $DEST at $OPENWRT_TAG ($head)"
