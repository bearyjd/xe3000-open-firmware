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

# Refuse to build when the overlay could carry secrets or anything not committed to git.
check_overlay() {
	local dir="$HERE/files" f rel
	[ -d "$dir" ] || die "overlay directory missing: $dir"
	if [ -n "$(find "$dir" -mindepth 1 ! -type f ! -type d -print -quit)" ]; then
		die "overlay contains symlinks or special files: $(find "$dir" -mindepth 1 ! -type f ! -type d -print -quit)"
	fi
	while IFS= read -r -d '' f; do
		rel="${f#"$dir"/}"
		case "$rel" in
		etc/* | usr/*) ;;
		*) die "overlay file outside etc/ and usr/: $rel" ;;
		esac
		case "$(basename "$rel" | tr '[:upper:]' '[:lower:]')" in
		.env | .env.* | *.pem | *.key | *.p12 | *.pfx | *.kdbx | *.secret | *.secrets | id_* | *_host_key | \
			shadow | shadow- | passwd- | .netrc | .git* | *credential* | *secret*)
			die "overlay file looks secret-bearing: $rel" ;;
		esac
		case "$rel" in
		*/dropbear/* | */.s[s]h/* | etc/shadow* | etc/ssl/private/*) die "overlay file in a secret location: $rel" ;;
		esac
		if grep -qE -e '-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----' -- "$f"; then
			die "overlay file contains private key material: $rel"
		fi
	done < <(find "$dir" -type f -print0)
	if git -C "$ROOT" rev-parse --show-toplevel >/dev/null 2>&1 && [ "$(git -C "$ROOT" rev-parse --show-toplevel)" = "$ROOT" ]; then
		local untracked
		untracked="$(git -C "$ROOT" ls-files --others -- recipe/files; git -C "$ROOT" ls-files --others --ignored --exclude-standard -- recipe/files)"
		[ -z "$untracked" ] || die "overlay has untracked or ignored files (commit or remove): $(printf '%s' "$untracked" | head -1)"
	fi
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
  4. copy recipe/files to files/ (refused if untracked, ignored, symlinked or secret-looking) and recipe/feeds/xe3000/* to package/xe3000/
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

check_overlay
[ ! -e "$DEST" ] || die "destination exists: $DEST (remove it yourself to start fresh)"
mkdir -p "$BUILD_DIR"

# Build in a scratch dir next to DEST; DEST only appears once every check and patch has succeeded.
tmp="$(mktemp -d "$BUILD_DIR/.openwrt.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
work="$tmp/openwrt"

git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$OPENWRT_TAG" "$OPENWRT_REPO" "$work"
head="$(git -C "$work" rev-parse HEAD)"
[ "$head" = "$OPENWRT_COMMIT" ] || die "tag $OPENWRT_TAG resolves to $head which does not match the pinned commit $OPENWRT_COMMIT"

for patch in "$HERE"/patches/tree/*.patch; do
	git -C "$work" apply --whitespace=nowarn "$patch" || die "tree patch failed: $patch"
done

pending="$work/target/linux/generic/pending-$KVER"
[ -d "$pending" ] || die "missing $pending (kernel version changed upstream?)"
cp "$HERE"/patches/kernel/*.patch "$pending/"

mkdir -p "$work/files" "$work/package/xe3000"
cp -a "$HERE/files/." "$work/files/"
cp -a "$HERE/feeds/xe3000/." "$work/package/xe3000/"
cp "$HERE/config/xe3000.config" "$work/.config"
printf '%s\n' "$head" >"$work/.xe3000-prepared"

mkdir -p "$(dirname "$DEST")"
mv "$work" "$DEST"

echo "prepared $DEST at $OPENWRT_TAG ($head)"
