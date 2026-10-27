#!/usr/bin/env bash
# Shared input-hygiene helpers for prepare.sh and container-build.sh. Source it; it runs nothing by itself.
set -euo pipefail

XE3000_MANIFEST=".xe3000-manifest"
XE3000_SEED=".xe3000-config.seed"

# Credential-shaped content (extended regex, case-insensitive). Empty values and $VAR references are allowed.
XE3000_CRED_PATTERNS=(
	'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'
	'^[[:space:]]*(option|list)[[:space:]]+(key|psk|[a-z_]*(password|passwd|passphrase|secret|token|api_?key|auth_?key|private_?key))[[:space:]]+["'"'"']?[^[:space:]"'"'"']'
	'(password|passwd|passphrase|psk|secret|token|api_?key|auth_?key|private_?key|wpa_?key)[a-z0-9_.@-]*["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?[^[:space:]"'"'"'$#;(`]'
	'\.key=["'"'"']?[^[:space:]"'"'"'$]'
	'gh[pousr]_[A-Za-z0-9]{30,}|sk-ant-[A-Za-z0-9_-]{10,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}'
)

xe3000_fail() {
	echo "recipe: $*" >&2
	return 1
}

# Reject symlinks, devices, fifos and sockets anywhere under DIR.
xe3000_check_special() {
	local dir="$1" label="$2" bad
	bad="$(find "$dir" -mindepth 1 ! -type f ! -type d -print -quit)"
	[ -z "$bad" ] || xe3000_fail "$label contains symlinks or special files: ${bad#"$dir"/}"
}

# Reject files whose name or location says "secret".
xe3000_check_names() {
	local dir="$1" label="$2" f rel
	while IFS= read -r -d '' f; do
		rel="${f#"$dir"/}"
		case "$(basename "$rel" | tr '[:upper:]' '[:lower:]')" in
		.env | .env.* | *.pem | *.key | *.p12 | *.pfx | *.kdbx | *.secret | *.secrets | id_* | *_host_key | \
			shadow | shadow- | passwd- | .netrc | .git* | *credential* | *secret*)
			xe3000_fail "$label file looks secret-bearing: $rel"
			return 1
			;;
		esac
		case "$rel" in
		*/dropbear/* | */.s[s]h/* | etc/shadow* | etc/ssl/private/*)
			xe3000_fail "$label file in a secret location: $rel"
			return 1
			;;
		esac
	done < <(find "$dir" -type f -print0)
}

# Reject credential-looking content (private keys, Wi-Fi keys, passwords, tokens) in any file under DIR.
xe3000_scan_credentials() {
	local dir="$1" label="$2" f p
	while IFS= read -r -d '' f; do
		for p in "${XE3000_CRED_PATTERNS[@]}"; do
			if grep -aqiE -e "$p" -- "$f"; then
				xe3000_fail "$label file contains credential-like content: ${f#"$dir"/}"
				return 1
			fi
		done
	done < <(find "$dir" -type f -print0)
}

# Full hygiene check for one input directory.
xe3000_check_input_dir() {
	local dir="$1" label="$2"
	[ -d "$dir" ] || xe3000_fail "$label directory missing: $dir" || return 1
	xe3000_check_special "$dir" "$label" || return 1
	xe3000_check_names "$dir" "$label" || return 1
	xe3000_scan_credentials "$dir" "$label"
}

# One line per prepared input: "<mode> <sha256> <path>" plus a digest of the tracked-file diff (tree patches).
xe3000_manifest_lines() {
	local tree="$1" f rel
	(
		cd "$tree"
		for rel in files package/xe3000 target/linux/generic/pending-* "$XE3000_SEED"; do
			[ -e "$rel" ] || [ -L "$rel" ] || continue
			find "$rel" \( -type f -o -type l \) -print0
		done | LC_ALL=C sort -z | while IFS= read -r -d '' f; do
			if [ -L "$f" ] || [ ! -f "$f" ]; then
				echo "special - $f"
			else
				printf '%s %s %s\n' "$(stat -c %a "$f")" "$(sha256sum -- "$f" | cut -d' ' -f1)" "$f"
			fi
		done
		printf 'tree-diff %s\n' "$(git diff HEAD 2>/dev/null | sha256sum | cut -d' ' -f1)"
	)
}

xe3000_write_manifest() {
	local tree="$1"
	xe3000_manifest_lines "$tree" >"$tree/$XE3000_MANIFEST"
}

# The seed .config symbols must survive `make defconfig`; extra inputs must not have appeared.
xe3000_verify_manifest() {
	local tree="$1" current line
	[ -f "$tree/$XE3000_MANIFEST" ] || xe3000_fail "prepared inputs have no manifest: re-run recipe/prepare.sh" || return 1
	current="$(xe3000_manifest_lines "$tree")"
	[ "$current" = "$(cat "$tree/$XE3000_MANIFEST")" ] ||
		xe3000_fail "prepared inputs changed since prepare.sh (overlay, packages, patches or seed config): re-run recipe/prepare.sh on a fresh build/openwrt" ||
		return 1
	if [ -f "$tree/$XE3000_SEED" ]; then
		[ -f "$tree/.config" ] || xe3000_fail "prepared inputs: .config is missing" || return 1
		while IFS= read -r line; do
			case "$line" in "" | "#"*) continue ;; esac
			grep -qxF -- "$line" "$tree/.config" || xe3000_fail "prepared inputs: .config lost seed setting $line" || return 1
		done <"$tree/$XE3000_SEED"
	fi
}

# Rescan everything that will enter the firmware or the build container.
xe3000_check_prepared_tree() {
	local tree="$1"
	xe3000_verify_manifest "$tree" || return 1
	[ ! -d "$tree/files" ] || xe3000_check_input_dir "$tree/files" "overlay" || return 1
	[ ! -d "$tree/package/xe3000" ] || xe3000_check_input_dir "$tree/package/xe3000" "package" || return 1
}
