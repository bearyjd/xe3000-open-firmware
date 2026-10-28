"""One canonical place for file-name decisions: which names are secret-bearing, and how harvest.sh frame names decode.

The exclusion rules below are mirrored by hand in scripts/harvest.sh (`name_excluded`) and scripts/remote/collect.sh
(`is_excluded`); tests/test_name_parity.py fuzzes the three against each other. Change all three together.

harvest.sh stores frame `etc/config/chap-secrets` as `frames/<kind>/etc%config%chap-secrets`. Only that validated
wrapper (`frames/<kind>/` or `<kind>/`, kind from KINDS) is dropped when decoding; every other parent directory is
kept, so `private/etc%config%glmodem` stays under `private/`. A '%' in a directory name, or an empty/'.'/'..' segment
after splitting, is something harvest.sh never writes: those names are ambiguous and refused (None / excluded).
"""
from __future__ import annotations

import re
from collections.abc import Sequence

FLAT_SEP = "%"
PARTIAL_SUFFIX = ".partial"

KINDS = frozenset({"ident", "hw", "hw-bin", "hw-dt", "kernel", "sys", "config", "modem", "probe"})

# Credential stems match as SUBSTRINGS of the lower-cased basename, so .bak/.old/~/.orig/.dpkg-old copies are caught.
# Over-exclusion is accepted: a daemon called "shadowsocks" is excluded too.
EXCLUDED_PREFIXES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
EXCLUDED_SUFFIXES = (".wg",)
EXCLUDED_FRAGMENTS = (
    "chap-secrets", "pap-secrets", "ipsec.secrets", "shadow", "passwd-", "htpasswd", "authorized_keys",
    "wpa_supplicant", "wpa_psk", "userpass", "auth-user-pass", "host_key", "ssh_host_", "serial",
    ".psk", ".secrets", ".auth", ".pem", ".key",
)
EXCLUDED_DIRS = frozenset({"dropbear", "private"})  # any path segment; segments starting with "shadow" too
_WG_CONF = re.compile(r"wg.*\.conf")  # wireguard private configs: wg0.conf, wgvpn.conf.bak


def _parts_excluded(parts: tuple[str, ...]) -> bool:
    lowered = [p.lower() for p in parts]
    name = lowered[-1]
    return (
        any(p in EXCLUDED_DIRS or p.startswith("shadow") for p in lowered)
        or name.startswith(EXCLUDED_PREFIXES)
        or name.endswith(EXCLUDED_SUFFIXES)
        or any(f in name for f in EXCLUDED_FRAGMENTS)
        or bool(_WG_CONF.match(name))
    )


def decode(parts: Sequence[str]) -> tuple[str, ...] | None:
    """Un-flatten a harvest.sh file name; None when ambiguous. A plain path is returned unchanged."""
    parts = tuple(parts)
    if not parts:
        return parts
    dirs, last = parts[:-1], parts[-1]
    if any(FLAT_SEP in p for p in dirs):
        return None
    if FLAT_SEP not in last:
        return parts
    segs = tuple(last.split(FLAT_SEP))
    if any(s in ("", ".", "..") for s in segs):
        return None
    if len(dirs) == 2 and dirs[0] == "frames" and dirs[1] in KINDS:
        dirs = ()
    elif len(dirs) == 1 and dirs[0] in KINDS:
        dirs = ()
    return (*dirs, *segs)


def is_excluded(parts: Sequence[str]) -> bool:
    """True for secret-bearing names in plain or flattened form, ambiguous flattened names, and any *.PARTIAL frame
    (a truncated frame is never analysed, and the suffix must not hide the real name)."""
    parts = tuple(parts)
    if not parts:
        return False
    if parts[-1].lower().endswith(PARTIAL_SUFFIX):
        return True
    decoded = decode(parts)
    return decoded is None or any(_parts_excluded(c) for c in {parts, decoded})


def unflattened_path(rel: str) -> str | None:
    """'frames/config/etc%config%x' -> 'etc/config/x'; a plain path is returned unchanged; None when ambiguous."""
    if FLAT_SEP not in rel:
        return rel
    decoded = decode(rel.split("/"))
    return None if decoded is None else "/".join(decoded)
