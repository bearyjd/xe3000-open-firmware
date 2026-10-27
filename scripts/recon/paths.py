"""Path allowlist. Only harvest/redacted and unpacked may feed the analysis; harvest/raw never.

Stdlib only (also used by the host pre-flight wrapper).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

REDACTED_REL = Path("harvest") / "redacted"
UNPACKED_REL = Path("unpacked")
RAW_REL = Path("harvest") / "raw"


class PathRefused(ValueError):
    """A path is outside the allowlist, or escapes it through ..'/symlinks."""


@dataclass(frozen=True)
class InputFile:
    name: str   # stable display name, e.g. "redacted/etc/config/network"
    path: Path  # resolved absolute path (inside the allowlist)


def allowed_roots(root: Path) -> tuple[Path, ...]:
    return (Path(root).resolve() / REDACTED_REL, Path(root).resolve() / UNPACKED_REL)


def _raw_root(root: Path) -> Path:
    return Path(root).resolve() / RAW_REL


def _resolved_roots(root: Path) -> tuple[Path, ...]:
    """Allowed roots after resolve(); a root that itself points into raw is refused."""
    raw = _raw_root(root)
    resolved = []
    for candidate in allowed_roots(root):
        real = candidate.resolve()
        if real == raw or real.is_relative_to(raw):
            raise PathRefused(f"allowed root {candidate.name} resolves into harvest/raw")
        resolved.append(real)
    return tuple(resolved)


def check_path(path: Path, root: Path) -> Path:
    """Return the resolved path, or raise PathRefused."""
    real = Path(path).resolve()
    raw = _raw_root(root)
    if real == raw or real.is_relative_to(raw):
        raise PathRefused("refused: path is under harvest/raw")
    for allowed in _resolved_roots(root):
        if real == allowed or real.is_relative_to(allowed):
            return real
    raise PathRefused(f"refused: {path} is outside harvest/redacted and unpacked")


def list_input_files(input_dir: Path, root: Path) -> tuple[InputFile, ...]:
    """Walk input_dir without following links; every entry must resolve inside the allowlist."""
    start = check_path(Path(input_dir), root)
    if not start.is_dir():
        raise PathRefused(f"refused: {input_dir} is not a directory")
    found: list[InputFile] = []
    for dirpath, dirnames, filenames in os.walk(start, followlinks=False):
        for entry in [*dirnames, *filenames]:
            candidate = Path(dirpath) / entry
            real = check_path(candidate, root)  # raises for links escaping the allowlist
            if candidate.is_symlink() and real.is_dir():
                continue  # directory link inside the allowlist: its real contents are walked in place
            if real.is_file():
                found.append(InputFile(_name_for(candidate, start), real))
    return tuple(sorted(found, key=lambda f: f.name))


def _name_for(candidate: Path, start: Path) -> str:
    """Name = <input-root-dir-name>/<path relative to the walked dir>."""
    return f"{start.name}/{candidate.relative_to(start).as_posix()}"
