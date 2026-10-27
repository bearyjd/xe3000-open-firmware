"""Independent secrets pre-flight (PRP 0001 §3, §3.5). Stdlib only: runs on the host.

gitleaks runs with --redact and its own config; this module reports file, line and rule only.
A passing run writes cache/preflight/<tree-sha256>.ok, which analyze.py requires.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from recon.paths import PathRefused, allowed_roots, list_input_files

LEAK_EXIT_CODE = 7  # distinct from gitleaks' own error code 1
CONTAINER_SCAN_DIR = "/scan"
CONTAINER_CONFIG = "/cfg/gitleaks.toml"
STAMP_DIR = Path("cache") / "preflight"
DEFAULT_CONFIG_REL = Path("containers") / "gitleaks.toml"
DEFAULT_IMAGE_REL = Path("containers") / "gitleaks.image"
PODMAN_ENV = "PODMAN"
GITLEAKS_BIN_ENV = "RECON_GITLEAKS_BIN"


class PreflightError(RuntimeError):
    """gitleaks could not run to completion. Messages never include scanned content."""


@dataclass(frozen=True)
class Hit:
    file: str
    line: int
    rule: str


@dataclass(frozen=True)
class PreflightResult:
    hits: tuple[Hit, ...]
    tree_hash: str
    stamp: Path | None


def default_inputs(root: Path) -> list[Path]:
    return list(allowed_roots(root))


def hash_tree(groups: Sequence[tuple[str, Sequence[tuple[str, bytes]]]]) -> str:
    """sha256 over (dir name, then each file's display name and content sha256). Missing dir = empty group."""
    outer = hashlib.sha256()
    for dir_name, items in sorted(groups, key=lambda g: g[0]):
        outer.update(f"dir:{dir_name}\n".encode())
        for name, data in items:
            outer.update(f"{name}\0{hashlib.sha256(data).hexdigest()}\n".encode())
    return outer.hexdigest()


def read_groups(dirs: Sequence[Path], root: Path) -> list[tuple[str, list[tuple[str, bytes]]]]:
    """Read every input file ONCE; the same bytes are hashed here and (by the runner) sent."""
    groups = []
    for directory in (Path(d) for d in dirs):
        items = [(f.name, f.path.read_bytes()) for f in list_input_files(directory, root)] if directory.exists() else []
        groups.append((directory.name, items))
    return groups


def tree_hash(dirs: Sequence[Path], root: Path) -> str:
    return hash_tree(read_groups(dirs, root))


def stamp_context(root: Path) -> dict | None:
    """Config hash and pinned image of the gitleaks setup in use; None if either file is missing/unpinned."""
    try:
        config = (Path(root) / DEFAULT_CONFIG_REL).read_bytes()
        image = read_image(Path(root) / DEFAULT_IMAGE_REL)
    except (OSError, PreflightError):
        return None
    return {"config_sha256": hashlib.sha256(config).hexdigest(), "image": image}


def _stamp_key(tree_digest: str, ctx: dict) -> str:
    return hashlib.sha256(f"{tree_digest}\0{ctx['config_sha256']}\0{ctx['image']}".encode()).hexdigest()


def stamp_path(root: Path, digest: str) -> Path:
    return Path(root) / STAMP_DIR / f"{digest}.ok"


def stamp_valid(root: Path, tree_digest: str) -> bool:
    """A stamp counts only for this exact tree, gitleaks config and image; its JSON is re-verified."""
    ctx = stamp_context(root)
    if ctx is None:
        return False
    try:
        data = json.loads(stamp_path(root, _stamp_key(tree_digest, ctx)).read_text())
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(data, dict) and data == {"tree_sha256": tree_digest, **ctx}


def has_stamp(root: Path, dirs: Sequence[Path]) -> bool:
    return stamp_valid(root, tree_hash(dirs, root))


def write_stamp(root: Path, digest: str) -> Path:
    ctx = stamp_context(root)
    if ctx is None:
        raise PreflightError("containers/gitleaks.toml or a digest-pinned containers/gitleaks.image is missing")
    path = stamp_path(root, _stamp_key(digest, ctx))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"tree_sha256": digest, **ctx}, indent=2, sort_keys=True) + "\n")
    return path


def read_image(image_file: Path) -> str:
    ref = Path(image_file).read_text().strip()
    if "@sha256:" not in ref:
        raise PreflightError(f"gitleaks image in {image_file} is not pinned by digest")
    return ref


def build_command(directory: Path, config: Path, *, podman: Sequence[str] | None, image: str,
                  gitleaks_bin: str | None) -> list[str]:
    """Container command (podman) or local-binary command (same flags). Input is mounted read-only."""
    flags = ["--no-banner", "--redact", "--report-format", "json", "--report-path", "-",
             "--exit-code", str(LEAK_EXIT_CODE), "--log-level", "error"]
    if podman:
        return [*podman, "run", "--rm", "--network=none",
                "-v", f"{directory}:{CONTAINER_SCAN_DIR}:ro,z",
                "-v", f"{config}:{CONTAINER_CONFIG}:ro,z",
                image, "dir", CONTAINER_SCAN_DIR, "--config", CONTAINER_CONFIG, *flags]
    if gitleaks_bin:
        return [gitleaks_bin, "dir", str(directory), "--config", str(config), *flags]
    raise PreflightError("neither podman nor a gitleaks binary is configured")


def parse_report(stdout: str, scan_prefix: str, label: str) -> tuple[Hit, ...]:
    """Keep only file, line and rule from gitleaks' JSON; secrets and matches are dropped."""
    if not stdout.strip():
        return ()
    try:
        rows = json.loads(stdout)
    except json.JSONDecodeError:
        raise PreflightError("gitleaks produced an unreadable report") from None
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        raise PreflightError("gitleaks produced an unexpected report shape")
    hits = []
    for row in rows:
        file = str(row.get("File", ""))
        rel = file[len(scan_prefix):].lstrip("/") if file.startswith(scan_prefix) else file
        try:
            line = int(row.get("StartLine", 0))
        except (TypeError, ValueError):
            raise PreflightError("gitleaks produced an unexpected report shape") from None
        hits.append(Hit(f"{label}/{rel}", line, str(row.get("RuleID", "?"))))
    return tuple(sorted(hits, key=lambda h: (h.file, h.line, h.rule)))


def _scan_one(directory: Path, config: Path, podman, image, gitleaks_bin, runner) -> tuple[Hit, ...]:
    cmd = build_command(directory, config, podman=podman, image=image, gitleaks_bin=gitleaks_bin)
    proc = runner(cmd, capture_output=True, text=True, check=False)
    if proc.returncode == 0:
        return ()
    if proc.returncode != LEAK_EXIT_CODE:
        raise PreflightError(f"gitleaks failed (exit {proc.returncode})")
    prefix = CONTAINER_SCAN_DIR if podman else str(directory)
    hits = parse_report(proc.stdout, prefix, directory.name)
    if not hits:  # gitleaks said "leaks found" but we cannot name them: never treat as clean
        raise PreflightError("gitleaks reported leaks but the report was empty")
    return hits


def run_preflight(dirs: Sequence[Path], root: Path, *, config: Path, podman: Sequence[str] | None,
                  image: str, gitleaks_bin: str | None,
                  runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> PreflightResult:
    digest = tree_hash(dirs, root)  # also enforces the path allowlist before anything is mounted
    hits: tuple[Hit, ...] = ()
    for directory in dirs:
        if Path(directory).is_dir():
            hits += _scan_one(Path(directory).resolve(), Path(config).resolve(), podman, image, gitleaks_bin, runner)
    if hits:
        return PreflightResult(hits, digest, None)
    return PreflightResult((), digest, write_stamp(root, digest))


def _default_runner() -> Callable[..., subprocess.CompletedProcess]:
    return subprocess.run


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="gitleaks pre-flight over the redacted input set.")
    ap.add_argument("--root", type=Path, default=Path(os.environ.get("RECON_ROOT", ".")))
    ap.add_argument("--input", type=Path, action="append", help="input dir (default: harvest/redacted and unpacked)")
    ap.add_argument("--config", type=Path)
    ap.add_argument("--image-file", type=Path)
    args = ap.parse_args(argv)
    root = args.root.resolve()
    dirs = [d if d.is_absolute() else root / d for d in (args.input or default_inputs(root))]
    config = args.config or root / DEFAULT_CONFIG_REL
    gitleaks_bin = os.environ.get(GITLEAKS_BIN_ENV)
    podman = None if gitleaks_bin else shlex.split(os.environ.get(PODMAN_ENV, "podman"))
    try:
        image = "" if gitleaks_bin else read_image(args.image_file or root / DEFAULT_IMAGE_REL)
        result = run_preflight(dirs, root, config=config, podman=podman, image=image,
                               gitleaks_bin=gitleaks_bin, runner=_default_runner())
    except (PathRefused, PreflightError) as exc:
        print(f"preflight: {exc}", file=sys.stderr)
        return 2
    if result.hits:
        print(f"preflight: ABORT, {len(result.hits)} finding(s) (file:line rule; values never printed)")
        for hit in result.hits:
            print(f"  {hit.file}:{hit.line} {hit.rule}")
        return 1
    print(f"preflight: clean, stamp {result.stamp.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
