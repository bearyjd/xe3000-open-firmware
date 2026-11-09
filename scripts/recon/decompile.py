"""Bounded disassembly of vendor binaries with radare2, run inside the decompile container (scripts/decompile.sh).

Reads ELF files from a mounted rootfs (read-only), writes annotated text (strings, imports, function index, the most
informative function bodies) to an output directory. Nothing from the firmware is executed: r2 is started in its default
read-only static mode, never with -w, -d or -D. Output per binary is capped; the list of binaries is capped at 25.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

from recon.redact import _is_excluded as is_excluded

MAX_BINARIES = 25
DEFAULT_MAX_BYTES = 200_000
DEFAULT_TIMEOUT = 300.0
READ_LIMIT = 32 * 1024 * 1024
ELF_MAGIC = b"\x7fELF"
EXIT_OK, EXIT_FAILED = 0, 2
R2_COMMANDS = ("aaa; ?e ===SECTION strings; izz; ?e ===SECTION imports; ii; ?e ===SECTION functions; afl; "
               "?e ===SECTION disassembly; pdf @@f")
R2_FLAGS = ("-q", "-e", "scr.color=0", "-e", "scr.utf8=false", "-e", "asm.bytes=false", "-e", "bin.relocs.apply=true",
            "-e", "log.level=0")
# Fractions of the byte budget for the sections ahead of the disassembly.
SECTION_SHARE = {"strings": 0.30, "imports": 0.05, "functions": 0.10}
INTERESTING_STRING = re.compile(r"AT[+^$!&#%]|/sys/|/dev/|/proc/|gpio|ubus|uci|tty|mcu|fan|led|modem|sim|power|reset|qmi|mbim",
                                re.IGNORECASE)
INTERESTING_CALL = re.compile(r"\b(open|ioctl|write|ubus_|uci_|gpio|tty|serial|system|popen|sysfs|termios)\w*", re.IGNORECASE)
STRING_COMMENT = re.compile(r'; .*"[^"]{2,}"')
HEADER_RE = re.compile(r"^[/┌] \d+: ")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
SECTION_RE = re.compile(r"^(?:===SECTION |## )(\w+)\s*$")


class DecompileError(ValueError):
    """A target list or option that must not be used."""


def parse_targets(text: str) -> tuple[str, ...]:
    names: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("/")
        if line.startswith("/") or ".." in parts or "\0" in line or any(c in line for c in "*?[]"):
            raise DecompileError(f"unsafe target name: {line!r}")
        if is_excluded(Path(line)):
            raise DecompileError(f"target is on the exclusion list (secrets/keys): {line!r}")
        if line in names:
            raise DecompileError(f"duplicate target: {line!r}")
        names.append(line)
    if len(names) > MAX_BINARIES:
        raise DecompileError(f"at most {MAX_BINARIES} binaries per run, got {len(names)}")
    return tuple(names)


def output_name(rel: str) -> str:
    return rel.strip("/").replace("/", "_") + ".r2.txt"


def _run_r2(r2: str, binary: Path, timeout: float, read_limit: int) -> tuple[str, str, int | None]:
    """(stdout text, status ok|timeout|read-limit, exit code). The child is killed when it hits a limit."""
    proc = subprocess.Popen([r2, *R2_FLAGS, "-c", R2_COMMANDS, str(binary)], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, start_new_session=True)
    chunks: list[bytes] = []
    size, status, deadline = 0, "ok", time.monotonic() + timeout
    fd = proc.stdout.fileno()
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            status = "timeout"
            break
        ready, _, _ = select.select([fd], [], [], min(left, 1.0))
        if not ready:
            continue
        data = os.read(fd, 65536)
        if not data:
            break
        chunks.append(data)
        size += len(data)
        if size >= read_limit:
            status = "read-limit"
            break
    if status != "ok":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    code = proc.wait()
    proc.stdout.close()
    return b"".join(chunks).decode("utf-8", errors="replace"), status, code


def _sections(raw: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    current = None
    for line in ANSI_RE.sub("", raw).splitlines():
        m = SECTION_RE.match(line)
        if m:
            current = out.setdefault(m.group(1), [])
        elif current is not None:
            current.append(line.rstrip())
    return out


def _take(lines: list[str], budget: int) -> tuple[list[str], bool]:
    kept, used = [], 0
    for line in lines:
        cost = len(line.encode()) + 1
        if used + cost > budget:
            return kept, True
        kept.append(line)
        used += cost
    return kept, False


def _prioritise_strings(lines: list[str]) -> list[str]:
    body = [ln for ln in lines if ln.strip() and not ln.lstrip().startswith(("nth ", "―", "-"))]
    first = [ln for ln in body if INTERESTING_STRING.search(ln)]
    return [*first, *(ln for ln in body if not INTERESTING_STRING.search(ln))]


def _blocks(lines: list[str]) -> list[list[str]]:
    """Split pdf output into function blocks; xref comment lines directly above a header join that function."""
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if HEADER_RE.match(line):
            carry: list[str] = []
            while current and current[-1].lstrip().startswith(";"):
                carry.insert(0, current.pop())
            if current:
                blocks.append(current)
            current = [*carry, line]
        else:
            current.append(line)
    if current:
        blocks.append(current)
    return blocks


def _score(block: list[str]) -> int:
    return sum(2 if STRING_COMMENT.search(ln) else 0 for ln in block) + sum(1 for ln in block if INTERESTING_CALL.search(ln))


def _select_blocks(lines: list[str], budget: int) -> tuple[list[str], bool]:
    blocks = [b for b in _blocks(lines) if not any(HEADER_RE.match(ln) and "sym.imp." in ln for ln in b)]
    order = sorted(range(len(blocks)), key=lambda i: (-_score(blocks[i]), i))
    chosen, used, cut = set(), 0, False
    for i in order:
        size = sum(len(ln.encode()) + 1 for ln in blocks[i])
        if used + size > budget:
            cut = True
            continue
        chosen.add(i)
        used += size
    kept = [ln for i in sorted(chosen) for ln in blocks[i]]
    if not kept and blocks:  # one oversized function: keep its head rather than nothing
        kept, _ = _take(blocks[0], budget)
    return kept, cut


def build_text(rel: str, sha: str, raw: str, status: str, max_bytes: int, timeout: float) -> str:
    sections = _sections(raw)
    out = [f"; decompiled text of {rel} (radare2 static analysis; nothing was executed)", f"; sha256 {sha}"]
    truncated = status == "read-limit"
    used = sum(len(ln.encode()) + 1 for ln in out) + 64  # reserve room for the closing marker
    for name in ("strings", "imports", "functions"):
        lines = sections.get(name, [])
        lines = _prioritise_strings(lines) if name == "strings" else [ln for ln in lines if ln.strip()]
        kept, cut = _take(lines, min(int(max_bytes * SECTION_SHARE[name]), max_bytes - used))
        truncated = truncated or cut
        out += [f"## {name}", *kept]
        used += sum(len(ln.encode()) + 1 for ln in kept) + len(name) + 4
    out.append("## disassembly")
    used += 16
    kept, cut = _select_blocks(sections.get("disassembly", []), max(0, max_bytes - used))
    truncated = truncated or cut
    out += kept
    if status == "timeout":
        out.append(f"; TIMED OUT after {timeout:g}s")
    if truncated:
        out.append(f"; TRUNCATED at {max_bytes} bytes")
    return "\n".join(out) + "\n"


def _resolve(rootfs: Path, rel: str) -> tuple[Path | None, str | None]:
    path = rootfs / rel
    if not path.exists():
        return None, "not found"
    real = path.resolve()
    if not real.is_relative_to(rootfs.resolve()):
        return None, "escapes the rootfs"
    if not real.is_file():
        return None, "not a regular file"
    with real.open("rb") as fh:
        if fh.read(4) != ELF_MAGIC:
            return None, "not an ELF file"
    return real, None


def decompile_all(rootfs: Path, targets: tuple[str, ...], out_dir: Path, r2: str, max_bytes: int, timeout: float,
                  read_limit: int = READ_LIMIT, say=print) -> int:
    done = 0
    for rel in targets:
        real, why = _resolve(rootfs, rel)
        if real is None:
            say(f"skipped {rel} ({why})")
            continue
        raw, status, code = _run_r2(r2, real, timeout, read_limit)
        if status == "ok" and code != 0:
            say(f"failed {rel} (r2 exit {code})")
            continue
        sha = hashlib.sha256(real.read_bytes()).hexdigest()
        out_dir.mkdir(parents=True, exist_ok=True)
        text = build_text(rel, sha, raw, status, max_bytes, timeout)
        (out_dir / output_name(rel)).write_text(text)
        done += 1
        say(f"decompiled {rel} -> {output_name(rel)} ({len(text.encode())} bytes, r2 {status})")
    say(f"decompiled {done} of {len(targets)} targets")
    return done


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Bounded radare2 disassembly of a listed set of binaries.")
    ap.add_argument("--rootfs", required=True, type=Path)
    ap.add_argument("--targets", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--r2", default="r2")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--read-limit", type=int, default=READ_LIMIT)
    args = ap.parse_args(argv)
    try:
        targets = parse_targets(args.targets.read_text())
    except (DecompileError, OSError) as exc:
        print(f"decompile: refused: {exc}", file=sys.stderr)
        return EXIT_FAILED
    done = decompile_all(args.rootfs, targets, args.out, args.r2, args.max_bytes, args.timeout, args.read_limit)
    return EXIT_OK if done else EXIT_FAILED
