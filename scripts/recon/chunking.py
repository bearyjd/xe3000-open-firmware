"""Split inputs by artifact type into line-numbered chunks. Original line numbers survive splitting."""
from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass

DEFAULT_MAX_LINES = 300
WINDOW_RADIUS = 2
NUM_WIDTH = 5

# Ordered: first match wins (so /etc/config/rpcd is a UCI config, not an RPC handler).
_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("har", (".har",)),
    ("hotplug-script", ("/hotplug.d/",)),
    ("init-script", ("/init.d/", "/rc.d/")),
    ("uci-config", ("/etc/config/",)),
    ("dts", (".dts", ".dtsi", ".dtb", "device-tree", "/fdt")),
    ("dmesg", ("dmesg",)),
    ("module-info", ("lsmod", "modinfo", "/lib/modules", "proc/modules")),
    ("rpc-handler", ("rpc", "ubus")),
    ("rootfs-script", (".sh", ".lua", "/usr/bin/", "/usr/sbin/", "/lib/")),
)
OTHER = "other"
# Ground truth is built only from these (not HAR captures or unclassified text, which may carry foreign content).
TRUSTED_TYPES = frozenset({"init-script", "hotplug-script", "uci-config", "dts", "dmesg", "module-info",
                           "rootfs-script", "rpc-handler"})


@dataclass(frozen=True)
class Segment:
    file: str
    start: int  # 1-based line number of lines[0]
    lines: tuple[str, ...]


@dataclass(frozen=True)
class Chunk:
    chunk_id: str
    artifact_type: str
    segments: tuple[Segment, ...]

    @property
    def files(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(s.file for s in self.segments))

    def render(self) -> str:
        parts = []
        for seg in self.segments:
            parts.append(f"=== FILE: {seg.file} ===")
            parts.extend(f"{seg.start + i:>{NUM_WIDTH}}| {line}" for i, line in enumerate(seg.lines))
        return "\n".join(parts)

    def digest(self) -> str:
        return hashlib.sha256(self.render().encode()).hexdigest()

    def window(self, file: str, line: int, radius: int = WINDOW_RADIUS) -> str | None:
        """Text of lines [line-radius, line+radius] clipped to this chunk; None if line is not in the chunk."""
        for seg in self.segments:
            if seg.file == file and seg.start <= line < seg.start + len(seg.lines):
                lo = max(seg.start, line - radius) - seg.start
                hi = min(seg.start + len(seg.lines) - 1, line + radius) - seg.start
                return "\n".join(seg.lines[lo:hi + 1])
        return None


def classify(name: str) -> str:
    lowered = "/" + name.lower()
    for artifact_type, needles in _RULES:
        if any(n in lowered or lowered.endswith(n) for n in needles):
            return artifact_type
    return OTHER


def _segments(name: str, text: str, max_lines: int) -> list[Segment]:
    lines = text.splitlines()
    return [Segment(name, i + 1, tuple(lines[i:i + max_lines])) for i in range(0, len(lines), max_lines)]


def _make(artifact_type: str, segs: Sequence[Segment]) -> Chunk:
    draft = Chunk("", artifact_type, tuple(segs))
    return Chunk(f"{artifact_type}-{draft.digest()[:12]}", artifact_type, tuple(segs))


def chunk_files(files: Sequence[tuple[str, str]], max_lines: int = DEFAULT_MAX_LINES) -> tuple[Chunk, ...]:
    """Group segments of the same artifact type into chunks of at most max_lines lines."""
    by_type: dict[str, list[Segment]] = {}
    for name, text in sorted(files):
        by_type.setdefault(classify(name), []).extend(_segments(name, text, max_lines))
    chunks: list[Chunk] = []
    for artifact_type in sorted(by_type):
        current: list[Segment] = []
        used = 0
        for seg in by_type[artifact_type]:
            if current and used + len(seg.lines) > max_lines:
                chunks.append(_make(artifact_type, current))
                current, used = [], 0
            current.append(seg)
            used += len(seg.lines)
        if current:
            chunks.append(_make(artifact_type, current))
    return tuple(chunks)
