"""Deterministic extractors for AT commands, ubus/RPC methods, GPIO numbers and module names.

These lists are canonical: a claim naming something absent from them is flagged `ungrounded`.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

AT_RE = re.compile(
    r"(?<![A-Za-z0-9_])(AT[+^$!&#%][A-Za-z0-9_]+|AT(?:Z|E[01]|I\d?|V[01]|Q[01]|S\d+)(?![A-Za-z0-9_]))")
UBUS_CALL_RE = re.compile(r"\bubus\s+(?:-\S+\s+)*call\s+([A-Za-z0-9_.\-]+)\s+([A-Za-z0-9_\-]+)")
RPC_PARAMS_RE = re.compile(r'"params"\s*:\s*\[\s*"[^"]*"\s*,\s*"([\w.\-]+)"\s*,\s*"([\w\-]+)"')
GPIO_WORD_RE = re.compile(r"\bgpio[\s_-]*#?(\d+)\b", re.IGNORECASE)
GPIO_SYSFS_RE = re.compile(r"/sys/class/gpio/gpio(\d+)")
GPIO_EXPORT_RE = re.compile(r"echo\s+(\d+)\s*>\s*/sys/class/gpio/export")
GPIO_DTS_RE = re.compile(r"gpios?\s*=\s*<\s*&[\w-]+\s+(\d+)")
MOD_CMD_RE = re.compile(r"\b(?:insmod|modprobe|rmmod|modinfo)\s+(?:-\S+\s+)*([\w./-]+)")
MOD_KO_RE = re.compile(r"([\w-]+)\.ko\b")
LSMOD_RE = re.compile(r"^([\w-]+)\s+\d+\s+\d+", re.MULTILINE)
CLAIM_MODULE_RE = re.compile(r"\bmodules?\s+`([\w-]+)`", re.IGNORECASE)
CLAIM_RPC_BACKTICK_RE = re.compile(r"`([a-z][\w-]*\.[a-z][\w]*)`")
# After "RPC/ubus method": a quoted/backticked name, or a bare name that is clearly an identifier (has . _ or a
# digit). A plain word such as "for" or "that" is prose, not a method.
CLAIM_RPC_PHRASE_RE = re.compile(
    r"\b(?:rpc|ubus)\s+method\s+(?:[`\"']([A-Za-z_][\w.]*)[`\"']|([A-Za-z][A-Za-z]*[._0-9][\w.]*))", re.IGNORECASE)
FILE_EXTENSIONS = frozenset({"sh", "conf", "ko", "json", "lua", "txt", "so", "dts", "dtb", "dtsi", "cfg", "ini",
                             "log", "py", "js", "html", "xml", "yaml", "yml", "bin", "img", "pem", "key", "sock"})
PROSE_STOPWORDS = frozenset({"with", "the", "a", "an", "to", "for", "and", "or", "in", "on", "of", "it", "is",
                             "as", "at", "by", "if", "no", "not", "from", "that", "this"})


@dataclass(frozen=True)
class GroundTruth:
    at_commands: frozenset[str] = frozenset()
    rpc_methods: frozenset[str] = frozenset()
    gpios: frozenset[int] = frozenset()
    modules: frozenset[str] = frozenset()


def _module_name(raw: str) -> str:
    name = raw.rsplit("/", 1)[-1]
    if name.endswith(".ko"):
        name = name[:-3]
    return name.replace("-", "_")


def _at(text: str) -> frozenset[str]:
    return frozenset(m.group(1).upper() for m in AT_RE.finditer(text))


def _rpc(text: str) -> frozenset[str]:
    names: set[str] = set()
    for rx in (UBUS_CALL_RE, RPC_PARAMS_RE):
        for obj, method in (m.groups() for m in rx.finditer(text)):
            names.update({obj, method, f"{obj}.{method}"})
    return frozenset(names)


def _gpios(text: str) -> frozenset[int]:
    return frozenset(int(m.group(1)) for rx in (GPIO_WORD_RE, GPIO_SYSFS_RE, GPIO_EXPORT_RE, GPIO_DTS_RE)
                     for m in rx.finditer(text))


def _modules(text: str, *, lsmod: bool = True) -> frozenset[str]:
    """lsmod=True is file mode (insmod/modprobe/lsmod lines); False is claim prose, where only .ko and
    backticked names count, because 'insmod with ...' in a sentence is not a module."""
    found = {_module_name(m.group(1)) for m in MOD_KO_RE.finditer(text)}
    if lsmod:
        found |= {_module_name(m.group(1)) for m in MOD_CMD_RE.finditer(text)
                  if m.group(1).lower() not in PROSE_STOPWORDS}
        found |= {_module_name(m.group(1)) for m in LSMOD_RE.finditer(text) if m.group(1).lower() != "module"}
    return frozenset(found)


def extract(files: Mapping[str, str]) -> GroundTruth:
    """Union of every extractor over all files of the input set."""
    blob = "\n".join(files.values())
    return GroundTruth(_at(blob), _rpc(blob), _gpios(blob), _modules(blob))


def mentions(claim: str) -> GroundTruth:
    """What a claim asserts, using the same extractors plus backticked module names."""
    modules = _modules(claim, lsmod=False) | {_module_name(m.group(1)) for m in CLAIM_MODULE_RE.finditer(claim)}
    rpc = set(_rpc(claim))
    rpc |= {m.group(1) for m in CLAIM_RPC_BACKTICK_RE.finditer(claim) if m.group(1).rsplit(".", 1)[1] not in FILE_EXTENSIONS}
    rpc |= {m.group(1) or m.group(2) for m in CLAIM_RPC_PHRASE_RE.finditer(claim)}
    return GroundTruth(_at(claim), frozenset(rpc), _gpios(claim), frozenset(modules - {"ko"}))


def ungrounded_reasons(claim: str, truth: GroundTruth) -> list[str]:
    said = mentions(claim)
    reasons = [f"AT command {c} not in ground truth" for c in sorted(said.at_commands - truth.at_commands)]
    reasons += [f"GPIO {g} not in ground truth" for g in sorted(said.gpios - truth.gpios)]
    reasons += [f"RPC method {r} not in ground truth" for r in sorted(said.rpc_methods - truth.rpc_methods)]
    reasons += [f"module {m} not in ground truth" for m in sorted(said.modules - truth.modules)]
    return reasons
