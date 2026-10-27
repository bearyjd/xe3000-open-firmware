"""One shared system prompt plus a per-artifact-type task prompt. PROMPT_VERSION is part of the cache key."""
from __future__ import annotations

import hashlib

from recon.chunking import OTHER
from recon.schema import CATEGORIES

PROMPT_VERSION = "1"
SYNTHESIS_VERSION = "1"

SYSTEM_SHARED = (
    "You analyse redacted artifacts from the stock firmware of a GL.iNet GL-XE3000 router to find behaviour "
    "that upstream OpenWrt does not provide (modem power and boot flow, SIM selection, battery/MCU, fan, LEDs, "
    "GPIO, vendor RPC). Rules:\n"
    "1. Report only what the text shows. Never infer values that are not written in the input.\n"
    "2. Every finding needs at least one evidence item: the file name exactly as given in the '=== FILE:' header, "
    "the line number from the left margin, and a verbatim excerpt of that line or the lines next to it.\n"
    "3. AT commands, GPIO numbers, ubus/RPC method names and kernel module names may only be mentioned in a claim "
    "if they appear literally in the input.\n"
    "4. Values shown as <REDACTED:...> were removed on purpose; do not guess them.\n"
    "5. Describe behaviour only. Do not reproduce proprietary code beyond the short evidence excerpt.\n"
    f"Allowed categories: {', '.join(CATEGORIES)}. Confidence is high only when the text states the behaviour directly."
)

_TASKS: dict[str, str] = {
    "init-script": "Task: procd/init scripts. Find what they start, stop, load or configure at boot, especially modem, GPIO, fan and MCU handling.",
    "hotplug-script": "Task: hotplug scripts. Find which events trigger which actions, especially network, modem and SIM changes.",
    "uci-config": "Task: UCI configuration. Find vendor-specific sections and options that control modem, SIM, fan, LED, network and cloud behaviour.",
    "dts": "Task: device tree text. Find GPIO assignments, fan/LED/button nodes, PCIe/modem power and regulator wiring.",
    "dmesg": "Task: kernel log. Find driver probes, modem enumeration order, firmware loads and errors that matter for porting.",
    "module-info": "Task: kernel module lists and metadata. Find vendor or out-of-tree modules and their parameters.",
    "rpc-handler": "Task: RPC/ubus handlers. Find method names, parameters and what hardware or service each method drives.",
    "rootfs-script": "Task: rootfs scripts. Find hardware control paths: modem, SIM, GPIO, fan, LED, battery/MCU.",
    "har": "Task: captured web UI traffic. Find the RPC methods the vendor UI calls and what they control.",
    OTHER: "Task: unclassified text. Report only clearly hardware-relevant behaviour.",
}


def task_prompt(artifact_type: str) -> str:
    return _TASKS.get(artifact_type, _TASKS[OTHER])


def system_blocks(artifact_type: str) -> tuple[str, str]:
    """(shared system prompt, per-task instructions). The client puts cache_control on the last block."""
    return SYSTEM_SHARED, task_prompt(artifact_type)


def prompt_hash(artifact_type: str) -> str:
    """Hash of the full prompt text sent for this artifact type (part of the cache key)."""
    return hashlib.sha256("\0".join(system_blocks(artifact_type)).encode()).hexdigest()


def user_message(chunk_text: str, feedback: str | None = None) -> str:
    if not feedback:
        return chunk_text
    return (f"{chunk_text}\n\nYour previous answer contained rejected findings:\n{feedback}\n"
            "Return corrected findings. Quote evidence verbatim from the numbered lines above.")


SYNTHESIS_SYSTEM = (
    "You write a gap report for porting upstream OpenWrt to the GL.iNet GL-XE3000. Input is a JSON list of "
    "verified findings (each with evidence). Group them by subsystem, state what stock firmware does that "
    "upstream does not, mark findings flagged ungrounded as unverified, and cite finding indexes. Do not add facts."
)
