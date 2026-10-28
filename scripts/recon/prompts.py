"""One shared system prompt plus a per-artifact-type task prompt. PROMPT_VERSION is part of the cache key."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

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


@dataclass(frozen=True)
class Topic:
    """A Phase 2 topic run: extra focus text plus the globs (same syntax as the allowlist) that narrow the inputs.
    The allowlist still decides what may be sent; a topic can only select a subset of it."""
    focus: str
    globs: tuple[str, ...]


_ANTI_INVENT = (" Name only AT commands, GPIO numbers, ubus/RPC methods and module names that appear literally in "
                "the input, and keep every claim under 300 characters.")
_ROOTFS_SCRIPTS = ("**/etc/init.d/*", "**/etc/rc.d/*", "**/etc/hotplug.d/**", "**/usr/sbin/*", "**/usr/lib/lua/**")

TOPICS: dict[str, Topic] = {
    "at-commands": Topic(
        "Topic at-commands: list every AT command the stock firmware sends to the modem, which script or program "
        "sends it, in what order, and what the surrounding code does with the reply (retries, timeouts, port used)."
        + _ANTI_INVENT,
        (*_ROOTFS_SCRIPTS, "**/etc/config/glmodem", "**/etc/modules.d/*", "**/modem/**")),
    "gl-rpc-map": Topic(
        "Topic gl-rpc-map: map the vendor RPC/ubus surface: object, method, parameters, and the service or hardware "
        "each method drives, plus which rpcd ACL grants it. Include a section on network access control methods: "
        "client lists, blocking or allowing a client, black/white lists, parental control and schedules; say which "
        "UCI config each one reads or writes." + _ANTI_INVENT,
        ("**/usr/lib/oui-httpd/**", "**/usr/lib/lua/**", "**/usr/share/acl.d/*.json", "**/usr/share/rpcd/acl.d/*.json",
         "**/etc/config/parental_control", "**/etc/config/gl_block", "**/etc/config/gl-black_white_list",
         "**/etc/config/gl_timer", "ubus/list*", "ubus-list*")),
    "modem-boot-flow": Topic(
        "Topic modem-boot-flow: reconstruct the order in which the modem is powered, enumerated, configured and "
        "brought up at boot and on SIM or network events: init.d START/STOP order, hotplug triggers, GPIO power "
        "and reset lines, module loads, and which step waits on which." + _ANTI_INVENT,
        (*_ROOTFS_SCRIPTS, "**/etc/config/glmodem", "**/etc/modules.d/*", "**/var/dmesg*", "**/dmesg*",
         "**/modem/**", "**/proc/modules")),
    "fan-led-mcu-battery": Topic(
        "Topic fan-led-mcu-battery: find how the fan, LEDs, the MCU link and battery or power monitoring are "
        "controlled: sysfs paths, GPIO or serial protocol, thresholds, and which daemon or RPC method owns each."
        + _ANTI_INVENT,
        (*_ROOTFS_SCRIPTS, "**/usr/lib/oui-httpd/**", "**/etc/config/glfan", "**/etc/config/gl_led",
         "**/etc/config/mcu", "**/etc/config/switch-button", "**/etc/config/board_special", "**/*.dts", "**/*.dtsi")),
    "wifi-driver": Topic(
        "Topic wifi-driver: find Wi-Fi driver and firmware handling: module names and load order, EEPROM or "
        "calibration data sources, hotplug and wifi detect scripts, and vendor changes to wireless bring-up."
        + _ANTI_INVENT,
        ("**/etc/init.d/*", "**/etc/hotplug.d/**", "**/lib/wifi/*", "**/etc/modules.d/*", "**/var/dmesg*",
         "**/dmesg*", "**/proc/modules", "**/usr/lib/lua/**")),
}


def topic_names() -> tuple[str, ...]:
    return tuple(TOPICS)


def _topic(topic: str | None) -> Topic | None:
    if topic is None:
        return None
    if topic not in TOPICS:
        raise ValueError(f"unknown topic {topic!r}; choose one of {', '.join(TOPICS)}")
    return TOPICS[topic]


def task_prompt(artifact_type: str) -> str:
    return _TASKS.get(artifact_type, _TASKS[OTHER])


def system_blocks(artifact_type: str, topic: str | None = None) -> tuple[str, str]:
    """(shared system prompt, per-task instructions). The client puts cache_control on the last block."""
    chosen = _topic(topic)
    task = task_prompt(artifact_type)
    return SYSTEM_SHARED, task if chosen is None else f"{task}\n{chosen.focus}"


def prompt_hash(artifact_type: str, topic: str | None = None) -> str:
    """Hash of the full prompt text sent for this artifact type and topic (part of the cache key)."""
    return hashlib.sha256("\0".join(system_blocks(artifact_type, topic)).encode()).hexdigest()


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
