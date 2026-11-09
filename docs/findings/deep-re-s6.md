# Deep reverse-engineering pass (S6): disassembly of 25 vendor binaries

**Model-derived, unverified.** These are bounded readings of strings and function outlines from static disassembly, produced by an LLM and filtered by the repository's grounding checks. They are not observed device behavior, and no GL.iNet binary or disassembly is stored in this repository (the disassembly stays in a gitignored local folder). Hardware, recovery and production gates are unchanged.

## Method and limits

- `scripts/decompile.sh` ran pinned `radare2` read-only (no execution, no network, firmware mounted read-only) over at most 25 programs from the stock 4.8.3 rootfs: modem tools, MCU/fan helpers, the RPC front ends and six kernel modules. Output is capped per program; `mt_wifi.ko` hit the read limit and is truncated.
- The pre-flight scan initially aborted with 128 hits. Every hit type sampled was a false positive (runtime string tables, format strings, the tool's own hash header, XML templates). The gate was not bypassed: flagged lines were masked in a new review root, re-verified, and re-scanned clean.
- Cheap-tier triage (five topics) covered all 25 files; a stronger model then re-read each topic's top 8 files only (17 distinct files). Earlier-analyzed content was not resubmitted. Spend: $1.88 triage plus $19.42 second pass, $21.31 total, under the approved $50.
- Counts: triage 1,964 accepted and 1,555 rejected; second pass 1,800 accepted and 449 rejected. Disassembly shows strings and structure, not call flow, so ordering and reply handling are mostly invisible.

## What the readings say

- **`QFirehose`** is a Quectel firmware-upgrade tool (Sahara/Firehose), built from a GL.iNet modem SDK tree. It finds the module through `/sys/bus/usb/devices` and the `ttyUSB` ports, can capture USB traffic via `usbmon`, and its `-e` option erases everything before download; its help text warns this erases calibration data.
- **AT command strings** appear in `qcm`, `at_cache`, `sms_manager` and `modem_AT`, for example Quectel config queries (`AT+QCFG` with `nwscanmode`, `usbnet`, `pcie/mode`), network-device control (`AT+QNETDEVCTL`, `AT+QNETDEVSTATUS`), cell and operator queries (`AT+QCAINFO`, `AT+COPS`, `AT+QENG`), and SIM/registration queries (`AT+CPIN?`, `AT+CREG`, `AT^ICCID?`). The text shows the strings, not when or in what order they are sent.
- **`mcu_update`** drives the MCU over a raw serial port (default 9600 baud in its usage text), guards access with `/tmp/mcu.lock`, and uses transmit/receive helpers with timeouts. Its usage text shows a default device path that differs from the `ttyS1` line seen on this unit; that is a default, not evidence.
- **`gl-sdk4-hw-info.ko`** reads a factory data file (`/lib/firmware/sn.data`); the text does not tie it to Wi-Fi calibration. **`gpio-button-hotplug.ko`** handles GPIO buttons only.

## What was not found

No AT command sequences or reply handling, no MCU protocol or message format, no charging logic, and no ubus or RPC method table beyond string fragments. Closing those gaps needs runtime evidence, which requires separately approved router access; nothing here authorizes any.

The full results stay local in a gitignored review root and the paid runs are complete; do not resubmit them.
