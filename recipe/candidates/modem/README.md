# Offline Quectel MHI profile candidate

This additive fragment and exact public patch were compiled in a separate
[candidate firmware build](../../../docs/evidence/firmware-candidate-20261101.json).
The independent audit verified resolved configuration, the actual patched kernel
source and named MHI modules in the image. The accepted r3 baseline and three-line
source seed remain unchanged; the candidate retains XE3000 USB/QMI packages.
Protocol mode, runtime matching, port ownership and XE3000 battery behavior
remain unverified. The source checker below retains its narrower offline scope.

Linux 6.12.112 already matches Qualcomm 17cb:0308 through its generic SDX65 entry.
The patch adds subsystem 17cb:5201 before that fallback and selects the existing
Quectel RM5xx profile. That profile selects `modem_quectel_em1xx_config`, whose
hardware channels are named `IP_HW0_MBIM`; `mhi_wwan_mbim` consumes that channel.
The offline checker follows those actual source declarations and records field
differences, including wake behavior and channel configuration. It does not
compile C or prove runtime matching. The generic profile instead uses `IP_HW0`.

No modem AT/UCI writes, protocol changes, hotplug scripts, MCU model choices or
firmware binaries are included. Captured stock MBIM=0/qmap=1 remains unresolved.
The external PM commit 4087faad55849b7891008482fe0d8beae81714b8 is excluded;
`pcie_port_pm=off` is not a default. Its effect on the battery-powered XE3000
requires separate evaluation and any hardware commands require exact approval.

Attribution: Marcello Barnaba, vjt/openwrt-glinet-x3000, commit
8cc71da72ac6dcc651c93e6a4c10351d56006fd8, 2026-04-28. The patch is copied byte
for byte from the pinned raw URL in provenance.json. Its upstream commit message
claims a previously unmatched device; our exact-source inspection instead shows
the existing generic SDX65 match. X3000 author reports do not establish XE3000
compatibility. The patch has no separate license header; the affected kernel
source declares GPL-2.0-or-later. This records context, not an independent license
grant. Retain attribution and confirm licensing before redistribution.

The small deterministic tests/linux-6.12.112-public-sources.txz fixture contains
the two exact public kernel C files and the kernel's GPL-2.0 license text and
Linux-syscall-note. Both C files carry GPL-2.0-or-later SPDX headers and their
original copyright notices. This source subset is used only by tests; production
CLI requires the full pristine archive hash and compares both members exactly.

Run `python scripts/check_modem_candidate.py --kernel-source PATH --kernel-archive
PATH --out NEW_DIRECTORY` with the pristine source root and full archive. Only two
verified public C files are copied, and git apply check/application run in the new
workspace. Inputs are never modified. The resulting proposal.json explicitly
keeps defconfig, firmware build and hardware flags false. No private files,
network access, router communication or signing keys are needed.
