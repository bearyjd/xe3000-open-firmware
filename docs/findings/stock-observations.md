# Preliminary stock observations

Links into `build/`, `findings/raw/` or `/tmp/` refer to local evidence only; those files are not hosted in this repository. Local `build/openwrt` references describe the inspected checkout and any explicitly identified experiments, not a published upstream source snapshot.

These are independently reviewed **local static/captured evidence** observations from the prepared inputs, inspected 2026-10-31. They are separate from the six completed paid S5/S6 extraction runs, whose partial coverage and curated interpretations are recorded in the [findings index](index.md) and [summary](summary.md). These independent observations do not establish paid-run coverage, verified runtime behavior or hardware acceptance. No artifact was executed or router command issued for this inspection. Findings summarize references without reproducing proprietary code.

The evidence links point to local, ignored prepared files. Confidence is high for the cited captured values or source references only. Source guards, branch applicability and device behavior remain bounded as described. Local inspection of `usr/bin/mcu` does not imply its inclusion in paid batches; no API allowlist was widened.

## 1. Captured PCI identity

The captured values are vendor/device `17cb:0308`, subsystem `17cb:5201`, with a driver link naming `mhi_q`. This confirms captured identity only. Upstream channel compatibility, driver equivalence and need for the experimental match patch remain unknown.

Evidence: [sys%bus%pci%devices%0001:01:00.0%vendor:1](../../build/review-20261031/harvest/redacted/hw/sys%25bus%25pci%25devices%250001%3A01%3A00.0%25vendor#L1), [sys%bus%pci%devices%0001:01:00.0%device:1](../../build/review-20261031/harvest/redacted/hw/sys%25bus%25pci%25devices%250001%3A01%3A00.0%25device#L1), [sys%bus%pci%devices%0001:01:00.0%subsystem_vendor:1](../../build/review-20261031/harvest/redacted/hw/sys%25bus%25pci%25devices%250001%3A01%3A00.0%25subsystem_vendor#L1), [sys%bus%pci%devices%0001:01:00.0%subsystem_device:1](../../build/review-20261031/harvest/redacted/hw/sys%25bus%25pci%25devices%250001%3A01%3A00.0%25subsystem_device#L1), [sys%bus%pci%devices%0001:01:00.0%driver.link:1](../../build/review-20261031/harvest/redacted/hw/sys%25bus%25pci%25devices%250001%3A01%3A00.0%25driver.link#L1).

## 2. Captured MHI settings

The snapshot lists `pcie_mhi`, with `mhi_mbim_enabled=0` and `qmap_mode=1`. Vendor driver/settings are distinct evidence from upstream MHI support. They do not establish a working data connection.

Evidence: [cmd%lsmod:133](../../build/review-20261031/harvest/redacted/kernel/cmd%25lsmod#L133), [sys%module%pcie_mhi%parameters%mhi_mbim_enabled:1](../../build/review-20261031/harvest/redacted/kernel/sys%25module%25pcie_mhi%25parameters%25mhi_mbim_enabled#L1), [sys%module%pcie_mhi%parameters%qmap_mode:1](../../build/review-20261031/harvest/redacted/kernel/sys%25module%25pcie_mhi%25parameters%25qmap_mode#L1).

## 3. Modem service declarations

Initialization declares START=19, a modem AT helper launch and a five-second delayed initialization call. Management declares START=99 and an XE3000 branch. Masked guards leave actual execution unknown; power/reset sequencing and successful service startup are unverified.

Evidence: [etc%init.d%modem-init:4](../../build/review-20261031/harvest/redacted/sys/etc%25init.d%25modem-init#L4), [etc%init.d%modem-init:36](../../build/review-20261031/harvest/redacted/sys/etc%25init.d%25modem-init#L36), [etc%init.d%modem:5](../../build/review-20261031/harvest/redacted/sys/etc%25init.d%25modem#L5), [etc%init.d%modem:12](../../build/review-20261031/harvest/redacted/sys/etc%25init.d%25modem#L12).

## 4. SIM selection reference

Source defines an AT wrapper and queries/sets the slot using `AT+QUIMSLOT`, with retries and two-second waits. No command was issued here. Actual acknowledgements, invocation and physical SIM routing remain unverified.

Evidence: [switch_sim_slot:584](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/usr/bin/switch_sim_slot#L584), [switch_sim_slot:684](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/usr/bin/switch_sim_slot#L684).

## 5. MCU service and UART selection

The service declares START=49 and respawn. Source obtains device/rate defaults from hardware information and prefers configured/discovered values before a `/dev/ttyUSB0`, 9600 fallback. Fallback values are not confirmed XE3000 UART settings; active configuration applicability is unknown.

Evidence: [etc%init.d%mcu:4](../../build/review-20261031/harvest/redacted/sys/etc%25init.d%25mcu#L4), [gl_util.sh:1926](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/lib/functions/gl_util.sh#L1926), [mcu:1194](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/usr/bin/mcu#L1194).

## 6. MCU protocol candidates

Source contains serial formatting and acknowledgement parsing for battery-related fields, plus a battery sysfs path. Periodic monitoring calls occur inside an OLED-flag branch. Applicable XE3000 branch remains unknown. These candidates do not establish its MCU framing, battery transport, charging control or failure policy.

Evidence: [mcu:280](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/usr/bin/mcu#L280), [mcu:684](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/usr/bin/mcu#L684), [mcu:1252](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/usr/bin/mcu#L1252), [mcu:793](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/usr/bin/mcu#L793).

## 7. Fan settings and service

Captured config records enabled=1, temperature=75, warning temperature=75 and divisor=1000. Service source maps configuration to daemon arguments, respawns and references cooling-state clearing on stop; XE3000 divisor defaults also occur in source. The temperature source is masked. Numeric 75 values are configuration values, not verified Celsius thresholds or demonstrated control/fail-safe behavior.

Evidence: [etc%config%glfan:3](../../build/review-20261031/harvest/redacted/config/etc%25config%25glfan#L3), [etc%init.d%gl_fan:9](../../build/review-20261031/harvest/redacted/sys/etc%25init.d%25gl_fan#L9), [etc%init.d%gl_fan:40](../../build/review-20261031/harvest/redacted/sys/etc%25init.d%25gl_fan#L40), [gl_util.sh:1754](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/lib/functions/gl_util.sh#L1754).

## 8. Wi-Fi and calibration references

Profile source identifies MT7981, two MediaTek profiles, mtwifi initialization and ra0/rax0 naming. Preinit source references calibration extraction from MTD or a factory-labelled partition. Masked fields/offsets prevent establishing calibration layout or equivalence with upstream handling. Execution is unproven.

Evidence: [l1profile.dat:2](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/etc/wireless/l1profile.dat#L2), [82_1_wifi_e2p:13](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/lib/preinit/82_1_wifi_e2p#L13).

## 9. Captured storage sizes

The captured table reports mmcblk0 with 7,634,944 blocks and p1–p8; p6 reports 32,768, p7 7,591,424 and p8 7,531,648 blocks. Reported sizes provide no offsets, labels, partition-table semantics or overlap determination. Do not infer ordinary disjoint GPT partitions or recovery suitability.

Evidence: [proc%partitions:3](../../build/review-20261031/harvest/redacted/ident/proc%25partitions#L3).

## 10. Boot and upgrade references

Captured boot arguments reference a root partition label, root waiting, squashfs/f2fs candidates and block2mtd mapping of mmcblk0p1. Upgrade source selects an MMC helper and tar-magic checks for its emmc board-name branch. Actual branch selection, bootloader behavior, accepted image compatibility, rollback integrity and working recovery remain unverified.

Evidence: [proc%cmdline:1](../../build/review-20261031/harvest/redacted/ident/proc%25cmdline#L1), [platform.sh:6](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/lib/upgrade/platform.sh#L6), [platform.sh:27](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/lib/upgrade/platform.sh#L27).

These observations guide experimental baseline decisions: package/transport selection, scoped PCI experiments, MCU/fan implementation boundaries and storage/calibration preservation. They do not justify production readiness or close the hardware gates in the [upstream assessment](upstream-gap.md).
