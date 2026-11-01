# Recovery and rollback planning

**PLANNING ONLY — no executable procedure or router/flash authorization.** The production router remains unchanged; the bootloader-untouched rule holds.

GL.iNet's [official debrick documentation](https://docs.gl-inet.com/router/en/4/faq/debrick/) includes XE3000 recovery guidance. This identifies a vendor recovery route, not a tested recovery path for this unit.

The [March 26, 2025 vendor advisory](https://docs.gl-inet.com/router/en/4/faq/problem_notification_for_mt2500_x3000_xe3000/) covers XE3000 startup and U-Boot recovery defects and recommends bootloader and firmware updates. Installed U-Boot status is unknown. A separately approved read-only identification step must establish applicability before recovery is assumed. This project does not authorize either upgrade; the bootloader remains untouched.

Before considering any device change:

1. Identify installed bootloader/firmware and the applicable official recovery path through separately approved read-only evidence collection. Resolve advisory applicability; stop if recovery assumptions remain unverified.
2. Establish actual storage offsets, labels, sizes and restore layout. Captured `/proc/partitions` sizes alone do not establish offsets, disjoint GPT partitions or restore compatibility. Preserve factory calibration, identity and existing boot configuration.
3. Define backup collection scope explicitly, including whether secrets may be collected, where encrypted backups may be stored, access controls and retention. This requires future approval; current recon authorization is not permission to collect arbitrary full-device secrets.
4. Validate backup integrity and a restore layout with independently reviewed evidence and an appropriately isolated restore test. A backup checksum alone does not demonstrate restorability. Identify the exact compatible stock recovery image and its verified provenance without installing it.
5. Prepare exact command/action lists, outage/recovery prerequisites, pass/fail criteria and stop conditions for any future hardware acceptance. Obtain explicit approval before router operations, recovery interaction, rebooting or flashing. No bootloader update is part of this plan.

Local build/recipe work can proceed without device changes. [Curated findings](../findings/index.md) and [upstream gates](../findings/upstream-gap.md) leave modem/SIM, MCU/charging/thermal, calibration/storage and recovery acceptance open. Firmware build success will not close these gates.
