# Recovery and rollback planning

**PLANNING ONLY — no executable procedure or router/flash authorization.** The production router remains unchanged; the bootloader-untouched rule holds.

GL.iNet's [official debrick documentation](https://docs.gl-inet.com/router/en/4/faq/debrick/) includes XE3000 recovery guidance. This identifies a vendor recovery route, not a tested recovery path for this unit.

The [March 26, 2025 vendor advisory](https://docs.gl-inet.com/router/en/4/faq/problem_notification_for_mt2500_x3000_xe3000/) covers XE3000 startup and U-Boot recovery defects and recommends bootloader and firmware updates. Installed U-Boot was identified on 2026-11-07 (see below): its build string matches the advisory's recommended XE3000 build, so the advisory's bootloader update does not appear to apply; recovery is still untested. This project does not authorize either upgrade; the bootloader remains untouched.

Before considering any device change:

1. Identify installed bootloader/firmware and the applicable official recovery path through separately approved read-only evidence collection. Resolve advisory applicability; stop if recovery assumptions remain unverified.
2. Establish actual storage offsets, labels, sizes and restore layout. Captured `/proc/partitions` sizes alone do not establish offsets, disjoint GPT partitions or restore compatibility. Preserve factory calibration, identity and existing boot configuration.
3. Define backup collection scope explicitly, including whether secrets may be collected, where encrypted backups may be stored, access controls and retention. This requires future approval; current recon authorization is not permission to collect arbitrary full-device secrets.
4. Validate backup integrity and a restore layout with independently reviewed evidence and an appropriately isolated restore test. A backup checksum alone does not demonstrate restorability. Identify the exact compatible stock recovery image and its verified provenance without installing it.
5. Prepare exact command/action lists, outage/recovery prerequisites, pass/fail criteria and stop conditions for any future hardware acceptance. Obtain explicit approval before router operations, recovery interaction, rebooting or flashing. No bootloader update is part of this plan.

Local build/recipe work can proceed without device changes. [Curated findings](../findings/index.md) and [upstream gates](../findings/upstream-gap.md) leave modem/SIM, MCU/charging/thermal, calibration/storage and recovery acceptance open. Firmware build success will not close these gates.

## Read-only storage identification (2026-11-07)

Two approved read-only command lists were run against the production unit (stock 4.8.3, OpenWrt 21.02-based, kernel 5.4.211, `mediatek/mt7981`). Only `cat`, `ls`, `block info`, `mount`, `df` and `uname` were used; nothing was written, flashed, rebooted or probed on the modem/MCU, and no raw flash device was read. `fdisk` is not installed on the router. Raw captures stay local and gitignored; redacted partition facts are summarised here. This closes the layout part of step 2 above but **does not** identify the installed U-Boot version or authorize any backup.

Single eMMC (`mmcblk0`, about 7.28 GiB) with `mmcblk0boot0`/`mmcblk0boot1` (4 MiB each, sector counts from sysfs) and `mmcblk0rpmb`. Start offsets are 512-byte sectors:

| # | Name | Start | Size | Notes |
|---|------|------:|-----:|-------|
| p1 | `log` | 4096 | 2 MiB | attached as `block2mtd` log device (only mtd device) |
| p2 | `u-boot-env` | 8192 | 512 KiB | U-Boot environment |
| p3 | `factory` | 9216 | 2 MiB | factory data (calibration/identity expected; contents not read) |
| p4 | `fip` | 13312 | 2 MiB | bootloader image by name; contents not read |
| p5 | `custom` | 17408 | 2 MiB | purpose unidentified |
| p6 | `kernel` | 21504 | 32 MiB | |
| p7 | `rootfs` | 87040 | about 7.24 GiB | read-only squashfs at `/rom` (58.5 MB used) |
| p8 | `rootfs_data` | 206592 | about 7.18 GiB | f2fs at `/overlay`; starts inside p7 |

- **p8 overlaps p7.** `rootfs_data` begins 119,552 sectors into `rootfs`, just after the squashfs image, so it is created at runtime from the tail of `rootfs`. The partitions are not disjoint; any restore plan must treat them together.
- Sectors 0-4095 are unmapped; what lives there and in the boot partitions is unknown.
- The kernel command line selects root by `root=PARTLABEL=rootfs`, but `/dev/disk/by-partlabel` is absent; names above come from sysfs `PARTNAME`.
- Still open: installed U-Boot/FIP version and advisory applicability, contents of p2-p5 and the boot partitions, backup scope and storage, restore-test method. A bootloader or `u-boot-env` backup (about 6.5 MiB for p2-p5, plus 8 MiB boot partitions) is plausible in size but needs separately approved exact commands; `fw_printenv` can expose identifiers and also needs its own approval and redaction.

## Installed U-Boot and local backup (2026-11-07)

- **Version.** Three further approved read-only router commands found no `/etc/fw_env.config` (so `fw_printenv` cannot run) and no `u-boot`/`bl31`/`fip` lines in `dmesg`. The version came from a locally searched read of the `fip` partition: `U-Boot 2022.07-rc3 (Feb 25 2025 - 19:07:14 +0800)`.
- **Advisory comparison.** The [vendor advisory](https://docs.gl-inet.com/router/en/4/faq/problem_notification_for_mt2500_x3000_xe3000/) recommends U-Boot "version 2025-02-25 19:05:24" for GL-X3000 and "2025-02-25 19:07:14" for GL-XE3000, with firmware 4.7.4. The installed build timestamp equals the XE3000 value, and installed firmware 4.8.3 is newer than 4.7.4. The advisory lists no affected versions and no way to check the installed one, so this is a timestamp match, not proof of the fix. No bootloader update is indicated or authorized.
- **Local read-only backup.** Raw reads (`dd bs=64k`, one SSH call each) of `u-boot-env` (p2), `factory` (p3), `fip` (p4), `custom` (p5), `mmcblk0boot0` and `mmcblk0boot1` were stored in a mode-0700 gitignored local folder and verified byte-identical to prior on-device `sha256sum` values (524,288 / 2,097,152 x3 / 4,194,304 x2 bytes). The `factory` copy was not opened. Contents and hashes are not reproduced here because `factory` carries device identity and calibration.
- **Limits.** This is a single local copy with no off-machine or encrypted second copy. A matching hash proves the transfer, not restorability: no restore layout or isolated restore test exists, and p7/p8 overlap (see above). Contents of `custom`, the boot partitions and the unmapped first 2 MiB remain unidentified. Step 2 of the checklist is complete for layout; steps 3-5 remain open.

