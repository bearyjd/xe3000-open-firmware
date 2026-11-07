# Restore-test plan and backup content findings

**PLANNING ONLY — no executable restore procedure, and no router write, flash, reboot or boot-partition unlock is authorized.** This supports step 4 of the [rollback plan](rollback-plan.md): a backup hash shows a faithful read, not that a restore works.

## What the local backup copies contain (structure only, 2026-11-07)

Measured on the local copies; no string contents were printed and `factory` was not opened.

| Copy | Size | Finding |
|------|-----:|---------|
| `u-boot-env` (p2) | 512 KiB | all zero bytes: no saved U-Boot environment (matches the absent `fw_env.config`) |
| `custom` (p5) | 2 MiB | all zero bytes: unused |
| `mmcblk0boot1` | 4 MiB | all zero bytes: unused |
| `mmcblk0boot0` | 4 MiB | MediaTek `EMMC_BOOT` and `BRLYT` headers; about 96% zero; early-boot image |
| `fip` (p4) | 2 MiB | FIP table header (`01 00 64 aa 78 56 34 12`), an embedded FDT and gzip data; contains `U-Boot 2022.07-rc3 (Feb 25 2025 - 19:07:14 +0800)` |

Consequences: a blank `u-boot-env` means U-Boot runs on built-in defaults, so there is no saved boot configuration in p2 to preserve (an environment stored elsewhere is not ruled out). The bootloader chain lives in `mmcblk0boot0` (early stage) and `fip`. Sectors 0-4095 and the GPT were never read, so partition GUIDs and the disk GUID are unknown.

## What can be tested with no device write

1. **Offline layout rebuild.** Create a sparse image the size of the eMMC (7,634,944 KiB), place each backup copy at its recorded start sector, read each region back and compare to the stored hashes. Pass: every region byte-identical; no overlap among p1-p6; p7/p8 overlap reproduced as recorded. This tests offsets and sizes only, not bootability.
2. **Vendor image check.** Obtain the official GL.iNet XE3000 4.8.3 firmware and the vendor U-Boot recovery guidance from vendor pages; record URL, size and SHA-256. Unpack read-only and confirm its partition layout and `fip`/`kernel`/`rootfs` expectations agree with the recorded map. Pass: names and sizes agree, or each difference is explained.
3. **Compare `fip` to vendor.** If the vendor ships the matching bootloader, compare it to the local `fip` copy. Pass: identical, or the difference is explained.

None of these needs the router.

## What needs hardware (gated, not planned in detail)

- Restoring `fip`, `mmcblk0boot0` or any partition: boot partitions are normally read-only (`force_ro`) and unlocking them is a device write.
- Exercising the vendor U-Boot recovery path (network recovery, button sequence): changes device state and can leave the unit unbootable.
- Reading sectors 0-4095 / the GPT: a read, but it holds the disk GUID and partition GUIDs; needs its own approved command and redaction.

A real restore test should run on a **second identical unit**, not the production router. Whether a spare exists is an open question for the owner. Without one, the honest result is "restorability unverified".

## Stop conditions and claims

- Stop at any hash mismatch, unexplained layout difference, or request to write to the production unit.
- Claim only what a test demonstrated. Layout rebuild passing means offsets are consistent; it does not mean a restore boots. `production_ready` and `reproducible` stay false.
- Keep all raw copies local, gitignored and unshared; record hashes only for non-identity partitions, never `factory`.

## Open decisions

1. Is there a spare GL-XE3000 for a destructive restore test?
2. May the first 4096 sectors (GPT) be read, and how should the disk and partition GUIDs be stored?
3. Where does the off-machine second copy of the backup live?
