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

A real restore test should run on a **second identical unit**, not the production router. **The owner confirmed on 2026-11-07 that no spare unit exists**, so no destructive restore or recovery-path test is possible. The standing result is "restorability unverified" until a spare is obtained; the no-write tests above are the most that can be demonstrated, and no flash, bootloader or recovery step on the production unit is planned.

## Stop conditions and claims

- Stop at any hash mismatch, unexplained layout difference, or request to write to the production unit.
- Claim only what a test demonstrated. Layout rebuild passing means offsets are consistent; it does not mean a restore boots. `production_ready` and `reproducible` stay false.
- Keep all raw copies local, gitignored and unshared; record hashes only for non-identity partitions, never `factory`.

## Decisions and remaining gaps (2026-11-07)

1. ~~Spare unit?~~ None exists.
2. ~~Read the first 4096 sectors?~~ Done under approved commands (`dd if=/dev/mmcblk0 bs=512 count=4096`, verified against an on-router hash of the same range). Sector 0 holds a protective MBR (0x55AA) and sector 1 a GPT header (`EFI PART`); the rest of the 2 MiB is blank. The disk and partition GUIDs are in the local copy only and are deliberately not recorded in this repository. The partition entries have not yet been parsed against the sysfs map.
3. ~~Where does the second copy live?~~ A mode-0700 folder `~/xe3000-backup-20261107` on the same workstation, with a `SHA256SUMS` manifest, verified identical to the first copy. This is a second copy on the same machine, not an off-machine or encrypted one, so it does not protect against loss of this workstation.

### GPT parsed offline (2026-11-07)

Parsed from the local first-4096-sector copy only (no router access; GUIDs not recorded here):

- Header and partition-entry CRCs both validate; 128 entry slots of 128 bytes start at sector 2.
- Seven entries: `log`, `u-boot-env`, `factory`, `fip`, `custom`, `kernel`, `rootfs`. Names, start sectors and sizes equal the sysfs-derived map in the [rollback plan](rollback-plan.md); none overlap in the GPT.
- `rootfs_data` is not in the GPT, which confirms it is created at runtime from the tail of `rootfs`; a restore must not expect it in the partition table.
- The last usable sector (15,269,887) is `rootfs`'s final sector and the last sector of the disk, so no backup GPT can sit at the disk end.
- The header's alternate-header field reads `1`. Not yet checked whether this is a vendor-tool quirk or a parsing error, so do not rely on that field.
- Consequence: rebuild the primary GPT from the saved copy; do not assume a backup table exists to repair from.

Still open: an off-machine encrypted copy; the offline layout rebuild test above.
