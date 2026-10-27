# Runbook: flashing and rollback for the GL-XE3000

Status: document only. These steps have not been executed by this project; no image has been built or flashed. Every step needs the owner's explicit go-ahead, one command list at a time.

The XE3000 is the production home router. Do not start unless you can live without internet for a few hours and have the stock firmware image and a wired laptop to hand.

## Principles

- The bootloader (U-Boot) is left untouched by this runbook. Only the firmware (kernel and rootfs) is replaced. That does not make recovery guaranteed: see the next section.
- Never flash until a full eMMC backup (every partition, including bootloader/FIP and factory data) has been taken and verified as described in section 2. If the backup is not verified, do not flash.
- Back up the eMMC before anything else, and verify the backup.
- Never run `fw_setenv`, never write the bootloader, preloader or FIP partitions, never change partition tables.
- Keep the stock firmware image for the installed version (GL.iNet 4.8.3 at the time of writing) on the laptop, with its published checksum.

## Known U-Boot recovery defect (read before anything else)

Upstream OpenWrt documents a GL.iNet U-Boot startup/recovery defect on the MT2500, X3000 and XE3000 family (see the OpenWrt device page for the GL.iNet GL-X3000/XE3000, https://openwrt.org/toh/gl.inet/gl-x3000, and the GL-MT2500 page, https://openwrt.org/toh/gl.inet/gl-mt2500). On affected units the stock U-Boot can fail to start or to enter web recovery. This project has not tested recovery on this unit. The web recovery path below may not work, and there is no guarantee of recovery. Treat every flash as potentially unrecoverable without a serial console or an external eMMC programmer, and re-read the upstream page for current details before starting. A verified full backup limits the damage but cannot be guaranteed to restore a router that no longer reaches U-Boot.

## 1. Before you touch anything

1. Confirm the build: `recipe/prepare.sh --print-plan` shows the pinned OpenWrt tag and commit. The built image is under `build/` and was produced by the recipe, not downloaded elsewhere.
2. Record `sha256sum` of the image and of the stock image. Keep both lists with the backup.
3. Prepare a wired laptop with a static address in the range the recovery page documents, a browser, and the stock image.
4. Note down the modem and SIM state you need after the flash (SIM slot, APN). Do not write PINs or credentials into files in this repo.

## 2. eMMC backup (read-only)

Do this from a shell on the router, with the backup written to external storage or streamed to the laptop. Reads only:

- List the partitions: `cat /proc/partitions` and `ls -l /dev/disk/by-partlabel/`.
- For each partition (at minimum the bootloader/FIP, factory/calibration data, kernel, rootfs, and any GL data partition), read it twice, once to a file on the laptop and once more to compare. Run the router side in a shell with `set -o pipefail` and check the exit status of every stage (`dd`, the transport, and `sha256sum`); a pipeline that only reports the last stage hides read failures. In a shell without pipefail, check `PIPESTATUS` or write to a file and check `$?` before hashing.
  - Example per partition: `dd if=/dev/disk/by-partlabel/<name> bs=1M` piped to the transport or to `sha256sum`, with all stages required to exit 0.
- Verify the byte count of each backup against the device size, not just the checksum. Get the expected size with `blockdev --getsize64 /dev/disk/by-partlabel/<name>` (or from `/sys/class/block/<dev>/size` times 512) and compare it with `wc -c` of the saved file. A backup whose byte count differs is incomplete and must be redone.
- Only after the exit statuses and byte counts are right, compare the checksums of the two reads. Matching checksums alone prove nothing: two identically truncated reads (the same failure twice) produce matching checksums, so a truncated backup would look verified.
- The factory (calibration) partition is the one that cannot be re-created. Keep two copies.

Store the backup somewhere off the router. The backup contains device-unique data, so it is never committed to this repository and never sent to any API.

## 3. Flash path (stock U-Boot web recovery)

1. Power off. Hold the reset button while powering on, until the LED pattern the vendor documents for recovery mode appears.
2. Connect the laptop by cable to the LAN port. Browse to the recovery address documented by the vendor for this model.
3. Upload the XE3000 `*-squashfs-sysupgrade.bin` image from `build/` (the upstream install instructions for this model use the sysupgrade image in U-Boot web recovery). Before uploading, check that the file name carries the `glinet_gl-xe3000` model and compare its `sha256sum` with the build's `sha256sums` file. Do not upload factory, preloader or FIP artifacts. Wait for the page to report completion and do not power off during the write.
4. The router reboots into the new image. U-Boot is not modified by this path.

## 4. Rollback

1. Enter U-Boot web recovery again (section 3, steps 1 and 2). This may not work if the U-Boot defect above applies to your unit.
2. Upload the stock firmware image, after checking its `sha256sum` against the published value.
3. Boot, confirm the stock UI and the modem come up, and reconfigure from the vendor backup.
4. If the router does not enter recovery at all, stop. Do not attempt to reflash the bootloader. Use the eMMC backup and a serial console, and ask for help with the backup checksums in hand.

## 5. After flashing

Compare with the stock behaviour before relying on the router: LAN/WAN, Wi-Fi, the modem enumerating as expected, SIM selection, battery/fan reporting. The kernel patch for the modem PCI ID and the `pcie_port_pm=off` command line are unverified on hardware until this step is done.

## What this runbook does not cover

Unlocking anything, changing the bootloader, or any step not listed above.
