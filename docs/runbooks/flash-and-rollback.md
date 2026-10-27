# Runbook: flashing and rollback for the GL-XE3000

Status: document only. These steps have not been executed by this project; no image has been built or flashed. Every step needs the owner's explicit go-ahead, one command list at a time.

The XE3000 is the production home router. Do not start unless you can live without internet for a few hours and have the stock firmware image and a wired laptop to hand.

## Principles

- The bootloader (U-Boot) stays untouched. Only the firmware (kernel and rootfs) is ever replaced, so the stock U-Boot web recovery is always available as the way back.
- Back up the eMMC before anything else, and verify the backup.
- Never run `fw_setenv`, never write the bootloader, preloader or FIP partitions, never change partition tables.
- Keep the stock firmware image for the installed version (GL.iNet 4.8.3 at the time of writing) on the laptop, with its published checksum.

## 1. Before you touch anything

1. Confirm the build: `recipe/prepare.sh --print-plan` shows the pinned OpenWrt tag and commit. The built image is under `build/` and was produced by the recipe, not downloaded elsewhere.
2. Record `sha256sum` of the image and of the stock image. Keep both lists with the backup.
3. Prepare a wired laptop with a static address in the range the recovery page documents, a browser, and the stock image.
4. Note down the modem and SIM state you need after the flash (SIM slot, APN). Do not write PINs or credentials into files in this repo.

## 2. eMMC backup (read-only)

Do this from a shell on the router, with the backup written to external storage or streamed to the laptop. Reads only:

- List the partitions: `cat /proc/partitions` and `ls -l /dev/disk/by-partlabel/`.
- For each partition (at minimum the bootloader/FIP, factory/calibration data, kernel, rootfs, and any GL data partition): `dd if=/dev/disk/by-partlabel/<name> bs=1M | sha256sum`, then again with the output going to a file on the laptop, and compare the two checksums.
- The factory (calibration) partition is the one that cannot be re-created. Keep two copies.

Store the backup somewhere off the router. The backup contains device-unique data, so it is never committed to this repository and never sent to any API.

## 3. Flash path (stock U-Boot web recovery)

1. Power off. Hold the reset button while powering on, until the LED pattern the vendor documents for recovery mode appears.
2. Connect the laptop by cable to the LAN port. Browse to the recovery address documented by the vendor for this model.
3. Upload the XE3000 `*-squashfs-sysupgrade.bin` image from `build/` (the upstream install instructions for this model use the sysupgrade image in U-Boot web recovery). Before uploading, check that the file name carries the `glinet_gl-xe3000` model and compare its `sha256sum` with the build's `sha256sums` file. Do not upload factory, preloader or FIP artifacts. Wait for the page to report completion and do not power off during the write.
4. The router reboots into the new image. U-Boot is not modified by this path.

## 4. Rollback

1. Enter U-Boot web recovery again (section 3, steps 1 and 2).
2. Upload the stock firmware image, after checking its `sha256sum` against the published value.
3. Boot, confirm the stock UI and the modem come up, and reconfigure from the vendor backup.
4. If the router does not enter recovery at all, stop. Do not attempt to reflash the bootloader. Use the eMMC backup and a serial console, and ask for help with the backup checksums in hand.

## 5. After flashing

Compare with the stock behaviour before relying on the router: LAN/WAN, Wi-Fi, the modem enumerating as expected, SIM selection, battery/fan reporting. The kernel patch for the modem PCI ID and the `pcie_port_pm=off` command line are unverified on hardware until this step is done.

## What this runbook does not cover

Unlocking anything, changing the bootloader, or any step not listed above.
