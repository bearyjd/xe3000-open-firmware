# Live hardware state from read-only router reads (2026-11-08)

Two approved read-only command lists (modem link state; thermal/MCU/power) were run against the production unit (stock 4.8.3). Only `cat`, `ls`, `readlink`, `grep`, `lsmod`, `ps` and `dmesg` were used. No modem or MCU device node was opened, no AT traffic was sent, `/dev/ttyS1` was not touched and nothing was written. Output was redacted before reading; raw captures stay local and gitignored. These are captured values, not evidence that any upstream driver works.

## Modem

- PCI function `0001:01:00.0`, vendor/device `17cb:0308`, subsystem `17cb:5201`, bound to the vendor driver `mhi_q`; link 5 GT/s x1, runtime status active. Its root port is `0001:00:00.0` (`14c3:1f32`). The Wi-Fi function is `0000:00:00.0` (`14c3:7981`, driver `mt_rbus`).
- `/sys/bus/mhi` does not exist: the vendor `pcie_mhi` module (use count 0) does not register the upstream MHI bus. It exposes vendor character devices instead (`/dev/mhi_BHI`, `_DIAG`, `_DUN`, `_LOOPBACK`, `_QMI0`) and the network interface `rmnet_mhi0`. They were listed with `ls` only.
- `/dev/wwan*` and `/dev/cdc-wdm*` do not exist. `/dev/ttyUSB0-3` exist and `option`, `qmi_wwan`, `cdc_wdm`, `cdc_ncm`, `rndis_host` and `huawei_cdc_ncm` are loaded.
- **The modem also enumerates over USB** (third read-only list, 2026-11-08): `2c7c:0801`, product `Quectel RM520N-GL`, at `usb1/1-1/1-1.2` behind a `05e3:0618` USB 2.0 hub on the xHCI host (`11200000.xhci`), with four interfaces (`1-1.2:1.0` to `1-1.2:1.3`). A further read-only list (2026-11-08) confirmed the mapping: interface `1-1.2:1.N` owns `ttyUSB<N>` for N = 0-3, each served by a USB serial driver. The same modem therefore appears over both PCIe (`17cb:0308`, vendor `mhi_q`) and USB, which is consistent with the retained USB QMI configuration in the candidate. A second device, `05e3:0752` "Generic USB Storage", sits on the same hub and is not identified. `lsusb` is not installed.
- The filtered `dmesg` returned nothing (likely the ring buffer has rolled over), so boot-time modem messages are unavailable.
- Consequence: a move to upstream MHI/WWAN drivers cannot reuse the vendor node and interface names, and the MBIM=0/QMAP=1 question stays open (see the [candidate record](0004-offline-candidates.md)).

## Traffic counters and stock kernel configuration

- **Which path carries data now.** Interface counters since boot show `rmnet_mhi0` (the PCIe modem interface) at 0 bytes and 0 packets in both directions, and no USB network interface exists. All traffic is on the Ethernet and Wi-Fi interfaces, so the cellular modem was carrying no data when read. This says nothing about which path stock firmware uses when the modem is the uplink, so that question stays open; an earlier suggestion that data "very likely flows over PCIe" is withdrawn.
- **Stock kernel (5.4.211) options**, from `/proc/config.gz` (eight lines were altered by the redactor and none are among the options below): no `MHI_BUS`, `PCI_MHI`, `WWAN`, `MHI_NET` or `RMNET` (`# CONFIG_RMNET is not set`), `PCIE_MEDIATEK_GEN3=y` (`PCIE_MEDIATEK` unset), `MMC_MTK=y`, `EFI_PARTITION=y`, and `USB_NET_QMI_WWAN`, `USB_NET_CDC_MBIM`, `USB_WDM`, `USB_SERIAL_OPTION` and `USB_SERIAL_WWAN` as modules. The stock kernel therefore has no upstream MHI or WWAN stack at all; the modem on PCIe works only through the vendor out-of-tree `pcie_mhi` driver, and the candidate's MHI patch for the 6.12-based upstream kernel is not a drop-in replacement for it.

## Thermal, fan, MCU, power

- One thermal zone (`cpu-thermal`) read 60.2 C; one cooling device (`pwm-fan`) was at state 0 of 255 (fan off); hwmon `pwmfan`.
- `/sys/class/power_supply/` is empty: no battery or charger is exposed as a kernel power supply. Any charge or battery state is reachable only through the userspace `mcu` daemon (running under `eco`) and its serial line (`ttyS1`). Reading it is an MCU probe and stays closed.
- `gl_fan` and `mcu` are running.

## Still open

The `05e3:0752` storage device; which of the PCIe or USB paths carries data in stock use; modem firmware/SIM/registration state (needs modem protocol access, not authorized); MCU charging behaviour, units and safe limits; whether the 10 s MCU freshness policy suits real traffic. Hardware, recovery and production gates are unchanged and `production_ready` stays false.
