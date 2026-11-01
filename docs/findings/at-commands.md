# AT command references

Links into `build/`, `findings/raw/` or `/tmp/` refer to local evidence only; those files are not hosted in this repository. Local `build/openwrt` references describe the inspected checkout and any explicitly identified experiments, not a published upstream source snapshot.

Curated static/captured evidence, 2026-10-31. The six approved paid runs completed with partial extraction. These bounded interpretations received independent semantic review; they do not establish runtime behavior or hardware acceptance. See [coverage and accounting](index.md). No proprietary source excerpts are reproduced.

The modem-init script declares START=19, an AT-daemon launch, and a background five-second delay before initialization followed by an echo/indication helper. These are conditional source declarations: masked guards and asynchronous daemon readiness prevent a proven runtime-order claim. Evidence: [etc%init.d%modem-init:4](../../build/review-20261031/harvest/redacted/sys/etc%25init.d%25modem-init#L4), [etc%init.d%modem-init:35](../../build/review-20261031/harvest/redacted/sys/etc%25init.d%25modem-init#L35).

Captured glmodem configuration records sim_num=1. Independently inspected SIM-selection source queries and sets QUIMSLOT with retries and waits. This does not establish the working physical slot, actual acknowledgements or a GPIO SIM-routing protocol; no AT command was issued for this review. Evidence: [etc%config%glmodem:5](../../build/review-20261031/harvest/redacted/config/etc%25config%25glmodem#L5), [switch_sim_slot:584](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/usr/bin/switch_sim_slot#L584), [switch_sim_slot:684](../../build/review-20261031/unpacked/stock-4.8.3/rootfs/usr/bin/switch_sim_slot#L684).

These selected references are not a complete modem command inventory. Flagged ungrounded AT-related records remain outside these conclusions.
