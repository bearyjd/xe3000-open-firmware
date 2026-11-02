# PRP 0004 — Offline MCU and modem candidates

Evidence date: 2026-11-01. These are separate, uncommitted local candidate
results. Links into `build/` are local evidence, not published artifacts. The
accepted [r3 build](../evidence/firmware-r3.json), preserved source baseline,
five feed pins and target-only recipe seed remain unchanged. No candidate
firmware has been compiled and no router operation is authorized by this record.

## MCU availability correction and candidate

The [pinned public packages feed](https://github.com/openwrt/packages/tree/093d551675b1119a06ef224d419905e8d6b2af1a/utils/gl-puli-mcu)
already contains a functional `gl-puli-mcu` source implementation for XE3000.
Our earlier assessment concentrated on a separate dirty local placeholder and
missed this package. The package defaults to the XE300 model; the accepted r3
resolved configuration does not select it. Public source availability establishes
an implementation to test, not behavior on this router.

The [MCU candidate](../../recipe/candidates/mcu/README.md) preserves the hash-pinned
public package and carries two reviewable patches: optional serial/socket
arguments and bounded, validated status handling. **27 native tests passed with
zero skips**, exercising both compiled models through a real daemon, PTY,
private ubusd and ubus CLI, using native builds of the real dependencies.
Independent review approved this offline scope. Input, patch, command, tool and
license evidence is under `build/mcu-offline-20261101/`.

The candidate retains the ubus status field names, validates complete ordered
frames before publication, recovers from malformed/oversized input and expires
samples using monotonic time. Its **10-second freshness limit is a proposed
candidate policy, not a device-derived limit**; polling remains three seconds.
It monitors battery status and adds no charging control. UART electrical behavior,
actual device framing/units, charging safety, thermal behavior and integration
remain unverified. The README records the native-only dependency accommodations
and the upstream package/source license declaration discrepancy.

## Modem profile candidate

The [modem candidate](../../recipe/candidates/modem/README.md) pins a public patch
and additive package fragment. The patch adds subsystem `17cb:5201` for Qualcomm
`17cb:0308` before the generic fallback, choosing `mhi_quectel_rm5xx_info`.
The pinned Linux 6.12.112 source already has a generic SDX65 match; the proposal
changes the profile and channels, rather than making a previously unmatched ID
match. The Quectel profile uses `IP_HW0_MBIM`; the generic profile uses `IP_HW0`.
The preserved dirty local experiment instead retains the SDX65 profile.

**32 modem candidate tests passed**, and independent review approved the bounded
source/config proposal. Exact-source clean application and profile comparison
are recorded in `build/modem-candidate-20261101-portable/proposal.json`.
This does not establish module compilation, runtime binding, port ownership or
working cellular service. Captured stock MBIM=0/qmap=1 remains unresolved.
The external PM change is excluded; `pcie_port_pm=off` is not a candidate default.
XE3000 battery and power consequences require separate evaluation.

## Remaining gates

An isolated combined stage at `build/candidate-config-20261101/` completed offline
feed indexing/installation and explicit `defconfig` with exit 0. The resulting
configuration selects MHI, ModemManager MBIM/netifd support and the XE3000 MCU
model, leaves the XE300 model disabled, and retains the USB/QMI target defaults.
Its SHA-256 is `5a73a8cd37db4187888c6a2592f37e3dda5d4061d6c39f73b83dd8abb018c0ce`,
with 31 configuration changes from the accepted r3 configuration. The exact
[combined fragment](../../recipe/candidates/integration.config) is retained for
later candidate builds. Independent verification of this actual configured
output passed; its report is
`build/offline-candidates-20261101/independent-verification.json`. This stage used
the original pinned sources: the candidate patches were checked separately and
are not applied in this configuration tree. No kernel or image was compiled.

Fresh public-input acquisition and the native build also succeeded at
`build/mcu-offline-ci-local/`, using only hash-verified public downloads rather
than the accepted build's cache. The CI-equivalent fixture passed all 27 native
tests with zero skips. The full offline suite passed 1,971 tests with 58 skips
and 95% recon coverage; the host gate passed 152 tests. The 22 additional offline
skips are real-daemon cases covered by the native job; builder refusal checks
run in the ordinary suite. These are local results, not a hosted CI claim.

Configuration acceptance must precede a separate candidate compilation and
artifact inspection. A candidate build would still leave reproducibility,
storage/identity preservation, modem/SIM behavior, MCU/thermal/charging behavior
and recovery/rollback acceptance open. Exact router commands, flashing and
bootloader changes require separate approval. The existing partial-recon
coverage and captured-evidence uncertainties remain in force.
