# PRP 0004 — Offline MCU and modem candidates

Source/native evidence: 2026-11-01; independent candidate firmware audit:
2026-11-02 UTC. The reviewed patches now have a separately compiled and
independently inspected [candidate build](../evidence/firmware-candidate-20261101.json).
Links into `build/` are local evidence, not published artifacts. The accepted
[r3 baseline](../evidence/firmware-r3.json), prepared source baseline, five feed
pins and target-only recipe seed remain unchanged. Hardware acceptance remains
open; this record authorizes no router operation.

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
These source checks alone did not establish module compilation. The separate
firmware audit below verifies compiled modules; runtime binding, port ownership
and working cellular service remain unverified. Captured stock MBIM=0/qmap=1
remains unresolved.
The external PM change is excluded; `pcie_port_pm=off` is not a candidate default.
XE3000 battery and power consequences require separate evaluation.

## Configuration stage and prior tests

An isolated combined stage at `build/candidate-config-20261101/` completed offline
feed indexing/installation and explicit `defconfig` with exit 0. The resulting
configuration selects MHI, ModemManager MBIM/netifd support and the XE3000 MCU
model, leaves the XE300 model disabled, and retains the USB/QMI target defaults.
Its SHA-256 is `5a73a8cd37db4187888c6a2592f37e3dda5d4061d6c39f73b83dd8abb018c0ce`,
with 31 configuration changes from the accepted r3 configuration. The exact
[combined fragment](../../recipe/candidates/integration.config) was used for the
candidate build below. Independent verification of this actual configured
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
run in the ordinary suite. The earlier independent candidate suite passed 59
tests. Separately, [merged PR #11](https://github.com/bearyjd/xe3000-open-firmware/pull/11)
passed its five CI jobs. These test results are distinct from actual firmware
compilation and do not establish hardware acceptance.

## Candidate firmware result

A fresh isolated workspace at `build/stages/candidate-firmware-20261101/`
compiled the reviewed MCU and MHI changes with the combined configuration above.
The [sanitized public summary](../evidence/firmware-candidate-20261101.json) records
18 public artifacts, five profile images, 165 installed packages and exact image
hashes. Compared with accepted r3, the inventory adds 17 packages and removes
none, retaining USB/QMI defaults. The MCU patches were applied in order directly
to the isolated feed's C source; the exact MHI patch was installed in the kernel
pending-patch series. The recorded upstream/feed HEADs retain their original
pins, with these explicit working-tree changes.

The independent actual-output audit passed 38 checks, including image structure,
metadata, checksums, source/configuration checks, the XE3000 MCU compile model and
UART default, MHI subsystem-match ordering, and named image files compared with
staged AArch64 outputs. That named-file comparison does not cover every rootfs
file. The prepared baseline, accepted r3 artifacts/source/feed bytes and original
unpatched configuration-only stage were verified separately. Historical dirty
experiment bytes were not independently revalidated against absent prior digests.
The full local report is
`build/candidate-firmware-20261101/independent-final-verification.json`.

This is one fresh candidate build with two incremental resumes. The first two
make attempts exited 2 on missing Lua archives, then lua-cjson; the final make
and image-metadata extraction exited 0. Fifteen additional public archives were
acquired and hash-verified outside the network-disabled build container; all
123 named public archives were verified. Failed logs and explicit input-revision
and resume records were retained. The pre-compilation snapshot remains preserved;
later archive additions are recorded separately, without a whole-tree snapshot
of generated signing material. Fresh default signing inputs were generated in
this workspace; old private keys were neither reused nor copied.

## Independent clean-build comparison

A new clean candidate at `build/stages/candidate-rebuild-20261102-r3/` completed
one uninterrupted offline make invocation and image inspection, both exit 0.
Its independent audit passed 38 checks, again finding 18 artifacts, five profile
images and the same 165-package inventory. The workspace suffix does not denote
the accepted r3 baseline. Source/feed pins, patches, resolved configuration,
epoch, container and recorded environment matched the first candidate; configured
snapshots nevertheless differ by the three Lua archives supplied upfront and
generated user/group metadata ordering. The upstream Perl generator iterates
unsorted hash keys; actual image `passwd` and `group` files match.

The [public comparison](../evidence/firmware-candidate-comparison-20261102.json)
preserves both samples' original image hashes and sizes. Thirteen of 18 target
artifacts match byte for byte; initramfs, factory, sysupgrade, profiles and
checksums differ. Sysupgrade CONTROL and kernel match, while rootfs differs.
The 12 named MCU/modem/MBIM/QMI/MHI payloads match. Public signing identities,
APK installed-database content and scripts differ. A 1,498-entry rootfs metadata
comparison has no added/removed names and two size changes: the public CA bundle
is 361,128 versus 181,603 bytes, and APK scripts are 12,802 versus 12,801 bytes.
Matching metadata and named files do not establish whole-rootfs equality.

The CA bundles have the same 121 unique public certificates, but the first has
241 blocks (120 duplicates) and the clean sample has 121. A disposable replay of
the exact public parser reproduces the clean bundle on its first run and the
larger incremental bundle when rerun without cleaning. Basename collision
handling creates extra CRT files; sorted concatenation overwrites the bundle.
The resume log confirms parser rerun, but why make selected it again remains
untraced. This explains the duplicate CA bundle, not all image differences; no
source fix or runtime trust acceptance is claimed.

## Remaining gates

`hardware_verified`, `reproducible` and `production_ready` remain false. Follow
the [comparison findings and signing-input plan](reproducibility-plan.md) before
any further experiment.
Storage/identity preservation, modem/SIM behavior, MCU/thermal/charging behavior
and recovery/rollback require separate acceptance. Exact router commands,
flashing and bootloader changes require separate approval. The partial-recon
coverage and captured-evidence uncertainties remain in force.
