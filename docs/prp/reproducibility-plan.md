# Reproducibility and signing plan for GL-XE3000 builds

Links into `build/`, `findings/raw/` or `/tmp/` refer to local evidence only; those files are not hosted in this repository. Local `build/openwrt` references describe the inspected checkout and any explicitly identified experiments, not a published upstream source snapshot.

Comparison update: 2026-11-02. The [accepted r3 summary](../evidence/firmware-r3.json) remains the baseline result; the [first candidate summary](../evidence/firmware-candidate-20261101.json) records one fresh MCU/MHI build with two incremental resumes. A [new independent clean candidate comparison](../evidence/firmware-candidate-comparison-20261102.json) is complete: 13 of 18 target artifacts match, but the original initramfs, factory and sysupgrade images differ. Both candidate samples passed independent actual-output audits. `reproducible` and `production_ready` remain false. R3 has different configuration/packages and remains a separate baseline, not either sample in this comparison. No router operation is authorized by this record.

## Confirmed source behavior

References below use the preserved `build/firmware-v25.12.6/checkout` at commit `64900e756efa667774214f9c6b17c113222e01f7`; line numbers refer to that pinned source.

- **Epoch selection:** [include/toplevel.mk](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/include/toplevel.mk):15 assigns `SOURCE_DATE_EPOCH` from the source helper and exports it at line 19. [scripts/get_source_date_epoch.sh](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/scripts/get_source_date_epoch.sh):11–20,34 prefers `version.date`, then Git commit time. The pinned `version.date` contains **1792273538**, whereas the preparation manifest and launcher environment record commit-derived **1792282260**. Consequently, the launcher value alone does not establish the epoch used inside make. The r2 compile was interrupted before target images; its supplemental interruption record preserves this discrepancy. The TDD repair passing manifest-derived `SOURCE_DATE_EPOCH=1792282260` on each make command line passed independent review. Fresh r3 configuration and `make -j8 V=s SOURCE_DATE_EPOCH=1792282260` completed with exit 0 under fixed hostname `xe3000-firmware-builder`; the helper records `compiled-inspected`, and output metadata reports epoch 1792282260. Independent verification of actual artifacts passed, including reported image epoch and preserved input evidence. Verify the command record and effective value before comparing builds, preserving the original evidence. [include/kernel.mk](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/include/kernel.mk):10–12 uses the effective epoch for the kernel timestamp; [include/rootfs.mk](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/include/rootfs.mk):126 normalizes rootfs timestamps. Package epochs are separately derived by [include/package.mk](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/include/package.mk):18–19.
- **Signing inputs and embedding:** [rules.mk](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/rules.mk):295–297 selects checkout-local signing paths. Both actual r3 and candidate configs enable `CONFIG_USE_APK`, `CONFIG_SIGNED_PACKAGES` and `CONFIG_SIGNATURE_CHECK`, with `CONFIG_BUILDBOT` disabled. [package/Makefile](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/package/Makefile):62–66,83–91 makes fresh APK key generation a prerequisite even when `SIGNED_PACKAGES` is disabled; lines 69–77,128–145 add index signing conditionally. [package/base-files/Makefile](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/package/base-files/Makefile):123–128,171 installs the public key in non-BUILDBOT APK images independently of `SIGNED_PACKAGES`. **Disabling package signing alone therefore does not remove generated key bytes from the image.** `BUILDBOT` also changes package/debug/kernel-identity defaults, so it is not a narrow embedding switch. Fresh default public identities can change image bytes even with otherwise identical inputs. The inspected [APK package invocation](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/include/package-pack.mk):592–607 has no `--sign` argument; index signing does not establish that every individual APK is signed.
- **Conditional image signatures:** The OPKG branch generates a usign key/certificate if absent ([package/base-files/Makefile](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/package/base-files/Makefile):130–144). [include/image-commands.mk](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/include/image-commands.mk):91–99 appends an image signature only when `key-build` and its certificate exist. Do not assume this conditional branch ran in the actual APK build. Establish actual signing behavior through build commands and public output metadata, without reading private-key contents.
- **Path and identity normalization:** [rules.mk](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/rules.mk):176–178 chooses `-ffile-prefix-map` when `CONFIG_REPRODUCIBLE_DEBUG_INFO` is enabled, otherwise `-fmacro-prefix-map`; [config/Config-build.in](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/config/Config-build.in):129–136 describes the debug-path option. [include/kernel.mk](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/include/kernel.mk):108–116 supplies path mapping, configured build user/host and build version. [config/Config-kernel.in](https://github.com/openwrt/openwrt/blob/64900e756efa667774214f9c6b17c113222e01f7/config/Config-kernel.in):5–21 describes empty user/domain defaults; r2 records both empty. These mechanisms are evidence of intended normalization, not proof every output is path-independent.

## Completed fresh-signing diagnostic and alternative policy

The read-only signing-policy investigation and its independent review are local
records at `build/reproducibility-policy-20261102/{policy.json,independent-policy-verification.json}`.
They verified the pinned source behavior and signed configurations above using
public signing identities only; private key contents were not read, copied or
hashed. Signature determinism was not established.

The diagnostic completed in `build/stages/candidate-rebuild-20261102-r3/` with
one uninterrupted offline make and image inspection, both exit 0. Source/feed
pins, reviewed patches, exact resolved config, container, epoch, path, user,
hostname and eight-job command matched the first candidate. The new workspace
excluded prior compiled/staging outputs and signing keys, reused verified named
public archives, and generated fresh default signing inputs. Its independent
audit passed 38 checks, with 18 artifacts, five profile images and 165 packages.

The [comparison summary](../evidence/firmware-candidate-comparison-20261102.json)
records true hashes before component diagnosis: 13 artifacts match; initramfs,
factory, sysupgrade, profiles and checksums differ. Sysupgrade CONTROL/kernel and
12 named MCU/modem/MBIM/QMI/MHI payloads match; rootfs, public signing identities,
APK installed database and scripts differ. Actual image `passwd`/`group` match
despite generated user/group metadata order differences from unsorted upstream
Perl hash iteration. Three Lua archives were present upfront in the clean
configured snapshot rather than added during resumes.

Rootfs metadata has the same 1,498 entries with two size differences: public CA
bundle 361,128 versus 181,603 bytes and scripts archive 12,802 versus 12,801.
The bundles share 121 unique public certificates; the incremental sample has
120 duplicate blocks. Exact public-parser replay reproduces each bundle on the
first run versus rerun without cleaning. Basename collision handling leaves
extra CRT files; concatenation overwrites rather than appends. Resume logs
confirm rerun, but the immediate make dependency reason remains untraced. No
source fix was applied. Fresh keys are not the sole established explanation for
all differences, and neither matching certificate sets nor named payloads proves
whole-rootfs equality, signature determinism or runtime trust acceptance.

An alternative of two unsigned experimental builds requires a separately
reviewed source/config policy for both index signing and public-key embedding.
Disabling `SIGNED_PACKAGES` alone is insufficient, and silently enabling
`BUILDBOT` changes other inputs. Neither existing r3 nor the signed candidate
would be a matching first sample for that alternative. No unsigned experiment
has been performed or selected here.

## Accepted-artifact build policy (A: fresh signing key per build)

1. **One uninterrupted build.** An artifact set may be accepted or compared only if it came from a single offline `make` on a fresh build directory. Resumed builds (`compile-resume-*`) are retained as evidence but labeled non-comparable. Cause: OpenWrt's `ca-certificates` parser does not clean its output, so a re-run leaves extra CRT files and a larger bundle (121 unique certificates became 241 CRT files and 241 bundle blocks, 120 duplicates). The `make` dependency that triggers the re-run is still untraced.
2. **Automatic guard.** `scripts/ca_bundle_guard.py` runs after image inspection in `build_firmware.py --compile`. It reads each `ca-certificates-*` build directory and fails the stage (`status=failed`) if the bundle or CRT set has duplicate certificates, or the bundle and CRT sets differ. It never rewrites outputs. Result is recorded as `ca_bundle_guard` in `build-record.json`. Verified on retained stages: the clean rebuild passes (121/121/121); the resumed first candidate fails (241 blocks, 121 unique).
3. **Signing: policy A.** Each build uses a fresh default APK signing key; private keys are never reused, copied or read. Whole-image, rootfs, public-key and package-database hashes are therefore expected to differ between builds. Comparisons use per-payload hashes (sysupgrade CONTROL/kernel, named rootfs files) and must state that scope. A fixed committed test key (byte-identical images) was considered and not selected: it weakens signing semantics. `reproducible` stays false.

## Procedure for further independent comparisons

1. Select and name the matching first sample for any further experiment; preserve both candidate samples' [comparison evidence](../evidence/firmware-candidate-comparison-20261102.json), configurations, patch order, input revisions and original output hashes. The first candidate's incremental resumes belong to that one build; the clean sample is a separate build. Preserve the accepted r3 baseline separately because it has different inputs.
2. Keep the candidate configuration and fresh default signing policy unchanged. Never reuse or inspect old private keys. Record only the explicitly named public identities for diagnosis; matching public keys alone would not prove deterministic signatures. Any unsigned alternative needs the separate policy review above and two new matched builds.
3. Create an independent fresh source/feed/build workspace from the verified baseline and reapply the exact three reviewed candidate patches in order; reuse no compiled objects, staging trees or generated outputs. Use immutable image `sha256:96695425b78f34c79f71e4500c7565f968095abae933c40da35a0d8e0584e5ec`, the same full source/feed commits, resolved config SHA-256 `5a73a8cd37db4187888c6a2592f37e3dda5d4061d6c39f73b83dd8abb018c0ce`, explicit make epoch `1792282260`, and recorded tool/package inventory. Reuse only the 123 named public archives after hash verification. Compare input records before compilation; avoid whole-tree snapshots after generated private keys exist.
4. Use the same eight-job command and stable in-container build path/user/hostname for the initial comparison. Mount the independent host workspace at the same container path; leave the original workspace preserved and unmounted. Record all identity/path inputs and any intentional differences. A later path-variation experiment is a separate, stronger test; do not enable debug remapping or change kernel identity options silently.
5. Inspect both outputs independently. Compare SHA-256 and byte lengths for every emitted GL-XE3000 factory/sysupgrade image and named auxiliary artifact. Compare package names/versions/architecture, rootfs/public-key identities, profiles metadata, embedded board/target/revision metadata and config/feed/version buildinfo. Keep all original bytes; record comparisons in a separate report. Auxiliary-artifact equivalence is distinct from permission to flash them.
6. If hashes differ, first compare recorded inputs, effective epochs and signing identities, then metadata, archive ordering/timestamps, named public rootfs files, kernel/toolchain objects and embedded paths. Removing a public-key file from a comparison alone does not prove equivalence: package/database/index metadata may also differ. Use local comparison tools such as diffoscope on non-secret copies; exclude private-key paths and avoid dumping arbitrary generated files into reports. Report differing components and unresolved causes without replacing image hashes with normalized hashes.
7. Claim only the exact scope demonstrated: byte-identical named images under the recorded inputs/environment, with any signing-material dependencies stated. Matching package inventories or unsigned payloads alone is a narrower result. Require independent review of the comparison and preserved-baseline checks; keep `reproducible=false` until that evidence supports changing it. Hardware, recovery and production acceptance remain separate gates.
