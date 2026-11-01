# xe3000-open-firmware

Links into `build/`, `findings/raw/` or `/tmp/` refer to local evidence only; those files are not hosted in this repository. Local `build/openwrt` references describe the inspected checkout and any explicitly identified experiments, not a published upstream source snapshot.

A project to build a reproducible OpenWrt for the **GL.iNet GL-XE3000 (Puli AX)**.

The planned deliverable is a *recipe repo*, not a fork: a pinned upstream OpenWrt tag, a few patches, a `files/` overlay and a small package feed. The XE3000 is the primary home router, so the device is treated as production.

## Status

Recon tooling is merged through PR #9. A local read-only harvest and unpacked stock 4.8.3 artifacts exist; their provenance and completeness have not been verified. Six approved paid S5/S6 runs completed with partial extraction; [curated findings](docs/findings/index.md) preserve coverage and hardware limits. Fixture-oriented engine runs do not establish completion. The original inputs still fail preflight; a separate prepared copy now passes full-tree and scoped gates and has independent verification. The user confirmed sample review and approved the exact six runs in `analysis-plan.json` in conversation; those API runs completed through the reviewed adapter with $5 per-run caps ($30 combined), not spend estimates. See [preparation evidence](docs/findings/preparation.md) and the local [review packet](build/review-20261031/REVIEW.md). See [current status](docs/prp/0003-current-status.md) for checked evidence and the remaining gates.

## License

**GPL-2.0-only.** Kernel patches must be GPL-2.0, so this repo does not use the author's usual AGPL. See `LICENSE`.

## Guardrails

- Never flash, sysupgrade, write mtd/eMMC/boot partitions, `fw_setenv`, change UCI, or reboot the router.
- Router commands are read-only; the only permitted write is `/tmp`, and only in approved phases. No opkg installs.
- No AT commands to the modem.
- Secrets (shadow, host keys, Wi-Fi/VPN keys, PPPoE creds, tokens, ICCID/IMSI/IMEI) are never collected, or are redacted before leaving `harvest/raw/`.
- `harvest/raw/` is gitignored and **never** sent to any external API.
- `scripts/harvest.sh` writes only under `harvest/raw/`; `HARVEST_OUT` may select a subdirectory there but is refused if it resolves (after `..`/symlinks) anywhere else.
- No GL proprietary binaries or UI in the repo: findings and notes only.
- Every router-touching step is shown as an exact command list and approved first.

## Layout

| Path | Purpose |
|------|---------|
| `docs/prp/` | Product requirement prompts (written before implementation, with devil's-advocate review) |
| `docs/findings/` | Curated partial findings, preparation evidence and preliminary upstream assessment |
| `recipe/` | Pinned upstream source/feed manifest and three-line XE3000 target seed; [source preparation guide](recipe/README.md) |
| `scripts/` | `recon/` engine plus redaction, pre-flight and analyze entry points. Read-only harvest tooling and offline `scripts/prepare_firmware.py` source preparation are implemented |
| `containers/` | Podman build/analysis image, pinned gitleaks image digest, independent `gitleaks.toml`, `unpack.Containerfile` (pinned unblob + extractors) |
| `tests/` | Offline pytest suite (FakeClient, runtime-generated fixtures) |
| `justfile` | `build`, `test`, `build-unpack`, `unpack`, `test-unpack`, `preflight`, `redact`, `redact-unpacked`, `analyze`, `dry-run`, `analyze-review` (`PODMAN` env selects the podman command) |
| `hooks/` | Git hooks (`scripts/install-hooks.sh` enables them) |

## Setup

```sh
scripts/install-hooks.sh        # blocks committing .env / Anthropic keys
cp .env.example .env            # then fill in ANTHROPIC_API_KEY yourself
```

### Known-secret canaries and the API allowlist

```sh
just canary-init     # creates ~/.config/xe3000-open-firmware/canaries (mode 0600, empty); add one real secret per line
```

Canary values must be at least 6 characters, so 4-digit SIM PINs cannot be canaried (they are covered by the AT-command and `pin`/`puk` redaction rules only). `preflight` and `analyze` abort if any canary (plain, URL-encoded, base64 or hex) appears in any input file, printing only the file and line. Keep the file outside the repo; it is mounted read-only into the analyze container and never printed. Only files matching `containers/recon-allowlist.txt` are ever sent to the API; `--allow-extra GLOB` is an explicit, logged opt-in.

### Unpacking the stock image

```sh
just unpack path/to/stock-image.bin stock-4.8.3     # NAME must be new; nothing is ever deleted
```

`scripts/unpack.sh` runs `scripts/unpack.py` in the `unpack.Containerfile` image (no network, read-only rootfs, no capabilities; the staging mount is `noexec`). Nothing from the image is executed. Tar inputs are extracted member by member and skip traversal, symlink-through-directory writes, escaping hardlinks, device nodes and setuid bits; other images go through unblob, then every escaping symlink is removed. Output:

- `build/unpack/NAME/` is the unredacted staging tree, binaries included. It is gitignored and is never sent to any API.
- `unpacked/NAME/` holds only redacted rootfs text (the engine redactor, name exclusions for shadow, keys and dropbear), the kernel FIT, the DTBs (including FIT-embedded ones), `layout.json` (names only) and reports.

`just test-unpack` runs the real-tool end-to-end test (synthetic squashfs plus FIT/DTB through unblob) in the unpack image.

## Roadmap

1. **Phase 0** — scaffold and recon tooling implemented through PR #9; latest pre-gate suite passed 1,934 tests with 36 skips and 95% recon coverage; 81 host tests passed.
2. **Phase 1** — read-only harvest tooling implemented and local artifacts exist; safe input preparation and independent checks are complete. Human sample review and approval were confirmed in conversation. Provenance/completeness validation remains pending.
3. **Phase 2** — the six approved S5/S6 runs completed with partial extraction; curated S7 findings and an S8 summary are available with explicit limits.
4. **Phase 3** — [preliminary static upstream assessment](docs/findings/upstream-gap.md) exists; offline pinned source preparation completed in `build/firmware-v25.12.6`, state `prepared-unconfigured`; independent source verification passed. Separate r3 compilation and image inspection completed with independent local approval ([public verification summary](docs/evidence/firmware-r3.json)); reproducibility remains unproven; see [rollback planning](docs/prp/rollback-plan.md); eventual hardware validation requires approval of exact router commands.
5. Later: reproducible build recipe and container/CI, with patches and packages selected from reviewed evidence; validated recovery/rollback planning with bootloader untouched; parental-control integration. Existing local MHI, PCI power-management and MCU experiments are unverified inputs, not committed recipe decisions.

Offline source preparation usage and verification:

The offline helper requires a standalone local upstream Git repository containing the pinned commit. On a fresh checkout, follow the [optional online source bootstrap](recipe/README.md) first; it uses a new `build/upstream-source` path and preserves existing experiments.

```sh
python3 scripts/prepare_firmware.py --source build/upstream-source --out build/firmware-v25.12.6
python3 scripts/prepare_firmware.py --source build/upstream-source --out build/firmware-v25.12.6 --verify
```

The existing prepared destination is not overwritten. See [recipe details](recipe/README.md) for the source-only boundary and later build gates. No firmware configuration expansion, compilation or router operation is performed by this helper.
