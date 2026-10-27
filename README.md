# xe3000-open-firmware

An up-to-date, reproducible OpenWrt for the **GL.iNet GL-XE3000 (Puli AX)**.

This is a *recipe repo*, not a fork: a pinned upstream OpenWrt 25.12.x tag, a few patches, a `files/` overlay and a small package feed. The XE3000 is the primary home router, so the device is treated as production.

## Status

Phase 0 — scaffold and LLM-assisted recon engine, built and tested on synthetic fixtures only. No router contact yet.

## License

**GPL-2.0-only.** Kernel patches must be GPL-2.0, so this repo does not use the author's usual AGPL. See `LICENSE`.

## Guardrails

- Never flash, sysupgrade, write mtd/eMMC/boot partitions, `fw_setenv`, change UCI, or reboot the router.
- Router commands are read-only; the only permitted write is `/tmp`, and only in approved phases. No opkg installs.
- No AT commands to the modem.
- Secrets (shadow, host keys, Wi-Fi/VPN keys, PPPoE creds, tokens, ICCID/IMSI/IMEI) are never collected, or are redacted before leaving `harvest/raw/`.
- `harvest/raw/` is gitignored and **never** sent to any external API.
- No GL proprietary binaries or UI in the repo: findings and notes only.
- Every router-touching step is shown as an exact command list and approved first.

## Layout

| Path | Purpose |
|------|---------|
| `docs/prp/` | Product requirement prompts (written before implementation, with devil's-advocate review) |
| `docs/findings/` | Generated findings (from `findings/raw/`) |
| `scripts/` | `recon/` engine plus redaction, pre-flight and analyze entry points. Harvest tooling (`scripts/remote/collect.sh`) is Phase 1, planned, not written yet |
| `containers/` | Podman build/analysis image, pinned gitleaks image digest, independent `gitleaks.toml` |
| `tests/` | Offline pytest suite (FakeClient, runtime-generated fixtures) |
| `justfile` | `build`, `test`, `preflight`, `redact`, `redact-unpacked`, `analyze`, `dry-run` (`PODMAN` env selects the podman command) |
| `hooks/` | Git hooks (`scripts/install-hooks.sh` enables them) |

## Setup

```sh
scripts/install-hooks.sh        # blocks committing .env / Anthropic keys
cp .env.example .env            # then fill in ANTHROPIC_API_KEY yourself
```

## Roadmap

1. **Phase 0** — scaffold + recon engine (this PR).
2. **Phase 1** — live read-only harvest, redaction, secrets pre-flight.
3. **Phase 2** — static analysis of the stock image (AT commands, GL RPC map, modem boot flow).
4. **Phase 3** — gap analysis against upstream OpenWrt 25.12.x.
5. Later: build recipe (pinned tag, `prepare.sh`, MHI patch, `pcie_port_pm=off`, XE3000 `gl-puli-mcu`, SIM-select script, uci-defaults); podman build container + CI; flash/rollback runbook (stock U-Boot web recovery, back up eMMC first, bootloader untouched); parental-control integration (nftables sets, rpcd ACL user for the access-control app and Vigie).
