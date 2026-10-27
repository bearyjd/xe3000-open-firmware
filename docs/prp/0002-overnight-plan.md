# PRP 0002 — Overnight autonomous plan

Status: APPROVED (summary) · Related: PRP 0001 (probes), PRP 0003 CI (this stage, S0)

## 1. Goal

Advance the recon of the stock GL-XE3000 as far as possible unattended, one reviewed and CI-gated feature at a time.

## 2. Stages

| Stage | Scope |
|---|---|
| S0 | CI: tests, shellcheck, gitleaks with baseline, pre-commit hook tests; this plan doc |
| S1 | Fix the 6 known synthetic test strings so the gitleaks baseline can be retired |
| S2 | Read-only harvest collector (`scripts/remote/collect.sh`) |
| S3 | Run the harvest, redact, preflight (local only) |
| S4 | Read-only `/rom` inspection and firmware unpack in containers |
| S5 | Analyze redacted harvest via the recon engine (budgeted) |
| S6 | Analyze unpacked firmware text via the recon engine (budgeted) |
| S7 | Findings reports under `docs/findings/` (findings and notes only) |
| S8 | Consolidated summary and open questions for the morning |

## 3. Per-feature pipeline and merge gates

Each stage works in its own git worktree and branch, then: commit, push, open a PR, TDD (commit 1 tests only and failing, commit 2 implementation), adversarial review, and merge only when CI is green. No force-push, no push to main, no branch deletion.

## 4. Hard rules

- Secrets: never read `.env`, never print key values, never send `harvest/raw/` or config backups to any API.
- Anthropic API only through the repo engine, with `--max-usd` per run, on redacted or allowlisted input.
- No real data, home-network addresses, secrets or GL proprietary binaries or UI in the repo or PR text.
- Heavy artifacts go to gitignored `unpacked/` and `build/`.

## 5. Budget and router scope

- Anthropic API budget for the whole night: 60 USD.
- The router is production and strictly read-only: harvest via listed read-only commands plus read-only `/rom` inspection. No flashing, UCI changes, package installs, reboots, file writes, modem ports or AT commands, and no shadow file, host keys or private keys.
