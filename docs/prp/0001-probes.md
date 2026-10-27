# PRP 0001 — Recon engine and read-only probes of the stock GL-XE3000

Status: DRAFT, awaiting approval · Branch: `feat/0001-recon-engine` · License: GPL-2.0-only

## 1. Goal

Learn exactly what stock GL.iNet firmware 4.8.3 does on the XE3000 that upstream OpenWrt 25.12.x does not, without risking the production router and without leaking secrets.

Recon is **deterministic collection plus LLM analysis**. The model never gets a shell on the router and never sees unredacted data.

Out of scope here: any build recipe, flashing, or changing the router in any way.

## 2. Data flow and trust zones

```
router --(ssh, read-only, one session)--> harvest/raw/<ts>.tar   [ZONE RAW: local only, gitignored]
        redact.py --> harvest/redacted/ + redaction-report.json   [ZONE REDACTED]
        preflight (gitleaks, container, independent rules) --> stamp
        stock image --(unblob, container)--> unpacked/            [ZONE REDACTED after redact.py pass]
        analyze (container) --> findings/raw/<run-id>/            [ZONE FINDINGS]
        report.py --> docs/findings/*.md (committed)
```

Only ZONE REDACTED data may reach the Claude API. ZONE RAW is never mounted into the analysis container, so a bug in path checks cannot expose it.

## 3. Recon engine design

Package `scripts/recon/`, entry points `scripts/analyze.py`, `scripts/redact.py`, `scripts/preflight.py`.

| Module | Responsibility |
|---|---|
| `paths.py` | Allowlist: a path is accepted only if `resolve()`d it `is_relative_to` `harvest/redacted/` or `unpacked/`. Anything under `harvest/raw/` is refused, including `..` traversal and symlinks inside allowed dirs that point out. |
| `redact.py` | Rule-based redaction (§5). Emits a report of `{file, rule, count}` and never values. |
| `preflight.py` | Host wrapper: runs gitleaks in a container with `--redact` and a custom config over the input set, mounting only the input dirs read-only. On success writes a stamp `cache/preflight/<tree-sha256>.ok`. |
| `groundtruth.py` | Deterministic extractors for AT commands, ubus/RPC method names, GPIO numbers, module names. These lists are canonical. |
| `chunking.py` | Splits inputs by artifact type (init/hotplug scripts, UCI configs, DTS/DTB, dmesg, module info, rootfs scripts, RPC handlers, HAR). Each chunk is line-numbered. |
| `prompts.py` | Per-artifact-type task prompt plus one shared system prompt. `PROMPT_VERSION` participates in the cache key. |
| `schema.py` | Finding schema (below) and the code-side validator. |
| `client.py` | Anthropic SDK wrapper: structured outputs, cached prefix, batches, token counting, error scrubbing. |
| `cache.py` | `cache/responses/<sha256(chunk + PROMPT_VERSION + model + SCHEMA_VERSION + schema hash + prompt hash + max_tokens)>.json`. Only fully clean chunk results are stored; hits are re-validated and `ungrounded` recomputed. |
| `cost.py` | Worst-case cost estimator and cap enforcement. |
| `report.py` | Generates `docs/findings/*.md` from `findings/raw/<run-id>/`. Every row links its evidence. |

### 3.1 API usage (verified against platform.claude.com/docs on 2026-10-26)

- Python `anthropic` SDK. `ANTHROPIC_API_KEY` is loaded with `python-dotenv` (host) or `podman run --env-file` (container). It is never printed, logged, cached, put in a cache key, or included in an error message; exceptions are scrubbed of any `sk-ant-` match before display.
- Models from env: `LLM_MODEL` (default `claude-sonnet-5-5`), `LLM_MODEL_CHEAP` (default `claude-haiku-5-5`, bulk triage). `claude-opus-5-5` only for the final gap-report synthesis behind `--synthesize`.
- **Structured outputs:** `output_config={"format": {"type": "json_schema", "schema": ...}}`. No beta header. Docs list all three models as supported, so no strict-tool-use fallback is built. Do not use the deprecated `output_format` param.
  - Schema limits: `additionalProperties: false` on every object; no `minLength`/`maxLength`/`minimum`/`maximum`/`pattern`-style constraints. So evidence presence cannot be enforced by the schema and is enforced in code (§3.3).
- **Sampling params:** `temperature`/`top_p`/`top_k` are rejected on Sonnet 5.5 and are not sent. Determinism comes from the cache, not sampling. `max_tokens` covers thinking plus text.
- **Prompt caching:** `cache_control: {"type": "ephemeral"}` on the last block of the `system` array (shared system prompt plus per-task instructions). Minimum cacheable prefix is 512 tokens on these models. Changing `output_config.format` invalidates the cache, so the schema is fixed per run.
- **Batches:** bulk passes (hundreds of chunks) use `client.messages.batches.create` with identical cached prefixes, 50% discount. Docs do not confirm `output_config` inside batch requests, so the batch path is verified by one tiny live batch on fixtures before it is trusted; until then it is reported as unverified.
- **Token counting:** `client.messages.count_tokens(model, system, messages, output_config)` for the pre-send estimate. Counts are model-specific (new tokenizer), so counted per target model.

### 3.2 Finding schema

```
{ "findings": [ {
    "claim": str, "category": enum, "confidence": enum[high|medium|low],
    "evidence": [ {"file": str, "line": int, "excerpt": str} ]
} ] }
```

`categories`: `at-command`, `rpc-method`, `gpio`, `modem-power`, `sim`, `battery-mcu`, `fan`, `led`, `network`, `wifi`, `storage`, `boot`, `other`.

The model supplies a verbatim excerpt and line number. The **engine** verifies it and computes `excerpt_sha256` itself; the model is never trusted to hash.

### 3.3 Validation (in code, after schema validity)

1. At least one evidence item per finding.
2. `evidence.file` must be one of the files in that chunk's input set.
3. The excerpt must occur (whitespace-normalized) within ±2 lines of the cited line. Otherwise rejected.
4. Ground-truth check: AT commands, GPIO numbers, RPC method names and module names mentioned in a claim must exist in the ground-truth lists for the input set; otherwise the finding is flagged `ungrounded` and shown as such in reports, never silently dropped.
5. Rejected outputs are retried up to 2 times with the specific rejection reason; after that they are recorded in `findings/raw/<run-id>/rejected.jsonl` and excluded from reports.

### 3.4 Cost and token caps

- Before any send: `count_tokens` for every uncached chunk. Worst-case cost = counted input tokens at the base input price **including the 1.25x cache-write premium on all counted input** (cache read discounts ignored) + `max_tokens` at the output price, per model, with the 50% factor only for batch runs.
- Cap from `--max-usd` (env `RECON_MAX_USD`; fixture default $0.25) and `--max-input-tokens`. The estimate is printed first. If the worst case exceeds the cap, **nothing is sent**.
- Cached chunks cost nothing and are excluded from the estimate. Haiku's 100K-token prompt price tier is priced at the higher rate when a chunk exceeds it.
- Pricing table lives in `cost.py` with its source URL and date; a test fails if a configured model has no price entry.

### 3.5 Enforced pre-flight

`analyze.py` refuses to run unless a stamp exists for the current hash of the input tree, so "pre-flight before every run" cannot be skipped. Any gitleaks hit aborts and prints **file, line and rule only** (gitleaks runs with `--redact`).

## 4. Containers

- `containers/recon.Containerfile`: Python plus pinned `anthropic`, `python-dotenv`, `jsonschema`, `pytest`. Tests and the engine run here, not on the host.
- Gitleaks runs from a pinned official image with a custom `containers/gitleaks.toml`.
- Mounts: absolute host paths, `:z` (never `:Z` on the repo), inputs read-only. Only `harvest/redacted/`, `unpacked/`, `cache/`, `findings/raw/` and the code are mounted; **never the repo root** and never `harvest/raw/`. The key enters only through `--env-file`.
- On this host `podman` is `distrobox-host-exec podman`; the `justfile` takes the command from `PODMAN`.

## 5. Redaction rules (`redact.py`)

Applied to every collected text file; binary artefacts are not sent to the model at all (derived text only).

| Rule | Matches |
|---|---|
| `uci-sensitive` | `option`/`list` whose name matches `key|psk|pass|passwd|password|secret|token|private|auth|sid|hash|cert|username` (username covers PPPoE) |
| `wifi-psk` | `psk=`, `sae_password=`, `wpa_passphrase=`, `password=` in hostapd/wpa_supplicant style files |
| `wg-key` | `PrivateKey`/`PresharedKey` lines, `private_key`/`preshared_key` options, any standalone 44-char base64 ending `=` |
| `pem-block` | any `-----BEGIN ... PRIVATE KEY-----` block through its END |
| `pw-hash` | `$1$ $5$ $6$ $y$ $p$` crypt hashes |
| `imei` | 15 digits passing Luhn, or digits after an `IMEI`/`MEID` label |
| `imsi` | digits after an `IMSI` label |
| `iccid` | `89` + 17–18 digits, or digits after an `ICCID` label |
| `token` | `Bearer …`, `sk-…` style keys, long hex/base64 after `token|secret|key|sid|cookie` labels |
| `mac` | pseudonymized: OUI kept, remainder replaced by a stable salted hash (client devices are family members' phones) |

Replacement is `<REDACTED:rule>`. The report lists file, rule and count only. Hard exclusions happen **at collection**, before redaction: `/etc/shadow`, `/etc/dropbear/*`, any `*_host_key`, `*.pem`/`*.key` files, USB `serial` attributes.

The pre-flight is deliberately **independent**: `gitleaks.toml` has its own rules for the same classes (UCI secret options, WireGuard keys, Luhn IMEI-like digit runs, ICCID, PSK lines). A test disables one `redact.py` rule, runs the redactor, and asserts the pre-flight aborts on exactly that planted secret.

### Layers (defence in depth)

Regex redaction is a blacklist and **cannot be complete** (an adversarial review of the first implementation leaked 48 of 100 hostile inputs). It is therefore only one of five layers, and none of them is trusted alone:

1. **Name exclusion**, at redaction and again at load time: `shadow`, `serial*`, `dropbear/*`, `*_host_key`, `*.pem`/`*.key`, `chap-secrets`, `pap-secrets`, `ipsec.secrets`, `*.psk`, `*.secrets`, `*.auth`, `*wpa_psk*`, `auth-user-pass`, `htpasswd`. These files carry unlabelled secrets that no text rule can see.
2. **Redaction** (`redact.py`, table above plus: URL userinfo, command-line forms such as `curl -u`/`sshpass -p`/`chpasswd`, JSON/XML/HTML/YAML forms, inline key blocks, 64-hex PSKs, base64 blobs, AT PIN/credential arguments). Rules repeat to a fixed point. The engine re-runs the redactor in memory over **every** text file it sends, not only `unpacked/`.
3. **Independent gitleaks pre-flight** with its own regexes and entropy rules (stamp bound to tree, config and image digest).
4. **Default-deny API allowlist**: `analyze.py` sends only files matching `containers/recon-allowlist.txt` (init/hotplug scripts, hardware configs by name, dmesg, DTS, module lists, ubus method lists). Everything else is listed under `denied` in the manifest and never sent. `--allow-extra GLOB` is an explicit opt-in, printed and recorded in the manifest. Files such as `ps`, `logread`, crontabs and `etc/config/{wireless,network,rpcd,vpn*,wireguard*,ddns}` are deliberately not on it.
5. **Known-secret canaries**: an optional 0600 file (`$RECON_CANARY_FILE` or `~/.config/xe3000-open-firmware/canaries`, created by `just canary-init`) holds the owner's real secrets. If any appears in ANY input file, including denied ones, as plain text, case-folded, URL-encoded, base64 or hex, the pre-flight and `analyze.py` abort and print only file and line. When a real harvest is detected (marker written by `redact.py`) and no canary file exists, they refuse unless `--no-canary` is given (fixture runs use that flag). The file is never copied into the repo; the analyze container gets it as a read-only mount only.

Residual risk, stated plainly: an unlabelled secret that is not in the canary file, not in an excluded file name and not recognised by any pattern, inside a file that is on the allowlist, would still be sent. The allowlist keeps that surface small (scripts, DTS, dmesg), and the canaries cover the secrets the owner knows about.

## 6. Harvest command list (Phase 1, NOT run in Phase 0)

Transport: one `ssh -o BatchMode=yes -o ConnectTimeout=10 root@$ROUTER_HOST 'sh -s' < scripts/remote/collect.sh`, streaming a framed text stream (`@@BEGIN kind name` … `@@END`) back over stdout; the workstation splits it into `harvest/raw/<ts>/` and tars it. Nothing is written on the router, not even `/tmp`. Binary data (the DTB) is streamed as hex via `od`. busybox `ash`; each command is wrapped so a missing command logs `@@MISSING <cmd>` and the script continues.

**Identity**
`cat /etc/openwrt_release` · `cat /etc/glversion` · `uname -a` · `cat /proc/cpuinfo /proc/meminfo /proc/cmdline /proc/mtd` · `cat /proc/partitions` (names and sizes only)

**Hardware**
`od -An -v -tx1 /sys/firmware/fdt` (raw flattened DTB; decompiled on the workstation) · property-by-property listing of `/proc/device-tree` as a fallback · `ls -l` + reading `vendor device subsystem_vendor subsystem_device class` and the `driver` symlink name under `/sys/bus/pci/devices/*` · `idVendor idProduct manufacturer product` under `/sys/bus/usb/devices/*` (never `serial`) · `ls -l /sys/class/leds` + `brightness max_brightness trigger` · `ls -l /sys/class/gpio` · `/sys/kernel/debug/gpio` **only if already mounted and readable** (never mount it) · `name temp*_input fan*_input pwm*` in `/sys/class/hwmon/*` · `type temp policy` in `/sys/class/thermal/*` · all readable attributes except `serial_number` in `/sys/class/power_supply/*`

**Kernel**
`lsmod` · `modinfo $m` for each module if `modinfo` exists, otherwise `/sys/module/$m/{version,srcversion,taint,parameters/*}` · `dmesg` (no `-c`/clear) · `ls -lR /lib/modules`

**System**
`ubus -v list` · `ubus call system board` (the only `ubus call`) · `ps w` (treated as secret-bearing) · `netstat -lntup` or `/proc/net/{tcp,tcp6,udp,udp6}` · `ls -l /etc/init.d /etc/rc.d /etc/hotplug.d/*` + `cat` of each init and hotplug script · `cat /etc/crontabs/*` · `logread` (snapshot)

**Config**
`cat /etc/config/*` — except that `rpcd`, GL cloud/bind configs and wireless/network/vpn files are known to carry secrets and rely on redaction

**Modem (ports and owners only, no AT traffic)**
`ls -l /dev/ttyUSB* /dev/ttyACM* /dev/cdc-wdm* /dev/wwan* /dev/mhi* /dev/mhi_*` · `ls -l /proc/[0-9]*/fd 2>/dev/null` filtered for those device nodes, mapped to `/proc/<pid>/comm` and `cmdline` (process name only is kept)

Nothing in this list writes, mounts, loads modules, calls `ubus call` besides `system board`, opens a modem port, or touches `/sys` attributes that are write-only or have read side-effects.

## 7. Outputs

- `harvest/redacted/`, `redaction-report.json`, preflight stamp
- `findings/raw/<run-id>/{findings.jsonl,rejected.jsonl,usage.json,manifest.json}` plus `synthesis.md` with `--synthesize`. A batch run's manifest has status `batch-pending` (and the `batch_id`) from creation until it completes; `--resume-batch` only accepts that status, the same input tree, model and `max_tokens` (manifest: model, prompt version, input hashes, estimated and actual tokens/cost)
- `docs/findings/*.md` generated by `report.py`

## 8. Test plan (Phase 0, synthetic fixtures only)

Fixtures are generated in pytest `tmp_path` at test time so planted fake secrets never exist in the repo and cannot trip the hook, GitHub push protection or any future CI scan. Fake keys are assembled at runtime.

1. `redact.py` removes every planted secret (Wi-Fi PSK, WireGuard key, IMEI, ICCID, IMSI, password, PEM block, token, crypt hash).
2. Pre-flight catches each secret class when its redaction rule is disabled.
3. `analyze.py` refuses `harvest/raw/` (direct, `..` traversal, symlink inside `redacted/` pointing to `raw/`).
4. Findings without valid evidence are rejected and retried; a claim citing an AT command not in ground truth is flagged.
5. Cost cap stops a run before any send when the worst case exceeds the cap.
6. Error scrubbing: a forced SDK error message containing a fake key never surfaces it.
7. Live: small real calls against fixtures under a $0.25 cap, including one tiny batch.

## 9. Risks

| Risk | Mitigation |
|---|---|
| Secret reaches the API | Raw never mounted; allowlist; redactor; independent gitleaks pre-flight stamp; scrubbed errors |
| Redaction removes useful signal | Report lists rules and counts; spot-check by the user before Phase 2 |
| Harvest affects the router | Read-only command list; user approves it before it runs; one session, no writes |
| Reading sysfs/debugfs has side effects | Attribute allowlist; debugfs only if already mounted |
| LLM hallucinated claims | Evidence verified in code; ground truth from grep wins; `ungrounded` flagged |
| Cost overrun | Worst-case cap, cache, cheap model for triage, Opus only behind a flag |
| Unhashed pip installs in the recon image | Versions are pinned but not hash-pinned (`--require-hashes` not used); accepted risk for Phase 0, base image and gitleaks are digest-pinned |
| API/model behavior drifts | Params verified against docs; pricing table dated; schema versioned in cache key |
| Closed GL code can't be fully read | Findings label behavior only; nothing proprietary is copied into the repo |

## 10. Devil's advocate (to be completed before merge)

Questions the reviewer must answer, with answers recorded here after the review pass:

1. **Is an LLM needed at all?** Grep and `dtc` give the lists; the model only labels purpose and links. If findings are mostly restatements of the ground truth, the engine is overhead. Test: do fixture findings add anything not in the ground-truth lists?
2. **Is redaction trustworthy?** No. Regexes miss novel formats, and the first implementation leaked 48 of 100 adversarial inputs, so the design now assumes regex redaction **cannot be complete** and adds name exclusions, a default-deny allowlist and known-secret canaries (the layers under section 5). The gitleaks pre-flight uses different rules but is also pattern based. Residual risk is nonzero (see the layers under section 5); spot-check of what is actually sent (`manifest.json` lists sent, denied and skipped files) is required before Phase 2.
3. **Does the evidence check just create confidence theater?** A verbatim excerpt proves the text exists, not that the claim follows from it.
4. **Is the single-session ssh stream fragile?** A dropped connection yields a partial harvest; the engine must mark partial frames, not analyze them as whole.
5. **Is `/sys/firmware/fdt` the live tree?** It is the DT the kernel booted with, which is what we want, but GL's U-Boot may patch it at boot, so it can differ from the DTB in the image. Both are collected on purpose.
6. **Cost of being wrong on Batches + structured outputs.** Docs are silent; hence the live batch check.
7. **Why not just reverse the image offline and skip live probing?** Runtime state (which process owns which modem port, actual GPIO states, loaded module params) is not in the image. Live probing is still worth it, but each probe must justify itself against what Phase 2 can learn statically.

---

## 11. Phase 0 results and review (2026-10-26)

**Tests:** 293 passed, 1 skipped (the single test that needs nested podman), 97% line coverage, run in the recon container. The host-podman pre-flight path was checked by hand: clean tree gives a stamp; with one redaction rule disabled it aborts printing file, line and rule only.

**Live checks on synthetic fixtures** (planted fake secrets generated at run time, redacted, pre-flighted, then analysed):

| Check | Result |
|---|---|
| Sonnet 5.5 interactive run, 6 chunks | 12 accepted, 0 rejected, actual $0.0386 (worst-case estimate $0.1414, cap $0.25) |
| Re-run with identical input | 6/6 chunks served from cache, $0.0000 |
| Cap enforcement | a run whose worst case was $0.2643 was refused before anything was sent |
| Haiku 5.5 batch with `output_config` | accepted by the API; resumed from the saved batch id: 13 accepted, 1 rejected, actual $0.0013. The doc gap (batch + structured outputs) is closed. |

**Independent reviews** (code-reviewer and security-reviewer, run separately from the authoring pass) found 0 critical, 3 high and ~14 medium/low issues. All were fixed with tests: cache poisoning by rejected or cap-skipped results, an unbudgeted sync fallback after batch errors, lost work on mid-run failure, a non-upper-bound cost estimate, nan/inf cap values, an incomplete cache key, a read-versus-hash gap on file contents, binary files, redaction gaps (JSON secrets, GL login hash/sid, prefixed names, SIM PIN, PGP/unterminated PEM, bare IMSI, other MAC/IPv6 forms), a forgeable pre-flight stamp, markdown injection into committed reports, container hardening and the pre-commit hook's handling of unusual paths.

**Defects found only by live runs:** a single poll timeout killed a batch run (fixed: free polling calls retry, `--resume-batch` added); a false-positive `ungrounded` flag on prose such as "RPC method for" (fixed).

### Devil's-advocate answers

1. *Is an LLM needed?* On fixtures the findings mostly restate ground truth with a purpose label (AT+CFUN=1 written at start, GPIO 12 exported, fan on a GPIO). The value is in linking items across files, which only real data can show. **Decision:** keep, but Phase 2 reports must separate "restates ground truth" from "adds a link", and the engine stays optional for anything grep can answer.
2. *Is redaction trustworthy?* The review found real gaps and they were closed, but it is still pattern based and the gitleaks layer shares the author's assumptions. **Residual risk accepted with a gate:** the user spot-checks `redaction-report.json` and a sample of `harvest/redacted/` before any Phase 2 API call.
3. *Evidence check is theater?* Partly. It proves the text exists near the cited line (and now requires at least 8 non-space characters), not that the claim follows. Reports show the evidence so a human can judge.
4. *Fragile ssh stream?* Open for Phase 1: a partial frame must be marked partial and excluded from analysis.
5. *`/sys/firmware/fdt` versus image DTB?* Both are collected on purpose; the diff is itself a finding.
6. *Batch plus structured outputs?* Verified live (above).
7. *Skip live probing?* Kept, because runtime ownership of modem ports and live GPIO/module state is not in the image, but every probe in §6 should justify itself.

### Known limitations
- The `ungrounded` heuristics for prose RPC names are best effort.
- Retries run as normal calls at full price, even in batch runs.
- Prices are copied from the docs table dated 2026-10-26 and must be refreshed when models change.
