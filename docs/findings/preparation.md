# Prepared analysis inputs

Links into `build/`, `findings/raw/` or `/tmp/` refer to local evidence only; those files are not hosted in this repository. Local `build/openwrt` references describe the inspected checkout and any explicitly identified experiments, not a published upstream source snapshot.

Evidence snapshot: 2026-10-31. This records local preparation and independent technical verification, not completed real S5/S6 analysis or production hardware findings.

The original input trees remain unchanged and still fail preflight with 5,689 hits across 563 files. A separate prepared tree at `build/review-20261031` passes the exact full-tree and scoped preflight gates using the unchanged pinned scanner policy. It contains 4,371 files, with 5,687 scanner-reported ranges masked and 13 credential-named files omitted before reading. Whole-range masking can remove useful context; passing a scanner does not prove completeness or absence of all secrets.

Independent review verified every source/copy/output hash, inventory consistency, inode separation, all three identical scanner policies and the preparation stamp. Checks found zero canary filename/content hits with one configured canary. The preparer and launch adapter passed adversarial reviews covering known-secret filenames, excluded-credential read ordering, mount aliases and inventory-read fixes. Trusted source/scripts are kept separate from prepared data; the launch path does not mount original raw inputs.

Inventory records before and after preparation show measurable context loss. These are extractor records, not unique RPC methods or proof of retained behavior. Stock AT records remain 60, while stock RPC records fall from 355 to 281. No conclusion attributes the lost records entirely to secrets rather than valid code or context; human utility review remains necessary.

| Input | AT records | RPC records | GPIO records | Module records | Init records |
| --- | --- | --- | --- | --- | --- |
| Harvest, original → prepared | 7 → 7 | 18 → 18 | 15 → 15 | 212 → 211 | 0 → 0 |
| Stock, original → prepared | 60 → 60 | 355 → 281 | 4 → 4 | 238 → 237 | 107 → 107 |

The local [review packet](../../build/review-20261031/REVIEW.md) links four representative masked/unmasked harvest/stock samples, [review metadata](../../build/review-20261031/review.json) and the [analysis plan](../../build/review-20261031/analysis-plan.json). These local, ignored artifacts are not published findings. The user confirmed human sample review and explicitly approved the exact six API runs in the analysis plan in conversation, then instructed continuation. This satisfies the pre-call approval gate under [PRP 0001](../prp/0001-probes.md); `analysis-plan.json` now records `approved-by-user`. The six runs completed through the reviewed adapter with partial extraction; see [curated coverage/accounting](index.md). This approval does not authorize router changes or flashing.

The plan has six cheap batch runs: harvest, AT commands, GL RPC map, modem boot flow, fan/LED/MCU/battery and Wi-Fi driver. Each has a $5 cap and a 500,000-input-token cap; the summed dollar caps are $30 within the earlier $60 project budget. These are limits, not cost estimates. No external token-count or inference call, router operation or flashing occurred during preparation.

Latest pre-gate verification passed: **81 host tests; 1,934 offline tests passed, 36 skipped, 95% recon coverage**. Earlier preparation-stage checks follow. Separate host scanner/integration checks passed 9 tests; CI/hook/launch checks passed 53 with zero skips; all 41 firmware-source preparation tests passed. Human approval, six paid runs, independent output/claim review and curated publication are complete. The pinned source baseline was prepared and independently verified at `build/firmware-v25.12.6`; original experiments remain unchanged. Its preserved state remains `prepared-unconfigured`. Separate r3 configuration, compilation and image inspection subsequently passed independent local verification; see the [public verification summary](../evidence/firmware-r3.json). Reproducibility and hardware validation remain open. The [upstream assessment](upstream-gap.md) records the remaining build and hardware gates.

Recorded usage totals $0.281910 and commitments $0.716756063; billing is unverified. Legacy run manifests omit configured cap fields, so cap provenance remains the approved plan/launch arguments. Partial extraction and quarantine details are in the [findings index](index.md).
