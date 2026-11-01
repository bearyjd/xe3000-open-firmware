# Curated findings and coverage

Links into `build/`, `findings/raw/` or `/tmp/` refer to local evidence only; those files are not hosted in this repository. Local `build/openwrt` references describe the inspected checkout and any explicitly identified experiments, not a published upstream source snapshot.

The six user-approved paid S5/S6 extraction runs completed with terminal `ok` status. Extraction is partial. Independent mechanical audit verified 694 accepted records and 1,524 evidence items for schema, reconstructed chunk membership, line windows, normalized evidence/hash, canary sanitation and prepared provenance. Acceptance does not establish interpretation correctness or hardware behavior.

Publication selects twelve independently reviewed, bounded interpretations across [AT references](at-commands.md), [RPC/access control](gl-rpc-map.md), [modem initialization](modem-boot-flow.md) and [hardware references](hardware.md). All twelve ungrounded records and semantic quarantines are excluded from conclusions. The semantic pass was not exhaustive approval of all 694 records. [Summary](summary.md), [independent stock observations](stock-observations.md), [preparation](preparation.md) and [upstream gaps](upstream-gap.md) preserve remaining limits.

| Run | Accepted records | Ungrounded | Rejection events | Unresolved chunks | Recorded USD |
| --- | ---: | ---: | ---: | ---: | ---: |
| harvest | 159 | 7 | 18 | 3 | 0.040812 |
| at-commands | 31 | 0 | 10 | 2 | 0.033483 |
| gl-rpc-map | 192 | 1 | 42 | 3 | 0.059697 |
| modem-boot-flow | 158 | 2 | 75 | 25 | 0.066842 |
| fan-led-mcu-battery | 51 | 2 | 7 | 1 | 0.032356 |
| wifi-driver | 103 | 0 | 29 | 2 | 0.048720 |
| Total | 694 | 12 | 181 | 36 | 0.281910 |

Recorded commitments total $0.716756063; recorded usage is $0.281910. Billing is unverified. All runs remain within approved $5 and 500,000-input-token caps ($30 summed dollar caps within the earlier $60 budget). Caps are limits, not estimates. Legacy live manifests lack configured cap fields: provenance is the approved analysis plan and launch arguments, not retroactively inserted fields.

Coverage limits: 24 chunks skipped retries at input caps (23 modem, one fan); 19 truncation events affected 12 distinct chunks. Rejection events include earlier attempts and are not 181 unique failed chunks. Thirty-six final-attempt chunks retain unresolved rejections. Masking/credential omissions also remove context; stock RPC extractor records fell from 355 to 281 while AT records remained 60. These are records, not unique methods, and losses cannot be attributed entirely to secrets rather than useful code.

The local [final audit](../../build/review-20261031/findings/raw/final-audit.md), [machine audit](../../build/review-20261031/findings/raw/final-audit.json) and [interpretation review](../../build/review-20261031/findings/raw/claim-review.md) retain detailed provenance/quarantine identifiers. No exhaustive absence claim, duplicated claim count, source default or generic model branch establishes XE3000 runtime behavior.

Offline source preparation completed with exit 0 at `build/firmware-v25.12.6/{checkout,manifest.json}`: OpenWrt `v25.12.6`, commit `64900e756efa667774214f9c6b17c113222e01f7`, five exact feed pins and a three-line target seed, with independent object copies. State is `prepared-unconfigured`, `production_ready=false`, `firmware_build_complete=false`. Six original metadata/experiment hashes remain unchanged. Independent verification of the actual prepared output passed (`--verify` exit 0), recorded in `build/firmware-v25.12.6/independent-verification.json`. See the [source recipe](../../recipe/README.md). Separate r3 environment capture, pinned feed installation, configuration, compilation and image inspection completed with independent local approval; see the [public verification summary](../evidence/firmware-r3.json). Reproducibility remains unproven. Source preparation, compilation and runtime acceptance are separate; no firmware was flashed and no router action occurred.

Latest pre-gate tests: 81 host tests passed; 1,934 offline tests passed, 36 skipped, 95% recon coverage. New cap fields apply to future run manifests; the six completed legacy manifests retain plan/launch-argument cap provenance.
