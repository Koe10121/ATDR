# v4.1 Schema-Aware SOC Queue Model Redesign

Date: 2026-07-14

Status: completed as a read-only development diagnostic. Readiness remains `candidate_only`.

## Purpose

v4.0 proved that the frozen Palo Alto-oriented supervised queue did not generalize to an external network-flow schema: it produced benign-like FPR `1.0000` on the locked provider-blinded benchmark. v4.1 redesigns the diagnostic pipeline around explicit evidence schemas rather than filling missing firewall fields with invented values or tuning against the v4.0 labels.

This phase does not activate or promote a model, write an active artifact, modify operational labels, create detection runs, create response actions, enable automatic response, or enable real firewall blocking.

## Evidence Boundary

The following v4.0 evidence is machine-locked by file name and SHA-256 before and after every v4.1 run:

- two v4.0 CSE-CIC-IDS2018 provider files;
- v4.0 pre-label manifest and feature-only sample;
- v4.0 frozen predictions and revealed labels;
- v4.0 final evidence manifest.

The lock denies every v4.1 development role: feature engineering, fit, calibration, threshold selection, and candidate selection. v4.1 records `v400_locked_rows_used=0` and `v400_locked_labels_used=0`.

The selected development-only corpus is three distinct, checksum-verified CSE-CIC-IDS2018 flow days:

| Day | Scenario | SHA-256 |
| --- | --- | --- |
| 2018-02-15 | DoS GoldenEye and Slowloris | `fa2947a8256d81ee9103ae16139d62d0e17aa23e696ee80d9e76fb51c01c9c4b` |
| 2018-02-22 | Web brute force, XSS, SQL injection | `da33c927018274f9d49b145baa00e4ce0526c25b3b890b34c489e247b5e24544` |
| 2018-03-02 | Bot activity | `d96f38e7496aba83475031e6fb8c6fdf1abf6aa1b71325a917798f3c7de93de1` |

The corpus is published by the Canadian Institute for Cybersecurity. Its official dataset page documents the traffic scenarios and flow data; the official AWS registry provides the public collection entry. [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html), [AWS Open Data Registry](https://registry.opendata.aws/cse-cic-ids2018/).

Provider labels remain `human_reviewed=false`, `import_ready=false`, and are not inserted into ATDR operational tables. Generated samples, manifests, and reports stay ignored under `.tmp/` and `ml_baseline_reviews/`.

`UNSW_NB15_testing-set.csv` is reserved as a future untouched benchmark. It was not downloaded, inspected, sampled, or used by v4.1. The official UNSW-NB15 page describes the testing partition and academic-use terms. [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset).

## Schema Contracts

`atdr/app/detection/schema_contracts.py` defines explicit contracts for four evidence forms:

| Schema | Required evidence | Important unavailable fields | Rule policy |
| --- | --- | --- | --- |
| `palo_alto` | timestamp, source/destination identity, destination port, protocol, action, application | none declared unavailable | firewall and behavior rules apply only when supporting fields exist |
| `generic_syslog` | timestamp and raw evidence | zones and app risk | parsed-field rules are conditional; parse-quality remains available |
| `provider_flow` | timestamp, destination port, protocol, directional bytes, packets, duration | source/destination IP, action, app, zones, app risk, behavior windows, raw evidence | byte/packet volume rules apply; unsupported rules remain unavailable |
| `raw_fallback` | timestamp and raw evidence | structured network fields | parse-quality only |

Common features include schema flags, field-availability indicators, protocol family, volume/rate features, and time-of-day. Missing values remain missing and receive missingness indicators. They are never converted into fabricated IPs, actions, applications, zones, or behavior windows.

## Evaluated Strategies

v4.1 compares the following diagnostics without writing an active artifact:

- firewall-specific calibrated ExtraTrees;
- provider-flow raw and calibrated ExtraTrees;
- provider-flow calibrated Logistic Regression;
- provider-flow three-class SOC queue;
- benign-fit IsolationForest;
- provider-flow applicable-rules-only score;
- provider-flow rule/anomaly/supervised hybrid;
- pooled common-feature calibrated ExtraTrees with schema/missingness indicators;
- schema-routed firewall-plus-flow ensemble; and
- two schema-held-out common-feature transfer diagnostics.

Each model uses separate fit, calibration, threshold-selection, and final-test roles. Exact, near-pattern, and used-feature fingerprint components are kept disjoint across roles. The flow evaluation uses time, source-group, and three repeated random splits. The existing internal firewall corpus is also evaluated where its evidence support permits it.

## Full Development Run

The report-producing run used 3,000 requested rows per provider label. It deterministically attempted 18,362 rows, accepted 16,817 after exact duplicate quarantine, and found zero schema violations. The accepted queue distribution was 8,811 non-threat and 8,006 needs-review rows.

| Candidate / scope | Queue F1 | Benign-like FPR | Queue recall | Suspicious recall | Malicious recall | Calibration |
| --- | --- | --- | --- | --- | --- | --- |
| Pooled schema-aware calibrated ExtraTrees, three random splits | `0.9237-0.9524` | `0.0882-0.1997` | `0.9432-0.9983` | `0.9931-1.0000` | `0.9275-0.9978` | weak on `3/3` |
| Schema-routed firewall-plus-flow ensemble, three random splits | `0.9227-0.9836` | `0.0172-0.2018` | `0.9392-0.9977` | `0.8696-0.9583` | `0.9275-0.9964` | weak on `3/3` |
| Provider-flow calibrated ExtraTrees, three random splits | `0.9054-0.9871` | `0.0051-0.1926` | `0.9291-0.9992` | `1.0000` | `0.9291-0.9992` | weak on `3/3` |
| Firewall-specific calibrated ExtraTrees, three random splits | `0.9713-0.9804` | `0.0303-0.3939` | `0.9655-0.9939` | `0.8686-0.9580` | `0.9091-0.9604` | weak on `3/3` |

The best cross-schema development diagnostic is `pooled_schema_aware_calibrated_extra_trees`. It is not an active model, promotion candidate, or production recommendation.

Its worst evaluated random split is `random_seed_42`: queue F1 `0.9237`, benign-like FPR `0.1997`, queue recall `0.9983`, suspicious recall `1.0000`, malicious recall `0.9978`, review queue rate `0.6392`, Brier score `0.1144`, ECE `0.1730`, and maximum confidence/accuracy gap `0.5666`. These calibration figures fail the conservative gate.

## Stability Findings

- Provider-flow time and source-group splits were evaluated and showed severe transfer instability. Several calibrated/queue strategies produced near-zero F1 in those views, so the good random-split scores do not establish time- or source-shift robustness.
- Schema-held-out provider-flow transfer had FPR `1.0000`; schema-held-out Palo Alto transfer had queue F1 `0.4647` and queue recall `0.3066`. A common-feature model trained on one schema cannot safely substitute for a model trained on the other.
- Existing internal firewall time holdout failed closed due unsupported final-window class evidence. Its source holdout is unavailable because the reviewed internal corpus has fewer than two source identities. These are evidence limitations, not hidden successful splits.
- Calibration was weak for every evaluated strategy. No result is eligible for promotion.

## Safety and State Integrity

The full run returned `completed_candidate_only` and recorded:

- configured/disposable database counts unchanged;
- active artifact bytes and timestamp unchanged;
- SQLAlchemy session clean before and after;
- v4.0 evidence lock unchanged;
- labels written `false`;
- model runs created `0`;
- detection runs created `0`;
- response actions created `0`;
- automatic response `false`; and
- real firewall blocking `false`.

## How To Reproduce

Use a migrated disposable SQLite database, not the configured database:

```powershell
$env:DATABASE_URL='sqlite:///C:/path/to/disposable-validation.sqlite3'
$env:MFU_IAM_ENABLED='false'
$env:ASSISTANT_LLM_ENABLED='false'
.\.venv\Scripts\python.exe -m atdr.scripts.run_v401_schema_aware_soc_queue --rows-per-provider-label 3000 --seed 401 --summary-only --pretty
```

The three verified development provider files must be present beneath ignored `.tmp/development_corpus/cse_cic_ids2018_v41/`. The command fails closed if a required checksum changes, a v4.0 locked file is supplied, or the reserved future benchmark is used.

## Decision And Next Gate

Readiness remains `candidate_only`. v4.1 is evidence that schema-aware design is necessary, not evidence that the result is deployable.

The next ML gate requires explicit approval to perform one separately governed final evaluation on the reserved untouched benchmark, plus independently collected multi-source/time-window real firewall or syslog evidence. Before any activation discussion, the design must show stable source/time behavior, acceptable false-positive burden, trustworthy calibration, and preserved analyst-only response controls.

## Closure Verification

The v4.1 closure matrix passed on 2026-07-14 using a migrated disposable SQLite database and process-local disabled MFU IAM/assistant-provider settings:

- task-board render and standard check passed;
- Ruff and compileall passed;
- focused v4.1 tests passed (`12 passed`);
- full backend suite passed (`568 passed, 1 skipped`);
- Alembic reported no new upgrade operations;
- React lint/build passed and Playwright passed (`21 passed, 1 skipped`);
- replay dry-run parsed two safe rows and wrote zero;
- performance smoke passed without warnings: Overview `0.4566s`, cached Overview `0.0061s`, alerts `0.0381s`, cases `0.0765s`, and ML Governance `1.2825s`; and
- `verify_release --pretty --timeout 900` returned `ok: true` with no required check failures.

The configured database and active supervised artifact were not changed by v4.1 evaluation or closure verification.
