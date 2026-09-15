# v3.99 Independent Multi-Source Evidence And Frozen Revalidation

## Status

Implemented and validated as a read-only diagnostic phase. v3.99 creates an ignored deterministic synthetic evidence pack, freezes fitting/calibration/threshold selection on existing reviewed evidence, and uses the new evidence only as final evaluation data. It does not import labels, activate or promote a model, write a model artifact, create response actions, enable automation, or enable real firewall blocking.

ATDR remains `candidate_only`. The results are synthetic regression evidence, not provider-blinded, real-device, externally reviewed, or production evidence.

## Why This Phase Was Needed

v3.98 proved that the current reviewed corpus cannot support a meaningful source or temporal generalization claim:

- all 2,235 reviewed latest labels belong to `local_import`;
- their timestamps cover only `2026-05-20T13:36:15Z` through `2026-05-20T13:39:30Z`;
- the strict source split therefore has one source;
- the temporal final partition has one queue class;
- repeated random FPR ranged from `0.0303` to `0.3939`;
- confidence calibration was weak.

The correct next step was a separately generated evidence harness, not another round of tuning against the v3.98 final partitions.

## Evidence Manifest

The generated manifest uses schema `atdr_v399_independent_evidence_manifest_v1` and records:

- source identity and source type;
- parser profile;
- collection-window start/end;
- generator provenance;
- scenario/category distribution;
- expected-label distribution and provenance;
- evidence kind (`synthetic`);
- human-review and import-readiness flags;
- exact, near-pattern, and used-feature overlap results;
- accepted and quarantined row counts.

Every generated row states:

- `label_provenance=deterministic_synthetic_scenario_expectation`;
- `human_reviewed=false`;
- `import_ready=false`.

No generated expectation is inserted into `ml_labels` or represented as analyst review.

## Source-Separated Evidence Sets

| Source | Type | Parser profile | Primary category | Rows |
| --- | --- | --- | --- | ---: |
| `v399-campus-router-normal` | router | generic_syslog | normal workstation/router traffic with bounded threat controls | 240 |
| `v399-edge-firewall-probing` | firewall | palo_alto | scan, probing, denied-service, C2-like, and benign control traffic | 240 |
| `v399-mixed-workstation` | sample | generic_syslog | mixed normal, policy, unknown-service, C2-like, and exfiltration-like traffic | 240 |

Each source spans four collection windows separated by seven days. Addresses use private or documentation-only ranges. CSVs and the manifest are generated beneath ignored `ml_baseline_reviews/v3_99_evidence/` and are not source-controlled.

## Independence And Leakage Controls

The current run attempted and accepted 720 rows:

- exact fingerprint overlap with reviewed corpus: `0`;
- normalized near-pattern overlap: `0`;
- used-feature fingerprint overlap: `0`;
- external exact duplicates: `0`;
- accepted sources: `3`;
- collection windows: `4`;
- quarantined rows: `0`.

If any exact, near-pattern, or feature fingerprint overlaps the reviewed corpus, the row is quarantined before evaluation. Duplicate external exact evidence is also quarantined. A run fails closed if fewer than 300 accepted rows, three sources, four windows, two final target classes, source disjointness, or chronological separation remain.

## Frozen Evaluation Protocol

1. Build features for existing latest reviewed labels only.
2. Assign exact, near-pattern, and used-feature leakage groups.
3. Freeze internal roles using `random_seed_42`:
   - fit: 1,006 rows;
   - calibration: 335 rows;
   - threshold selection: 335 rows;
   - reserved internal final: 559 rows.
4. Build the synthetic corpus in an isolated in-memory SQLite feature workspace.
5. Quarantine overlap without consulting final performance.
6. Fit and calibrate candidates using internal fit/calibration rows only.
7. Select thresholds using internal threshold rows only.
8. Score external final evidence after every model and threshold is frozen.

Frozen partition hash:

```text
a48a3b961843c55385979ee4e00e0846b8e41d8d7ee78107c98a6ba65b011df3
```

External rows used for fit/calibration/threshold selection: `0/0/0`. External final labels used before scoring: `false`.

## Strategies Evaluated

- deterministic rules, with the anomaly rule excluded;
- fresh in-memory IsolationForest;
- repaired binary SOC queue ExtraTrees with dedicated sigmoid calibration;
- balanced Logistic Regression baseline;
- hybrid rule/anomaly/supervised decision support;
- fit-partition majority baseline.

No strategy writes an artifact or changes runtime detection behavior.

## Primary Candidate Results

| Split | Final rows | Precision | Recall | F1 | Benign FPR | Suspicious recall | Malicious recall | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| source holdout | 720 | 1.0000 | 0.9091 | 0.9524 | 0.0000 | 1.0000 | 1.0000 | 0.0257 | 0.1115 |
| temporal holdout | 180 | 1.0000 | 0.9091 | 0.9524 | 0.0000 | 1.0000 | 1.0000 | 0.0248 | 0.1097 |
| random seed 7 | 540 | 1.0000 | 0.9134 | 0.9548 | 0.0000 | 1.0000 | 1.0000 | 0.0248 | 0.1097 |
| random seed 17 | 540 | 1.0000 | 0.9141 | 0.9551 | 0.0000 | 1.0000 | 1.0000 | 0.0247 | 0.1104 |
| random seed 42 | 540 | 1.0000 | 0.9108 | 0.9533 | 0.0000 | 1.0000 | 1.0000 | 0.0252 | 0.1107 |

Primary queue F1 ranged `0.9524-0.9551`; review-queue rate ranged `0.5481-0.5667`. Bootstrap 95% intervals and complete confidence buckets are retained in the ignored JSON report.

## Error Analysis

The primary candidate produced zero synthetic benign-like false positives. Its false negatives were 28-40 `needs_context` rows, concentrated in allowed `unknown-tcp`/`unknown-udp` services on varying ports. Suspicious and malicious scenario controls were all queued in this synthetic pack.

This clean FPR is not sufficient evidence of real-world performance. The generator intentionally creates separable controlled patterns and is useful for repeatable regression detection, not an unbiased accuracy estimate.

## Strategy Comparison

| Strategy | Queue F1 range | FPR range | Queue recall range |
| --- | --- | --- | --- |
| ExtraTrees supervised queue | 0.9524-0.9551 | 0.0000 | 0.9091-0.9141 |
| Logistic Regression | 0.6412-0.6611 | 0.7073-0.7429 | 0.6963-0.7138 |
| Deterministic rules | 0.4703-0.4942 | 0.0000 | 0.3075-0.3282 |
| IsolationForest | 0.7514-0.7657 | 1.0000 | 1.0000 |
| Hybrid decision support | 0.9977-1.0000 | 0.0000 | 0.9955-1.0000 |
| Majority baseline | 0.7514-0.7657 | 1.0000 | 1.0000 |

The hybrid result is expected to be strong on rule-oriented synthetic scenarios and must not be interpreted as external production accuracy.

## Calibration

Calibration failed all five splits. Brier score was low (`0.0247-0.0257`), but ECE remained approximately `0.1097-0.1115` and the largest sparse-bucket confidence/accuracy gap was `0.5128-0.5227`. Confidence values must therefore remain supporting context rather than authoritative probabilities.

## Readiness Decision

Result: `candidate_only` (`9/11` checks passed).

Remaining blockers:

- primary confidence calibration is not acceptable across all splits;
- no provider-blinded, independently reviewed, or real-source evidence is available.

Regardless of metrics:

- `production_promoted=false`;
- `model_activated=false`;
- `model_artifact_written=false`;
- `response_automation_allowed=false`;
- `real_firewall_blocking_enabled=false`.

## Safety Evidence

The disposable 145,232-row database had identical before/after counts:

- raw logs: 145,232;
- normalized logs: 145,232;
- alerts: 3,231;
- labels: 2,672;
- model runs: 41;
- detection runs: 31;
- response actions: 0.

The active artifact metadata and byte size were unchanged. The configured database was not reset, migrated, or evaluated.

## Command

Run only against a migrated disposable/read-only validation database:

```powershell
$env:DATABASE_URL='sqlite:///C:/path/to/disposable-validation.sqlite3'
.\.venv\Scripts\python.exe -m atdr.scripts.run_v399_multisource_frozen_revalidation --rows-per-source 240 --seed 399 --summary-only --pretty
```

Generated evidence and reports remain ignored under `ml_baseline_reviews/`.

## Verification

- Task-board render and standard check: passed.
- Ruff and compileall: passed.
- Focused v3.99 tests: `5 passed`.
- Full backend: `549 passed, 1 skipped`; the skip is hardware-dependent.
- Disposable Alembic check: no drift at `b4c5d6e7f8a9 (head)`.
- React lint/build: passed.
- Playwright: `21 passed, 1 skipped`; the skip is the live hardware scenario.
- Replay dry-run: two safe sample rows parsed, zero writes.
- Performance smoke: no warnings; Overview `0.4315s`, cached Overview `0.0062s`, ML Governance `1.1671s`, alerts `0.0334s`, cases `0.0666s`, features `0.2731s`.
- Release gate: `ok: true` against the migrated disposable database with external IAM/LLM process-locally disabled.

## Remaining Evidence Gap

The next meaningful validation step is not additional tuning on this corpus. It is an approved, independently reviewed, multi-source and multi-time-window dataset from real devices or a provider-blinded external source, evaluated once under a protocol frozen before labels are inspected.
