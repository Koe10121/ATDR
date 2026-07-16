# v3.98 Independent Detection/ML Holdout Validation

## Status

Implemented as a read-only, diagnostic validation phase. v3.98 does not activate or promote a model, write an active model artifact, create labels, run response actions, enable automatic response, or enable real firewall blocking. ATDR remains a controlled decision-support system and is not production-ready.

The word *independent* in this phase means that each final-test partition is frozen and excluded from fit, probability calibration, and threshold selection. It does not mean that an external organization or real-device dataset independently validated ATDR.

## Why v3.98 Was Needed

Earlier supervised evaluations produced useful candidate evidence, but several limitations prevented a strong generalization claim:

- some historical feature experiments used whole labeled-batch context;
- global rarity features could describe the full current database rather than only the training partition;
- old train/test helpers did not always reserve separate fit, calibration, threshold-selection, and final-test partitions;
- repeated or near-repeated behavior could occur across a naive row split;
- controlled synthetic benchmarks are useful regression evidence but are not external real-world independence.

v3.98 replaces those assumptions with an explicit frozen protocol and fail-closed leakage audit.

## Frozen Protocol

The evaluator uses the latest trainable label for each normalized log and includes reviewed labels only. Superseded label history and weak/unreviewed latest labels are excluded from model fitting and scoring.

Every validation mode creates four distinct partitions:

1. **Fit**: trains the model and feature pipeline.
2. **Calibration**: fits sigmoid probability calibration.
3. **Threshold selection**: selects the SOC review-queue threshold.
4. **Final test**: produces the reported holdout metrics only.

Final-test labels are never passed to fitting, calibration, or threshold selection.

Required split modes are:

- strict temporal holdout;
- source-disjoint holdout;
- fingerprint-grouped random seed 7;
- fingerprint-grouped random seed 17;
- fingerprint-grouped random seed 42.

## Leakage Controls

Rows are joined into indivisible leakage groups when they share any of the following:

- exact raw-evidence SHA-256 fingerprint;
- near behavior fingerprint based on normalized protocol/application/action/port/zone/risk and magnitude buckets;
- fingerprint of the features actually used by the v3.98 candidate;
- normalized log identity.

The reports contain only hashes and aggregate diagnostics. They do not include raw log lines or IP addresses.

The audit fails closed when it finds:

- exact, near, feature, log-ID, or leakage-group overlap between any partitions;
- source overlap between development and final test in source-holdout mode;
- chronological overlap in temporal mode;
- an empty required partition;
- a required partition without both queue classes.

Temporal behavior groups crossing a time boundary are quarantined. Source patterns shared across held-out and development sources are also quarantined instead of being split.

## Feature Boundary

v3.98 uses the existing normalized feature pipeline but excludes whole-database rarity flags from the candidate feature set. Rule-derived features are rebuilt from row-local evidence, while existing causal window features remain available. Full labeled-batch rule context is not used as a supervised feature.

The evaluated feature families include:

- normalized traffic volume, protocol, action, application, zones, ports, and time values;
- causal repeated-source and destination/port diversity values;
- unknown/incomplete application context;
- high-risk application and anomaly context;
- row-local deterministic rule evidence;
- evidence-enrichment values used by the repaired binary SOC queue target.

## Strategies Compared

Each valid final-test split compares:

- repaired binary SOC queue ExtraTrees with dedicated sigmoid calibration;
- balanced Logistic Regression baseline;
- deterministic rule baseline;
- fresh in-memory IsolationForest baseline;
- rule/anomaly/supervised hybrid decision-support score;
- fit-partition majority-class baseline.

The v3.62 repaired binary queue is selected as the primary diagnostic candidate before final-test evaluation. Exact five-class severity remains explanation/ranking information rather than an authoritative production classification target.

## Metrics And Reports

The evaluator reports:

- queue precision, recall, and F1;
- benign-like false-positive rate;
- suspicious and malicious diagnostic recall;
- macro and weighted F1;
- false-positive and false-negative counts;
- review-queue size/rate;
- Brier score, expected calibration error, maximum confidence/accuracy gap, and confidence buckets;
- deterministic bootstrap confidence intervals;
- error counts by source, application, action, and destination port;
- split ranges, worst primary split, quarantined rows, and leakage findings.

Generated reports remain ignored under `ml_baseline_reviews/`:

- `v3_98_holdout_validation_<timestamp>.md`;
- `v3_98_leakage_audit_<timestamp>.md`;
- `v3_98_validation_latest.json`.

No import-ready review sample is generated by default. v3.98 does not create human-reviewed labels.

## Current Disposable-Copy Result

The current 145,232-row SQLite database was first backed up and copied to ignored temporary storage. Only the disposable copy was upgraded through migration `b4c5d6e7f8a9`; the configured database remained on its prior revision. The v3.98 evaluator used 2,235 reviewed latest labels, excluded 437 weak/unreviewed latest labels, found zero duplicate normalized-log identities, and did not write raw logs into reports.

Leakage grouping found 1,749 behavior components. Of the reviewed rows, 676 belong to a multirow component; the audit found 126 repeated exact-fingerprint groups, 190 repeated near-pattern groups, and 135 repeated used-feature groups. These rows stayed together rather than being distributed across partitions.

Two strict splits failed closed:

- **Temporal holdout:** the final time window contained 532 `needs_review` rows and zero `non_threat` rows. The evaluator quarantined 236 boundary-crossing rows and refused to report a misleading two-class metric from a one-class final partition.
- **Source holdout:** all 2,235 reviewed rows are linked to the single `local_import` source. A genuinely source-disjoint split is therefore impossible with the current labels.

The three fingerprint-grouped random diagnostics evaluated successfully:

| Split | Queue precision | Queue recall | Queue F1 | Benign-like FPR | Suspicious recall | Malicious recall | Review queue rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Random seed 7 | 0.9958 | 0.9655 | 0.9804 | 0.0303 | 0.8686 | 0.9091 | 0.8551 |
| Random seed 17 | 0.9643 | 0.9858 | 0.9749 | 0.2727 | 0.9441 | 0.9406 | 0.9016 |
| Random seed 42 | 0.9496 | 0.9939 | 0.9713 | 0.3939 | 0.9580 | 0.9604 | 0.9231 |

The worst primary diagnostic is random seed 42: 26 false positives, 3 false negatives, macro F1 0.8526, weighted F1 0.9432, and benign-like FPR 0.3939. Its false positives are all allowed traffic and are led by ping (`9`) and QUIC/443-like traffic (`6`), while its three false negatives are one suspicious and two malicious rows on port 443.

Strategy ranges reinforce why queue F1 alone is not a sufficient gate:

| Strategy | Queue F1 range | FPR range | Queue recall range |
| --- | ---: | ---: | ---: |
| Repaired ExtraTrees queue | 0.9713-0.9804 | 0.0303-0.3939 | 0.9655-0.9939 |
| Logistic Regression baseline | 0.7971-0.8724 | 0.1212-0.3636 | 0.6734-0.8114 |
| Deterministic rules | 0.7525-0.7597 | 0.0000-0.0152 | 0.6045-0.6126 |
| IsolationForest | 0.8768-0.8882 | 0.8788-0.9697 | 0.8803-0.9026 |
| Hybrid decision support | 0.9693-0.9829 | 0.1970-0.4242 | 0.9919-0.9980 |
| Majority baseline | 0.9373 | 1.0000 | 1.0000 |

Sigmoid probability calibration has low Brier score (`0.0245-0.0446`) and low aggregate ECE (`0.0215-0.0318`), but the maximum confidence/accuracy gap is `0.7575-0.8781` in sparse intermediate-confidence buckets. The conservative calibration gate therefore remains weak rather than passing on aggregate averages alone.

Execution completed without changing database table counts or the active supervised artifact. It created no labels, model runs, detection runs, or response actions. The current readiness result is `candidate_only`, with 3 of 8 checks passing. The blockers are incomplete temporal/source validation, unstable worst-split FPR, sparse-bucket calibration weakness, and missing external independent validation.

## Run Safely

Use a migrated disposable database copy for release evidence:

```powershell
$env:DATABASE_URL = "sqlite:///C:/absolute/path/to/disposable-copy.sqlite3"
.\.venv\Scripts\python.exe -m atdr.scripts.run_v398_independent_holdout_validation --pretty
```

Do not point this command at an unapproved database merely to satisfy migration or validation evidence. Although the evaluator is read-only, the configured schema must already be current.

## Readiness Rules

The decision remains `candidate_only` unless all internal splits pass leakage controls and meet stable queue-quality and calibration gates. Even if every internal gate passes, external provider-blinded or real-source labeled validation remains required before any stronger claim.

The evaluator hard-codes these safety outcomes:

- `production_promoted=false`;
- `model_activated=false`;
- `model_artifact_written=false`;
- `response_automation_allowed=false`;
- `real_firewall_blocking_enabled=false`.

## Remaining Limits

- Reviewed labels originate from the current ATDR corpus and analyst workflow; they are not an external benchmark.
- Temporal and source partitions can quarantine repeated behavior, reducing usable support.
- Suspicious/malicious recall is diagnostic because the primary target is a binary review queue.
- Calibration and quality may vary across sources and time windows.
- Real-device, provider-blinded, long-duration drift, and independent analyst validation remain open evidence gates.

## Verification

- Focused v3.98 tests: `6 passed`.
- Full backend suite: `544 passed, 1 skipped`.
- Ruff and compileall: passed.
- Disposable Alembic check: `b4c5d6e7f8a9 (head)`, no drift.
- React lint/build: passed.
- Playwright: `21 passed, 1 skipped`.
- Replay dry-run: passed, zero writes.
- Performance smoke: cold-path warnings recorded; immediate warm rerun passed all local budgets.
- Release gate: `ok: true`; optional running-stack smoke skipped.

Generated validation reports and local command captures remain ignored. No commit, push, configured-database migration, model activation, or response action was performed.
