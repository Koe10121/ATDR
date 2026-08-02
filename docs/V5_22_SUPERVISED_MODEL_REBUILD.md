# v5.22 Supervised Model Rebuild

Date: 2026-08-02

## Decision

v5.22 rebuilds ATDR's supervised SOC review queue against the exact native
PAN-OS development roles locked by v5.21. It freezes one diagnostic shadow
configuration, but writes no model artifact and grants no alert or response
authority.

The lifecycle remains `shadow_observation`. Deterministic rules remain
alert-authoritative. Automatic response and real firewall blocking remain
disabled.

## Evidence Integrity

The complete private source reproduced the v5.21 lock exactly:

| Role | Rows | Used by v5.22 |
| --- | ---: | --- |
| Development fit | 433,499 | fitting only |
| Calibration | 116,422 | probability calibration only |
| Threshold | 111,626 | threshold selection and development evaluation |
| Untouched future validation | 112,004 | no |
| Quarantine | 0 | no |

Exact and near-duplicate families remain contained. The blind pack was not
opened, sampled, labeled, or scored. No future-role assisted suggestion was
calculated.

The governed configured-database evidence contributes 918 genuinely
human-reviewed rows and 549 assisted/weak rows. v5.22 no longer interprets a
generic `reviewed=true` flag as proof of human authorship: only `manual` and
`reviewed_import` provenance qualify. Assisted rows receive lower weights.

The private development policy contributes 500,770 high-confidence weak
training events and excludes 160,777 ambiguous events. These counts represent
agreement with a fixed assisted policy, not ground-truth accuracy.

## Candidate Comparison

Six strategies were compared across four development views:

- calibrated ExtraTrees;
- assisted-weighted calibrated ExtraTrees;
- calibrated HistGradientBoosting;
- calibrated Logistic Regression;
- three-class ExtraTrees SOC queue; and
- hierarchical two-stage ExtraTrees.

The views include two nested native chronological views, the predeclared
development roles, and a 114-row human-only provenance holdout. A real
source-disjoint view failed closed because fewer than two usable real source
identities are available.

The predeclared v5.22 stability ranking selected:

| Contract item | Frozen value |
| --- | --- |
| Strategy | `hierarchical_two_stage_extra_trees` |
| Queue model | calibrated ExtraTrees |
| Severity stage | ExtraTrees suspicious/malicious classifier |
| Calibration | sigmoid on dedicated calibration role |
| Queue threshold | `0.40` |
| Feature contract | 32 numeric + 8 categorical native PAN-OS features |
| Artifact written | no |
| Activated/promoted | no / no |

Cross-view ranges for the selected configuration are:

| Metric | Worst | Best |
| --- | ---: | ---: |
| Queue F1 | 0.8025 | 1.0000 |
| Benign-like FPR | 0.0476 | 0.0000 |
| Suspicious recall | 0.5000 | 1.0000 |
| Malicious recall | 1.0000 | 1.0000 |
| Queue rate | 0.5614 | 0.4320 |
| ECE | 0.3741 | 0.0018 |
| Maximum confidence/accuracy gap | 0.7099 | 0.0087 |

On the human-only holdout, precision/recall/F1 are
`0.9844/0.6774/0.8025`, FPR is `0.0476`, suspicious recall is `0.5000`,
malicious recall is `1.0000`, and ECE is `0.3741`.

## Interpretation

Compared with earlier development diagnostics, the candidate substantially
reduces noise while preserving malicious recall. It is not ready for
activation because:

- suspicious recall remains below the fixed `0.70` gate;
- calibration exceeds the fixed ECE and confidence-gap gates;
- no source-disjoint real-device view is available; and
- independent human-confirmed blind labels remain unavailable.

The near-perfect weak-policy views show policy learnability, not independent
accuracy. The human-only holdout is the more important warning signal.

## Safety And Side Effects

The complete run produced:

```text
configured database entity changes: 0
labels created: 0
model runs created: 0
detection runs created: 0
alerts created: 0
response actions created: 0
model artifacts written: 0
model activations/promotions: 0/0
blind/future labels opened: false
```

One joblib physical-core probe warning was classified as an environment-only
capacity message. There were zero model-quality, all-null-feature, or
sample-weight-routing warnings.

## Verification

- Taskboard render and standard check: passed.
- Ruff, compileall, and Alembic no-drift check: passed.
- Focused v5.22 backend tests: `8 passed`.
- Full backend and independent release-gate suites: `808 passed, 1 skipped`.
- React lint/build: passed.
- Playwright: `27 passed, 1 skipped` (the skip requires live hardware).
- Controlled detection scenarios: `24/24` passed.
- Layered detection matrix: `288/288` passed with zero controlled false
  positives or false negatives.
- SOC Assistant QA: `20/20` passed with zero side effects.
- Replay dry-run: passed with zero writes.
- Performance smoke: passed with no warnings; cold/cached Overview were
  `0.7935s`/`0.0101s`.
- Gemini status check: configured and secret-safe; no external call was made.
- Release gate: `ok=true` with no failed required checks.

## Remaining Roadmap

Three phases remain in the current closure program:

1. v5.23 live-source acceptance;
2. v5.24 investigation and Gemini quality lock; and
3. v5.25 integrated acceptance.

Supervised lifecycle advancement additionally remains gated by a second real
source and independent human/advisor-confirmed native labels. No commit or push
is authorized by this phase.
