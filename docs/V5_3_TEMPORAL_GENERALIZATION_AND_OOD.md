# v5.3 Temporal Generalization And OOD Validation

Date: 2026-07-22

## Decision

v5.3 adds rolling chronological validation, fit-only out-of-distribution
diagnostics, calibrated abstention, and a broader diagnostic model comparison.
It does not select, activate, promote, or write a new model artifact.

The best aggregate diagnostic comparator is
`calibrated_hist_gradient_boosting_sigmoid`, but it passes zero strict views.
Its temporal FPR is `0.9976`, and the three rolling temporal windows have FPR
between `0.9923` and `1.0000`. The supervised lifecycle therefore remains
`shadow_observation`. Deterministic rules remain alert-authoritative,
production promotion is false, response automation is false, and real
firewall blocking is disabled.

## Frozen v5.2 Baseline

The evaluation freezes the same 2,235 latest eligible reviewed rows used by
v5.2. No label was created, replaced, or reclassified.

| Item | Frozen value |
| --- | --- |
| Dataset fingerprint | `ae3d2972bdb888f0fba7631932ae512f674e5dbdb9cc72c1d3cd633d67ec4420` |
| Eligible reviewed rows | 2,235 |
| Label provenance | 1,672 manual; 529 rule-assisted; 7 ML-assisted; 27 hybrid-assisted |
| Weak/unreviewed latest rows excluded | 437 |
| Duplicate normalized-log IDs in evaluation | 0 |
| v5.2 selection | No candidate selected |
| Governed artifact | `v5.1-soc-queue-20260722T102436Z`, shadow observation |
| Database counts | 145,232 raw; 145,232 normalized; 3,231 alerts; 2,672 labels; 45 model runs; 31 detection runs; 0 responses |

The database counts and active artifact fingerprint are identical before and
after v5.3 evaluation.

## Temporal Failure Diagnosis

The strict temporal partition contains 957 fit, 282 calibration, 228 threshold,
532 final-test, and 236 quarantined near-duplicate rows. Leakage checks pass,
and the final-test labels are not reused for tuning.

The FPR failure is primarily a chronological evidence-distribution problem,
not unfamiliar parser schema:

- threshold-selection review prevalence is `0.8640`, while final-test review
  prevalence is `0.2218`;
- fit evidence is dominated by 515 rule-assisted rows, while all 532 final
  rows are manual provenance;
- fit labels are dominated by `benign_unusual`, while final labels are
  dominated by 404 `benign` rows;
- final applications are dominated by 404 `quic-base` rows, compared with 161
  in fit;
- application total-variation distance is `0.7428`, label-provenance distance
  is `0.5737`, and original-label distance is `0.7290`;
- missingness is nearly unchanged (`0.000320` fit versus `0.000288` final), and
  only two final rows contain an unseen application value; and
- source/destination diversity and scan-context features also shift sharply
  across the chronological boundary.

The threshold-only v5.2 baseline chooses `0.15`; nearly all final scores exceed
it. A post-hoc final-test oracle could reduce FPR at the cost of severe recall,
but that diagnostic is explicitly excluded from tuning and selection.

## Rolling Temporal Protocol

The canonical fit, calibration, and threshold partitions are frozen once. The
532 final rows are then divided into three disjoint chronological future
windows of 178, 178, and 176 rows. No rolling final label contributes to model
fit, calibration, threshold selection, feature selection, or strategy ranking.

For the leading diagnostic comparator:

| View | Precision | Recall | F1 | FPR | Suspicious recall | Malicious recall | Queue rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Temporal final | 0.2222 | 1.0000 | 0.3636 | 0.9976 | 1.0000 | 1.0000 | 0.9981 |
| Rolling future 1 | 0.2712 | 1.0000 | 0.4267 | 0.9923 | 1.0000 | 1.0000 | 0.9944 |
| Rolling future 2 | 0.2135 | 1.0000 | 0.3519 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Rolling future 3 | 0.1818 | 1.0000 | 0.3077 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

These results are stable evidence of failure, not a candidate success. The
model catches threats by sending almost every chronological row to review.

## Diagnostic Strategy Comparison

All newly fitted strategies are memory-only diagnostics. The v5.1 governed
artifact is an operational reference on the temporal split and is excluded
from non-temporal candidate ranking because historical overlap cannot be
proven absent.

| Strategy | Strict views passed | Temporal F1 / FPR | Zone-proxy F1 / FPR |
| --- | ---: | --- | --- |
| v5.2 leading ExtraTrees | 0 | 0.3555 / 1.0000 | 0.7668 / 0.1027 |
| Recency-weighted ExtraTrees | 0 | 0.2921 / 0.6329 | 0.6430 / 0.0804 |
| Provenance-weighted ExtraTrees | 0 | 0.3032 / 0.5531 | 0.6289 / 0.0580 |
| Time-balanced ExtraTrees | 0 | 0.3138 / 0.5845 | 0.8103 / 0.1071 |
| Calibrated Logistic Regression | 0 | 0.3631 / 1.0000 | 0.4034 / 0.0268 |
| Calibrated HistGradientBoosting | 0 | 0.3636 / 0.9976 | 0.7826 / 0.0804 |
| Schema-routed ExtraTrees | 0 | 0.1751 / 0.6715 | 0.7607 / 0.0491 |
| Calibrated abstention queue | 0 | 0.3379 / 0.7488 | 0.9275 / 0.2902 |

The leading comparator ranks best only in aggregate. It remains unsuitable for
advancement. Its non-temporal results also miss strict gates: random-view F1 is
`0.7956` to `0.8446`, suspicious recall is `0.5983` to `0.7094`, and the
zone-proxy suspicious recall is `0.4968`.

## OOD And Abstention

The OOD profile is fitted on fit rows only. It checks critical schema
missingness, unseen categorical rate, robust numeric-range drift, missingness
drift, and confidence near the selected threshold. OOD or unstable rows are
reported as `insufficient_model_evidence`.

The temporal final view has:

- OOD rate `0.0733`;
- confidence-instability rate `0.0526`;
- abstention rate `0.1053`; and
- retained model coverage `0.8947`.

Across eight evaluated views, the calibrated abstention strategy has OOD rate
`0.0000` to `0.7449`, abstention `0.0197` to `0.7513`, and coverage `0.2487` to
`0.9803`. Abstention is counted as an analyst-review queue item for strict FPR
and queue metrics. It therefore cannot hide false positives by dropping hard
rows. The strategy still passes zero strict views.

## Calibration And External Evidence

Calibration remains weak on chronological and rolling views. The leading
comparator has temporal ECE `0.5285` and maximum confidence/accuracy gap
`0.7059`; rolling ECE is `0.4912` to `0.5570`. Some random views have acceptable
ECE, but their maximum gaps remain above the `0.15` gate.

The locked CSE-CIC-IDS2018 aggregate remains failed with worst FPR `1.0000`.
Row-level locked predictions are not available for new v5.3 candidate scoring,
so v5.3 fails closed instead of reopening provider labels. External rows and
labels contribute zero rows to fit, calibration, threshold selection, and
tuning.

## Controlled And Private Evidence

- Controlled scenarios remain 24/24 with no automatic response, real blocking,
  or production claim.
- The layered matrix remains 288/288 with zero false positives, false
  negatives, or response actions.
- The latest private PAN-OS aggregate parsed 773,551 rows with zero parse
  failures and scored 2,000 rows. It contains no ground-truth labels and is
  operational evidence only, not accuracy evidence.
- Source holdout fails closed because the reviewed evidence contains fewer than
  two independent source devices. No synthetic source is represented as a real
  device.

## Dashboard Telemetry

AI Governance exposes concise aggregate-only fields for temporal FPR, OOD rate,
abstention range, coverage, rolling-window count, threshold/final prevalence,
calibration, missingness, root causes, and strict blockers. It shows no raw
logs, IPs, private paths, or secrets and does not present the diagnostic leader
as active or promoted.

## Safety And Lifecycle

- `model_activated=false`
- `model_artifact_written=false`
- `production_promoted=false`
- `response_automation_allowed=false`
- `real_firewall_blocking_enabled=false`
- response actions before/after: `0/0`
- deterministic rules remain alert-authoritative
- no AI-assisted label is created or called human-reviewed

The final v5.3 decision is `shadow_observation` with no candidate selected.

## Verification

- Taskboard render and standards checks passed.
- Whole-repo Ruff and compileall passed.
- Full backend suite: 656 passed, 1 hardware-dependent skip.
- Alembic: no new upgrade operations detected on local SQLite.
- React lint and production build passed.
- Playwright: 26 passed, 1 live-scenario/hardware-dependent skip.
- Controlled scenario corpus: 24/24 passed in a temporary database.
- Layered validation: 288/288 passed, with zero FP, FN, or responses.
- SOC Assistant QA: 20/20, citation pass rate 1.0, unsafe refusal passed,
  and zero response/detection/model/label side effects.
- Private disposable shadow: 5,000/5,000 parsed, 1,000 rows shadow-scored,
  47 queued, configured DB/artifacts unchanged, zero responses, and no private
  path/raw evidence/secret returned.
- Replay dry-run parsed two safe rows and wrote/sent zero.
- Read-only performance smoke had no warnings: Overview `0.1821s`, cached
  `0.0117s`, ML Governance `1.1820s`, alerts `0.0432s`, cases `0.0805s`, and
  20-row feature generation `0.0070s`.
- Official release gate returned `ok: true`, with zero failed required checks.
- `git diff --check` passed apart from non-failing Windows LF/CRLF notices;
  no v5.3 path is staged and protected/generated evidence remains ignored.

Generated full reports remain ignored under `ml_baseline_reviews/` and are not
part of the commit allowlist.

## Evidence Still Required

1. Independently reviewed evidence from at least two real devices and multiple
   time windows.
2. A separate development corpus with the chronological application and
   provenance regimes now observed, without reusing locked final labels.
3. A new untouched, schema-compatible external firewall/syslog benchmark.
4. Human/advisor approval of evidence collection and any future lifecycle
   advancement.
5. Provider approval and real-device forwarding evidence where external
   systems are required.
