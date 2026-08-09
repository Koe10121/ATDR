# v5.26 Native PAN-OS Blind Detection Qualification

## Status

`blind_predictions_complete_insufficient_human_labels` on 2026-08-08.

ATDR completed a one-time, prediction-before-label qualification over the
sealed 40-row native PAN-OS blind pack. The run produced privacy-safe frozen
predictions for deterministic rules, IsolationForest, the v5.22 supervised
shadow candidate, and the hybrid advisory projection. It did not produce
accuracy metrics because the blind pack contains zero genuine human-reviewed
decisions.

This result is evidence of protocol execution and queue behavior. It is not
evidence of detection accuracy, model readiness, or production readiness.

## Baseline And Evidence Locks

- Repository baseline: `be9c12a03d5f60087b331a1cc0708db9afe0c9bd`.
- The v5.21 chronological roles remain locked: 433,499 development-fit,
  116,422 calibration, 111,626 threshold, and 112,004 untouched-future rows.
- Exact and propagation-family duplicate groups do not cross evidence roles.
- The 40-row blind-pack identity matches the v5.21 lock.
- The blind pack was not used for fit, calibration, threshold selection, or
  candidate selection.
- The v5.22 frozen candidate contract remains hierarchical two-stage
  ExtraTrees, dedicated sigmoid calibration, and queue threshold `0.40`.
- No second real source or independent reviewer was inferred.

Private identities and lock fingerprints are retained only in ignored local
evidence. They are intentionally omitted from this tracked document.

## Eligibility And Provenance

| Evidence class | Rows | Treatment |
| --- | ---: | --- |
| Sealed native blind rows | 40 | Eligible for prediction-before-label protocol |
| Genuine human-reviewed blind decisions | 0 | Insufficient for metrics |
| Blind rows excluded from metrics | 40 | Not reviewed |
| Assisted or weak blind values counted as human | 0 | Prohibited |
| Fabricated labels | 0 | Prohibited |
| Governed historical human-reviewed rows | 918 | Development evidence only |
| Governed assisted or weak rows | 549 | Separate diagnostic evidence only |

The blind pack contains no rule, model, or AI suggestions and is not
import-ready. Existing governed labels were read for development reconstruction
only; no label was created, overwritten, or promoted.

## One-Time Execution

The runner streamed the complete private source through disposable storage:

- rows processed: 773,551;
- parser successes: 773,551;
- parser failures: 0;
- development-fit representatives: 8,000;
- calibration representatives: 3,000;
- threshold representatives: 3,472; and
- blind rows scored: 40.

Predictions were persisted to an ignored private lock before human-decision
fields were opened. The public result contains no source path, raw row, IP
address, source identity, secret, or fingerprint.

## Queue Observations

| Layer | Rows queued | Queue rate | Interpretation |
| --- | ---: | ---: | --- |
| Deterministic rules | 25 | 0.625 | Authoritative review triggers, not an accuracy claim |
| IsolationForest | 3 | 0.075 | Advisory anomaly queue only |
| Supervised shadow candidate | 12 | 0.300 | Advisory queue only |
| Hybrid projection | 4 | 0.100 | Advisory decision-support queue only |

Layer agreement was `0.675` for rule versus supervised, `0.450` for rule
versus IsolationForest, `0.475` for rule versus hybrid, `0.725` for supervised
versus IsolationForest, and `0.750` for supervised versus hybrid. All four
layers agreed on 17 of 40 rows.

The rule queue contained five rows in each of the following aggregate pattern
groups: incomplete/80 allow, other context, scan-like behavior, unknown TCP,
and vendor THREAT records. The supervised queue was concentrated in vendor
THREAT records, other context, and scan-like behavior. These are queue
distributions, not false-positive or true-positive findings.

## Metrics Withheld

The fixed metric gate requires at least 20 genuine human decisions and both
binary queue classes. The pack has zero such decisions. Therefore the
following are unavailable and must not be inferred:

- confusion matrices;
- precision, recall, or F1;
- benign-like false-positive rate;
- suspicious or malicious recall;
- macro or weighted F1;
- calibration ECE, Brier score, or confidence gap;
- false-positive and false-negative pattern claims; and
- promotion or activation readiness.

This is the correct fail-closed outcome. A queue rate is not an accuracy rate.

## Protocol Repair Record

The initial execution froze predictions in memory but did not persist a
row-matchable private prediction lock. No human label was present and no
accuracy metric was calculated during that execution. A narrowly bounded
pre-lock correction was therefore permitted once, before any ground truth was
observed. The original aggregate result is preserved in ignored evidence, and
the corrected run reproduced all four queue rates exactly before persisting
the private lock.

The full runner now fails closed on repeat execution. Only preflight may be
repeated. This correction is not a second blind evaluation.

## Safety Result

- configured database counts unchanged;
- private source not imported into the configured database;
- disposable storage removed;
- zero labels, model runs, detection runs, alerts, or response actions created;
- no active model artifact written;
- no model activation or promotion;
- rules remain alert-authoritative;
- ML remains advisory;
- automatic response remains disabled; and
- real firewall blocking remains disabled.

Lifecycle remains `shadow_observation`. Readiness passed 6 of 8 protocol and
safety checks. The failed checks are minimum genuine human blind labels and
availability of blind metrics.

## Next Evidence Required

Detection-specific closure still requires four major evidence phases:

1. A qualified independent human or advisor reviews the already sealed 40-row
   pack without seeing predictions, followed by a read-only join to the frozen
   private prediction lock.
2. A second real PAN-OS device or independently administered source supplies
   chronological, schema-compatible evidence for source holdout.
3. Any repair uses development evidence and aggregate errors only; the consumed
   v5.26 blind pack must never become a tuning set.
4. A repaired candidate receives a newly preregistered untouched blind test
   before lifecycle reconsideration.

Deployment readiness additionally requires the separate MFU IAM preproduction,
approved-host operations, Gemini privacy/quota/key governance, real-device
transport, and security/recovery acceptance workstreams. At least five major
cross-system deployment workstreams therefore remain; their duration depends
on external owners and evidence availability.

## Verification

The final local matrix passes:

- taskboard render and standard checks;
- Ruff and compileall;
- backend tests: `832 passed, 1 skipped`;
- Alembic: no drift;
- React lint and production build;
- Playwright: `27 passed, 1 skipped` (external live-source test deferred);
- rule/scenario contract: 18 rules and 24 scenarios;
- layered detection: `288/288`, zero controlled FP/FN and zero responses;
- Assistant QA: `20/20` with zero authoritative side effects;
- v5.26 non-consuming private preflight: all eligibility/candidate checks pass;
- replay dry-run: two safe rows parsed and zero rows written;
- warning-free performance smoke at 145,232 rows: Overview `0.8518s`, cached
  Overview `0.0120s`, Alerts `0.0738s`, Cases `0.0264s`, and ML Governance
  `1.3055s`;
- official release gate: `ok: true`; and
- exact `15/15` path, empty staging, diff, privacy, ignored-evidence, and
  tracked-hygiene checks.

An initial standalone pytest attempt used `.pytest_tmp/` inside the repository,
which the backup-output safety policy correctly rejects. The affected tests
passed `21/21` with an external temp root, and the authoritative full rerun
passed `832 passed, 1 skipped`. No safety rule was weakened.

No commit or push is authorized by this phase.
