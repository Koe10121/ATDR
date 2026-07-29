# v5.5 Development-Only Detection Model Repair And Anomaly Reliability Audit

Date: 2026-07-26

## Decision

v5.5 evaluates supervised SOC queue strategies and the existing
IsolationForest using only the v5.4 development roles for model fitting,
calibration, threshold selection, and diagnostic ranking. The v5.3 temporal
final, rolling-future, duplicate-quarantine, and external evidence remain
locked out of selection.

The lifecycle remains `shadow_observation`. No candidate is eligible for
activation or promotion. Deterministic rules remain alert-authoritative, and
automatic response and real firewall blocking remain disabled.

## Evidence Boundary

The tracked v5.4 lock reproduced exactly.

| Evidence role | Rows | Use in v5.5 |
| --- | ---: | --- |
| Fit | 957 | Development fitting only |
| Calibration | 282 | Development probability calibration only |
| Threshold selection | 228 | Development threshold selection only |
| Total development evidence | 1,467 | Candidate comparison and ranking |
| Temporal final | 532 | One read-only regression after candidate freeze |
| Duplicate quarantine | 236 | Excluded |
| Rolling future windows | 532 | Locked; not reopened |
| External benchmark | Locked aggregate | Not reopened |

The governed dataset fingerprint remains
`ae3d2972bdb888f0fba7631932ae512f674e5dbdb9cc72c1d3cd633d67ec4420`.
The locked temporal-final fingerprint remains
`db6a13ada1a1fed71e7ec9d013be138a98f1468e4551ee24729c17e4e875e71e`.

Development evaluation used three chronological prefix folds. Each fold kept
fit, calibration, threshold, final, and quarantine leakage groups disjoint.
Provenance-balanced sample weights were derived only from development rows.
Source-aware validation failed closed because the reviewed evidence contains
only one real source identity.

## Supervised Strategy Comparison

The in-memory diagnostic comparison included:

- calibrated ExtraTrees;
- calibrated HistGradientBoosting;
- calibrated Logistic Regression;
- a three-class SOC queue using ExtraTrees; and
- a hierarchical two-stage ExtraTrees strategy.

The best development-only diagnostic leader was
`three_class_soc_queue_extra_trees`. It passed **0/3** strict chronological
folds and is therefore not a selected lifecycle candidate.

| Metric | Development-fold range | Mean |
| --- | ---: | ---: |
| Threat/SOC queue F1 | 0.4904-0.7194 | 0.6126 |
| Benign-like false-positive rate | 0.0706-0.2683 | 0.1491 |
| Suspicious recall | 0.3279-0.6333 | 0.4882 |
| Malicious recall | 0.1429-0.7326 | 0.4276 |
| Expected calibration error | 0.1853-0.4644 | 0.3206 |

The result was frozen as a diagnostic leader before any locked-final label was
read. The freeze is evidence of evaluation ordering, not an active model
artifact and not an activation decision.

## Locked Temporal One-Shot Regression

After the development leader was frozen, v5.5 ran one read-only regression on
the 532-row locked temporal-final role.

| Metric | Result |
| --- | ---: |
| Threat-positive precision | 0.6049 |
| Threat-positive recall | 0.4153 |
| Threat-positive F1 | 0.4925 |
| Benign-like false-positive rate | 0.0773 |
| Suspicious recall | 0.3824 |
| Malicious recall | 0.4143 |
| Macro F1 | 0.6878 |
| Weighted F1 | 0.7966 |
| Review queue | 81 / 532 (0.1523) |
| Expected calibration error | 0.5405 |
| Maximum confidence/accuracy gap | 0.7076 |
| Calibration status | Weak |

Compared with the v5.3 temporal FPR of `0.9976`, the frozen diagnostic leader
substantially reduces queue noise. This is not an overall quality pass:
threat recall, suspicious recall, malicious recall, and calibration are below
the fixed gates. The locked result was not fed back into model, feature,
calibration, threshold, or strategy selection.

## IsolationForest Reliability

The existing IsolationForest artifact was loaded read-only and remained
byte-for-byte unchanged.

### Development evidence

| Metric | Result |
| --- | ---: |
| Rows scored | 1,467 |
| Anomaly count | 267 |
| Anomaly rate / queue rate | 0.1820 |
| Benign-like false-positive estimate | 0.2773 |
| Threat detection estimate | 0.0818 |
| Needs-context queue estimate | 0.1094 |

Noise-pattern anomaly rates were `0.0359` for QUIC/443, `0.0000` for
incomplete/80, and `0.0395` for unknown UDP/TCP. No ping rows were available
in the governed development set. Structured rows had a `0.2122` anomaly rate
versus `0.0391` for limited-schema rows.

Eight benign controlled scenarios scored 49 logs and produced eight anomaly
signals (`0.1633`), all in two allowed high-volume scenarios. They produced
zero authoritative false-positive scenarios and zero response actions because
anomaly output remains advisory.

### Locked temporal final

IsolationForest marked 5/532 rows anomalous (`0.0094`), with a benign-like FPR
estimate of `0.0000` and threat detection estimate of `0.0481`. The large
development-to-final rate change confirms that the existing artifact is not a
reliable standalone threat detector across the chronological shift.

## Quality And Lifecycle Decision

Readiness passed 2/7 governance checks.

Current blockers:

1. No supervised strategy passes all development temporal folds.
2. Source-aware evaluation cannot run with only one real source identity.
3. Independent reviewed multi-device evidence is unavailable.
4. The locked external benchmark remains failed and unavailable for tuning.
5. IsolationForest benign-like FPR is high on development evidence and threat
   capture is low.
6. The frozen supervised diagnostic has weak locked-final calibration and
   insufficient suspicious/malicious recall.

The current decision is:

- lifecycle: `shadow_observation`;
- candidate selected for lifecycle advancement: `false`;
- model activated or promoted: `false`;
- rules alert-authoritative: `true`;
- response automation allowed: `false`; and
- real firewall blocking enabled: `false`.

## Safety State

- Database counts before and after are identical.
- Labels created or overwritten: `0`.
- Model runs created: `0`.
- Detection runs created: `0`.
- Response actions created: `0`.
- Active supervised and IsolationForest artifacts are unchanged.
- ML created, suppressed, or modified authoritative alerts: `false`.
- No final/rolling/external labels contributed to selection.

## Verification

The governed v5.5 run completed in `18.9769s`.

- Taskboard render and standards checks passed.
- Whole-repo Ruff and compileall passed.
- Focused v5.4/v5.5 tests passed `13/13`.
- Full backend and release-gate backend suites passed
  `669 passed, 1 hardware-dependent skip`.
- Alembic reported no new upgrade operations on local SQLite.
- React lint and production build passed.
- Playwright passed `26`, with one live hardware scenario skipped.
- Controlled detection passed `24/24`, with zero unexpected or missed alerts
  and zero response actions.
- Layered validation passed `288/288`, with zero false-positive or
  false-negative runs.
- SOC Assistant QA passed `20/20`, with citation pass rate `1.0`, safe refusal,
  and zero response/detection/model/label side effects.
- Replay dry-run parsed two safe rows and wrote or sent zero.
- Performance smoke passed with no warnings: Overview `0.1926s`, cached
  `0.0117s`, alerts `0.0458s`, cases `0.0893s`, ML Governance `1.2955s`, and
  feature generation `0.0067s`.
- The official release gate returned `ok: true` with zero failed required
  checks.

## Remaining Evidence Required

1. Independently reviewed chronological evidence from new collection periods.
2. Reviewed evidence from at least two real source devices.
3. A new untouched schema-compatible external benchmark.
4. Broader benign and threat support across applications, schemas, and time.
5. Advisor/environment approval before any future lifecycle advancement.

Generated JSON and Markdown diagnostics remain ignored under
`ml_baseline_reviews/`. No commit or push is authorized by this document.
