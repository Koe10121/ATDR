# v5.40 Development-Only Supervised Model Repair

## Status

v5.40 is complete as a diagnostic development phase. It enforces the consumed
v5.39 evidence boundary, audits the remaining development evidence, evaluates
six supervised SOC queue strategies with nested temporal and duplicate-group
isolation, and defines a new blind-evidence protocol.

The result does not qualify a candidate for freezing or activation:

- lifecycle: `shadow_observation`;
- deterministic rules: alert-authoritative;
- best diagnostic ranking: `hierarchical_two_stage`;
- complete development gates passed: `0/3` folds;
- diagnostic candidate frozen: no;
- model artifact written, activated, or promoted: no; and
- automatic response and real firewall blocking: disabled.

## Consumed v5.39 Boundary

The evaluator fails closed unless the private v5.39 state reports one completed
attempt, both owner contracts are valid and closed, the expected 40 detection
rows exist, and the sealed pack still matches its private freeze.

Only the 40 review tokens needed to exclude matching configured rows are read.
The protected labels, predictions, errors, reviewer identities, digests, paths,
and row evidence are not opened or returned. The measured configured database
had zero token overlap, but the exclusion contract remains mandatory before
any future fit, calibration, threshold, or model-selection operation.

| Boundary measurement | Result |
| --- | ---: |
| Configured reviewed rows | `2,235` |
| Protected v5.39 tokens | `40` |
| Token matches removed before modeling | `0` |
| Protected rows used by any development role | `0` |
| Canonical development rows | `1,467` |
| Canonical temporal-final rows excluded | `532` |
| Canonical quarantined rows excluded | `236` |

The v5.39 evaluator was not called and its result was not used for model
selection.

## Development Evidence Audit

The 1,467-row development pool contains:

| Property | Result |
| --- | ---: |
| Manual provenance | `918` |
| Assisted/weak provenance, down-weighted | `549` |
| Benign | `108` |
| Benign unusual | `635` |
| Needs context | `64` |
| Suspicious | `456` |
| Malicious | `204` |
| Independent source identities | `1` |
| Duplicate groups | `1,201` |
| Multirow duplicate groups | `155` |
| Rows in multirow duplicate groups | `421` |
| Largest duplicate group | `5` |

The evidence is concentrated in one short chronological collection from one
source. Assisted provenance is substantial, and duplicate families require
fold isolation. v5.40 does not relabel assisted evidence as human-reviewed.

## Feature Repair

The development-only feature contract adds 12 numeric features and one
categorical evidence family for:

- QUIC/443 and routine encrypted allowed traffic;
- incomplete/80 allowed traffic;
- unknown UDP/TCP behavior;
- source destination/port diversity and scan context;
- local deterministic-rule and anomaly/behavior evidence;
- application risk and parser-field missingness; and
- low-signal routine traffic.

All added features are row-local or causal at scoring time. No hard
post-prediction suppression guard is used. Duplicate fingerprints are rebuilt
after feature augmentation and isolated between fit, calibration, threshold,
and evaluation roles.

## Development Comparison

v5.40 compares calibrated ExtraTrees, HistGradientBoosting, Logistic
Regression, a binary threat queue, a three-class SOC queue, and a hierarchical
two-stage strategy. Threshold selection is limited to fixed profiles at
`0.50`, `0.70`, `0.85`, and `0.92`; nested evaluation labels and v5.39 labels
cannot select a threshold.

No strategy passed every fixed gate on all three nested temporal folds. The
hierarchical two-stage strategy ranked first diagnostically:

| Metric | Minimum | Maximum | Mean |
| --- | ---: | ---: | ---: |
| Queue precision | `0.8333` | `0.9865` | `0.9059` |
| Queue recall | `0.1000` | `0.5828` | `0.3290` |
| Queue F1 | `0.1786` | `0.7068` | `0.4501` |
| Benign-like FPR | `0.0120` | `0.1176` | `0.0513` |
| Suspicious recall | `0.0719` | `0.5164` | `0.2405` |
| Malicious recall | `0.0000` | `0.9259` | `0.5489` |
| Macro F1 | `0.3938` | `0.6897` | `0.5211` |
| Weighted F1 | `0.4442` | `0.6945` | `0.5644` |
| Review queue rate | `0.0451` | `0.4153` | `0.2412` |

Low false-positive behavior was achieved only by missing too many true review
cases. Across nested prefixes, the leader produced 12 false-positive and 275
false-negative observations; rows can recur between prefixes. Most false
negatives were suspicious scan-like allowed traffic, including incomplete,
unknown UDP, QUIC, and SSL patterns. This is aggregate development diagnosis,
not independent accuracy evidence.

## Calibration

The leader used sigmoid calibration on dedicated calibration partitions, but
calibration remains weak:

| Metric | Minimum | Maximum | Mean |
| --- | ---: | ---: | ---: |
| Brier score | `0.2241` | `0.3901` | `0.3030` |
| Expected calibration error | `0.1862` | `0.5054` | `0.3244` |
| Maximum confidence/accuracy gap | `0.3454` | `0.9015` | `0.5612` |

Isotonic calibration is also evaluated where the dedicated partition has
enough class support; sparse partitions fail closed rather than borrowing
evaluation evidence.

## New Blind Evidence Design

The tracked protocol is documented in
`docs/detection/V5_40_NEW_BLIND_EVIDENCE_PROTOCOL.md`. It requires future
evidence strictly after the development cutoff, at least two independent real
source identities, at least three collection windows, and a target of 240
genuinely human-reviewed rows with minimum support of 100 benign-like, 50
suspicious, and 50 malicious rows.

The pack is designed but not collected. It contains no predictions, automatic
labels, development rows, or v5.39 rows and is not import-ready.

## Safety Result

The measured run preserved all configured state: raw logs `145,232`, normalized
logs `145,232`, alerts `3,231`, labels `2,672`, model runs `45`, detection runs
`31`, and response actions `0` before and after. Model artifacts, the private
v5.39 state, and the sealed v5.39 pack were unchanged.

No production-readiness or predictive-accuracy claim is made. The next
evidence-dependent phases are collection and genuine review of a new disjoint
multi-source blind pack, followed by one frozen evaluation and a separately
approved lifecycle decision.

## Verification

The final local matrix passes:

- taskboard render and standard checks;
- Ruff and canonical source compileall;
- focused v5.40 tests: `11 passed`;
- full backend and official release suites: `938 passed, 1 skipped`;
- Alembic: at head with no drift;
- React lint/build and Playwright: `35 passed, 1 skipped` (intentional live
  source skip);
- final controlled source acceptance: passed in disposable storage;
- layered detection validation: `288/288`, zero controlled false positives or
  false negatives;
- deterministic Assistant QA: `20/20`, all word budgets and safety checks;
- v5.38 product reliability: `11/11`;
- replay dry-run: parsed two safe sample rows with zero writes;
- performance smoke: no warnings, Overview `0.2144s`, cached Overview
  `0.0115s`, AI Governance `0.2833s`, alert list `0.0456s`, case summary
  `0.0635s`, and heavy supervised report `2.1603s`;
- official release verifier: `ok: true`, no failed required checks; and
- exact 12-path allowlist, empty staging area, ignored report, private-value,
  trailing-whitespace, and tracked-diff hygiene checks.

Existing scikit-learn warnings concern sparse legacy feature columns and older
calibration tests. The Windows joblib physical-core probe falls back to logical
cores. Neither condition caused a v5.40 failure or authority change.

## Operator Commands

Safe preflight:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v540_development_supervised_repair --preflight-only --no-report --pretty
```

Development-only diagnostic run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v540_development_supervised_repair --pretty
```

Generated reports remain ignored under `ml_baseline_reviews/`. No commit or
push is authorized by this document.
