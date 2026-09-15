# v5.11 Operational Drift And Shadow Monitoring Hardening

Date: 2026-07-28

## Decision

ATDR now explains the aggregate operational warnings recorded by v5.10 and
provides a disabled-by-default, durable monitoring cadence using the existing
operation-job infrastructure.

The current eight observations remain reused, unlabeled development
telemetry. They support operational drift diagnosis only. They do not support
accuracy, false-positive, recall, F1, or calibration claims. The supervised
lifecycle remains `shadow_observation`; deterministic rules remain
alert-authoritative; IsolationForest remains advisory; no model is activated
or promoted; response automation and real firewall blocking remain disabled.

## Measured Root Causes

The diagnostic pass inspected eight observations from four opaque source
scopes. It found:

| Aggregate cause | Observation count |
| --- | ---: |
| Application-distribution shift | 6 |
| Parser-profile limited fields | 3 |
| Parser-quality shift | 3 |
| Candidate-score or queue shift | 2 |
| Short or sparse window | 2 |
| Source-volume imbalance | 2 |
| Rule/shadow disagreement shift | 1 |
| No material aggregate shift | 2 |
| IsolationForest variation | 0 |

Interpretation:

- Queue rate varies from `0.000000` to `1.000000`, with mean `0.672734`.
  The large changes follow application mix and candidate-score regimes. They
  are queue-operating signals, not measured false positives.
- Rule/shadow disagreement varies from `0.000000` to `0.684000`, with mean
  `0.278047`. Only one chronological transition exceeds the v5.11 change
  threshold. Disagreement does not identify which layer is correct.
- Six observations have material application-distribution shift. Schema
  total variation remains approximately `0.001930`, so broad schema
  missingness is not the dominant OOD cause.
- Three observations contain limited parser fields or unknown applications.
  One 64-row OOD window has warning/unknown rates of approximately `0.90625`.
- Two source scopes contain only 20 and 10 rows. They remain
  `Insufficient Evidence` and are never converted into accuracy claims.
- IsolationForest anomaly rate stays between `0.000000` and `0.020000`, with
  mean `0.005000`. No transition crosses its variation threshold, so the
  advisory anomaly layer is not the measured root cause.

The effective current state remains `OOD Warning`.

## Monitoring Thresholds

v5.11 classifies aggregate operating evidence with fixed thresholds:

| Monitor | Threshold |
| --- | ---: |
| Minimum sufficient rows | 50 |
| Drift total variation | 0.25 |
| OOD total variation | 0.50 |
| Parser-limited rate | 0.50 |
| Queue-rate change | 0.35 |
| Candidate score-mean change | 0.20 |
| Rule/shadow disagreement change | 0.35 |
| IsolationForest anomaly-rate change | 0.05 |
| Low source-volume ratio | 0.25 |

These thresholds do not alter the classifier, model threshold, rule engine,
alert creation, or response behavior.

## Hysteresis

The monitoring display uses conservative state hysteresis:

- `Drift Warning` requires two consecutive drift observations to escalate
  from `Stable`.
- Recovery from `Drift Warning` requires two consecutive stable
  observations.
- `OOD Warning` escalates immediately.
- Recovery from `OOD Warning` requires three consecutive sufficient,
  lower-risk observations.
- `Insufficient Evidence` never clears an existing warning.

The raw state remains available beside the effective state for auditability.

## Disabled Operational Cadence

The new durable job type is `shadow_monitoring_cycle`. It is disabled by
default and has no always-on scheduler. An external operator may perform a
due check only after all three settings are enabled:

```text
GOVERNED_SHADOW_SCORING_ENABLED=true
GOVERNED_SHADOW_OBSERVATION_ENABLED=true
GOVERNED_SHADOW_MONITORING_ENABLED=true
```

Defaults:

- cadence: 60 minutes;
- maximum source scopes: 8;
- maximum windows per source: 3;
- minimum rows per sufficient scope: 50;
- maximum rows per window: 250;
- retries: 2;
- duplicate suppression: cadence-bucket idempotency key; and
- cooperative cancellation: enabled.

This mechanism does not create an in-process or always-on scheduler. It uses
the existing durable worker only when an authorized operator or deployment
scheduler invokes the due check.

## API, CLI, And Dashboard

Authenticated analyst/admin read-only diagnostics:

```text
GET /api/ml/supervised/shadow-operations/diagnostics
```

Inspect aggregate diagnostics:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v511_shadow_monitoring --pretty
```

Ask for one due-check enqueue:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v511_shadow_monitoring `
  --enqueue-if-due `
  --pretty
```

The AI Governance page includes a collapsed operational drill-down with
opaque source/time scope labels, observation time, raw/effective drift state,
queue rate, disagreement, anomaly rate, aggregate quality warning, root-cause
codes, and runtime. It exposes no source identifiers, raw rows, labels,
private paths, or execution controls.

## Retention Rehearsal

The retention rehearsal ran only in a disposable in-memory SQLite database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v511_shadow_monitoring `
  --retention-rehearsal `
  --pretty
```

Result:

- preview candidate count: 1;
- deleted aggregate observations: 1;
- recent aggregate observations preserved: 1;
- users, raw logs, normalized logs, alerts, labels, model runs, ingestion
  runs, detection runs, and response actions all preserved;
- retention audit event created;
- configured database accessed: false; and
- no source identifiers, paths, raw evidence, or secrets returned.

No retention operation was applied to the configured database.

## Privacy And Mutation Proof

Diagnostics, API, CLI, job summaries, and dashboard output explicitly report:

- accuracy metrics calculated: false;
- labels accessed: false;
- source identifiers included: false;
- raw logs included: false;
- IP addresses included: false;
- private paths included: false;
- fingerprints included: false;
- secrets exposed: false;
- model activated: false;
- production promoted: false;
- response automation allowed: false; and
- real firewall blocking enabled: false.

The public v5.9 observation serializer no longer returns the internal
`source_id`. Internal database filtering retains that field only for bounded
queries.

## Verification

Complete closure evidence:

- v5.11 backend tests: `7 passed`;
- v5.9/v5.10 regression tests: `13 passed`;
- focused API authorization/privacy checks: `8 passed`;
- authoritative backend suite: `722 passed, 1 skipped`;
- Alembic current/check: `d6e7f8a9b0c1` at head, no drift;
- React lint and production build: passed;
- Playwright: `26 passed, 1 skipped` (live-hardware test);
- controlled detection scenarios: `24/24`;
- layered validation: `288/288`, zero controlled false positives and zero
  controlled false negatives;
- deterministic assistant QA: `20/20`, all mutation checks true;
- replay dry-run: two safe rows parsed and zero writes;
- performance smoke: passed with no warnings;
- official release gate: `ok: true`;
- diagnostics: 8 observations, 4 opaque scopes, aggregate-only;
- disabled cadence due check: zero jobs created;
- retention rehearsal: passed with configured database untouched; and
- taskboard, Ruff, compileall, exact allowlist, protected-file tracking,
  secret-safe fixture classification, and `git diff --check`: passed.

Measured performance:

| Operation | Seconds |
| --- | ---: |
| Overview | 0.1551 |
| Cached Overview | 0.0113 |
| AI Governance cold | 0.2717 |
| AI Governance warm | 0.2580 |
| Alert list | 0.0305 |
| Case summary | 0.0668 |
| Heavy supervised report | 1.8768 |
| Feature generation | 0.0066 |

The first full-suite attempt could not access the Windows global pytest temp
directory. A second attempt under `.pytest_tmp` correctly triggered ATDR's
in-repository backup-root safeguard. The affected persistence tests passed
`14/14` under the approved ignored `.tmp/` root, after which the full suite
and independent release-gate suite both passed there. No product safety check
was weakened.

## Remaining Evidence

v5.11 improves operational interpretation and repeatability. It does not
close the model-readiness gate. ATDR still needs:

1. at least two independently operated real devices;
2. at least two new, non-overlapping collection periods;
3. native or documented compatible PAN-OS evidence;
4. independently human-, advisor-, or provider-confirmed labels;
5. prediction-before-label and overlap/duplicate review; and
6. one preregistered read-only independent evaluation.

No commit or push is authorized by this status record.
