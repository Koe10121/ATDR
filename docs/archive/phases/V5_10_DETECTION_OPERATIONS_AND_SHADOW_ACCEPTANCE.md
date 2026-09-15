# v5.10 Detection Operations Reliability And Longitudinal Shadow Acceptance

Date: 2026-07-28

## Decision

ATDR now has a governed operational acceptance layer for the frozen
supervised shadow candidate. It discovers bounded, non-overlapping
source/time scopes from the configured database, records aggregate-only
observations through the existing v5.9 contract, and reports longitudinal
queue, disagreement, drift, data-quality, IsolationForest, and runtime
behavior.

The eight required operational gates passed. Four operational warnings remain
visible because queue and rule/shadow disagreement vary materially, three
scopes are out-of-distribution warnings, and two scopes contain insufficient
evidence.

This result is operational evidence only. It is reused development evidence,
not independent validation, and no accuracy metric was calculated. The
supervised lifecycle remains `shadow_observation`. Deterministic rules remain
alert-authoritative, IsolationForest remains advisory, no model is activated
or promoted, response automation remains disabled, and real firewall blocking
remains disabled.

## Historical Scope Contract

The v5.10 planner uses only configured-database evidence that already exists.
It:

- discovers configured sources with normalized evidence;
- partitions each source chronologically into bounded, non-overlapping scopes;
- marks every scope
  `reused_development_operational_evidence_only`;
- exposes opaque names such as `source-scope-01` instead of source IDs or
  names;
- excludes locked-final labels and does not calculate accuracy;
- rejects a frozen-candidate contract mismatch before persistence; and
- remains disabled unless both governed shadow scoring and observation are
  explicitly enabled in the executing process.

The planner found four source scopes and eight chronological scopes. Six had
sufficient evidence and two were retained as `Insufficient Evidence`. No
second device or independent evidence was fabricated.

## Operational Result

The first governed execution completed all eight planned scopes:

| Measure | Result |
| --- | ---: |
| Observations | 8 |
| Source scopes | 4 |
| Time scopes | 8 |
| Successful / failed | 8 / 0 |
| Sufficient / insufficient | 6 / 2 |
| Queue-rate range | 0.000000 to 1.000000 |
| Mean queue rate | 0.672734 |
| Rule/shadow disagreement range | 0.000000 to 0.684000 |
| Mean rule/shadow disagreement | 0.278047 |
| IsolationForest anomaly-rate range | 0.000000 to 0.020000 |
| Mean IsolationForest anomaly rate | 0.005000 |
| Runtime range | 0.033915s to 4.200560s |
| Missing-feature rate | 0.000000 |
| Parser-error rate | 0.000000 |
| Operational gates | 8 / 8 passed |

Drift states:

| State | Scope count |
| --- | ---: |
| Stable | 2 |
| Drift Warning | 1 |
| OOD Warning | 3 |
| Insufficient Evidence | 2 |

The current aggregate state is `OOD Warning`. That warning is not a detector
accuracy claim. It means the observed aggregate operating distribution differs
materially from the governed fit baseline and must remain visible during
shadow observation.

## Idempotency And Mutation Proof

A second execution reused all eight observation keys:

- created observations: `0`;
- idempotently reused observations: `8`;
- failed observations: `0`; and
- frozen-candidate contract mismatches: `0`.

Every stored observation carries the v5.10 aggregate operational contract and
zero-mutation proof. The run created no alerts, cases, labels, model runs,
detection runs, or response actions and did not activate or promote a model.

## Privacy And Retention

Operational API, CLI, job, and dashboard output exclude:

- source identifiers and source names;
- raw logs and row-level evidence;
- IP addresses;
- private file paths;
- row, file, or artifact fingerprints;
- labels and reviewed decisions; and
- secrets.

The existing v5.9 retention operation remains admin-only, explicit, previewed,
audited, and isolated to aggregate shadow-observation rows. Retention was not
applied during this acceptance pass.

## API And CLI

Authenticated analyst/admin read-only endpoints:

```text
GET /api/ml/supervised/shadow-operations/plan
GET /api/ml/supervised/shadow-operations/acceptance
```

Safe plan and acceptance inspection:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v510_detection_operations_acceptance --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v510_detection_operations_acceptance --acceptance-only --pretty
```

Explicit process-local execution:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v510_detection_operations_acceptance --execute --pretty
```

The CLI enables governed scoring and observation only for its own process and
restores the previous environment afterward. The dashboard exposes no analyst
execution control; durable observation jobs remain an admin operation.

## AI Governance

The AI Governance page now shows compact operational shadow evidence:

- observation, source-scope, and time-scope counts;
- latest observation time and current drift state;
- mean queue and rule/shadow disagreement;
- failed and insufficient scope counts;
- eight operational gate results; and
- bounded operational warnings.

The panel keeps `Rules Authoritative`, `Shadow Observation`,
`No Model Activation`, `Response Automation Disabled`, and
`Raw Evidence Excluded` visible.

## Cold Performance Repair

The inherited large-SQLite cold warning was traced to the ML Governance
`dataset_profile` path. Broad conditional aggregates caused SQLite to read
wide normalized-log rows despite existing indexes. Profiling showed that
component at approximately `10.1258s`.

The repair:

- adds the covering index
  `ix_normalized_ml_profile_cover(is_anomaly, action, app_risk, app)`;
- rewrites traffic and quality aggregates as scalar subqueries;
- reuses shared aggregate/distribution work across Governance sections;
- avoids loading the frozen model contract for the lightweight observation
  summary; and
- adds a cold/warm profiler and response-equivalence checks.

Post-repair profiling:

| Measure | Result |
| --- | ---: |
| ML Governance cold | 0.290613s |
| ML Governance warm | 0.257297s |
| Queries cold / warm | 29 / 29 |
| Cold/warm response equivalent | true |

The final performance smoke measured ML Governance at `0.2676s` cold and
`0.2520s` warm with no warnings. Overview was `0.1710s`, cached Overview
`0.0099s`, alert list `0.0367s`, case summary `0.0647s`, heavy supervised
report `1.8963s`, and feature generation `0.0068s`.

## Verification

The complete local closure matrix passed:

- taskboard renderer and standard checker: passed;
- Ruff and compileall: passed;
- focused v5.10/v5.9/API/performance tests: `15 passed`;
- authoritative backend suite: `714 passed, 1 skipped`;
- Alembic current/check: `d6e7f8a9b0c1` at head, no drift;
- React lint and production build: passed;
- Playwright: `26 passed, 1 skipped` (live-hardware test);
- controlled detection scenarios: `24/24`;
- layered validation: `288/288`, zero controlled false positives and zero
  controlled false negatives;
- deterministic assistant QA: `20/20`, all mutation checks true;
- replay dry-run: two safe rows parsed and zero writes;
- cold/warm profiler and performance smoke: passed with equal responses and
  no warnings; and
- official release gate: `ok: true`.

The full backend suite retains existing scikit-learn warnings for sparse
legacy features and calibration diagnostics plus a Windows logical-core
fallback warning. They do not represent v5.10 test failures.

## Remaining External Evidence Gate

Operational acceptance does not close model-readiness evidence gaps. ATDR
still requires:

1. independently operated real sources, including at least two devices;
2. new, non-overlapping collection periods;
3. native or documented compatible PAN-OS evidence;
4. human-, advisor-, or provider-confirmed labels hidden until prediction is
   frozen;
5. provenance, permission, and overlap/duplicate review; and
6. one preregistered, read-only independent evaluation.

Until those inputs exist, v5.10 supports reliable shadow operations only.
No commit or push is authorized by this document.
