# v5.8 Governed Shadow Scoring Runtime And Evidence Intake Hardening

Date: 2026-07-26

## Decision

ATDR can now evaluate the frozen v5.6/v5.7 supervised candidate against
bounded normalized-log batches as a strictly read-only shadow process.
Shadow scoring is disabled by default, fails closed on any artifact or
contract mismatch, and never creates, suppresses, or modifies alerts.

The candidate remains a **Frozen Diagnostic Candidate** in
`shadow_observation`. Deterministic rules remain alert-authoritative,
IsolationForest remains separately advisory, production promotion is false,
and response automation is disabled.

## Frozen Contract

The local frozen contract matched all required checks:

| Contract | Matched value |
| --- | --- |
| Candidate | `calibrated_hist_gradient_boosting` |
| Model family | `HistGradientBoostingClassifier` |
| Calibration | sigmoid |
| Threshold | `0.3` |
| Feature count | 40 |
| Decision policy | calibrated threshold only |
| Post-prediction guard | none |
| Active / promoted | false / false |
| Rules alert-authoritative | true |
| Fallback model allowed | false |

The public/API contract does not return the artifact path, artifact hash,
feature names, private identifiers, raw logs, or secrets.

## Runtime Contract

Configuration is disabled by default:

```text
GOVERNED_SHADOW_SCORING_ENABLED=false
GOVERNED_SHADOW_BATCH_SIZE=250
GOVERNED_SHADOW_MAX_BATCH_SIZE=1000
GOVERNED_SHADOW_TIMEOUT_SECONDS=30
GOVERNED_SHADOW_CACHE_SECONDS=30
```

The service:

- reads only normalized logs;
- preserves chronological ordering and optional source/time scope;
- enforces batch and timeout bounds;
- caches identical process-local evaluations without persistent writes;
- uses no silent model fallback;
- accesses no labels and calculates no accuracy metrics;
- computes aggregate score, confidence, queue, drift, source/time stability,
  rule-agreement, and persisted IsolationForest telemetry; and
- verifies database and artifact state before and after evaluation.

Authenticated analyst/admin status is available at:

```text
GET /api/ml/supervised/shadow-runtime
```

The CLI is:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v58_governed_shadow_runtime --pretty
```

An intentionally scoped shadow run can be enabled for one process without
changing `.env`:

```powershell
$env:GOVERNED_SHADOW_SCORING_ENABLED="true"
.\.venv\Scripts\python.exe -m atdr.scripts.run_v58_governed_shadow_runtime --execute-shadow --limit 100 --pretty
```

## Measured Aggregate Shadow Result

A bounded 100-row run against the configured database produced:

| Measure | Result |
| --- | ---: |
| Rows evaluated | 100 |
| Advisory queue count / rate | 47 / 47.0% |
| Score mean / p95 | 0.3774 / 0.9407 |
| Confidence mean / p95 | 0.7914 / 0.9408 |
| Drift state | `Drift Warning` |
| Application total-variation distance | 0.2620 |
| Schema total-variation distance | 0.0600 |
| Rule/shadow disagreement | 58 / 58.0% |
| Persisted IsolationForest anomalies | 9 / 9.0% |
| Runtime | 8.2395s |

This is unlabeled monitoring evidence, not an accuracy result. The high
queue/disagreement rates and drift warning reinforce the conservative
shadow-only decision.

## Mutation-Safety Proof

Before/after checks confirmed:

- configured database counts unchanged;
- active model artifact states unchanged;
- frozen candidate artifact unchanged;
- raw and normalized logs created: `0`;
- alerts and alert-evidence rows created: `0`;
- labels and model runs created: `0`;
- detection runs and response actions created: `0`; and
- model activation, production promotion, automation, and real blocking:
  `false`.

## Governed Evidence Intake

The v5.8 preflight composes the v5.7 independent-evidence contract and adds
explicit rejection of evidence already used for a v5.7 prediction freeze. It
validates manifest/schema/chronology, device and period counts, provenance,
checksums, configured-database overlap, and duplicate containment.

It never emits private paths, raw rows, IPs, row fingerprints, or file hashes.
It does not calculate blind accuracy and does not access labels. Predictions
and one-time label reveal remain governed by the v5.7 protocol.

Required invocation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v58_governed_shadow_runtime `
  --sample-path "<NEW_PRIVATE_PANOS_PATH>" `
  --evidence-manifest "<APPROVED_MANIFEST_PATH>" `
  --preflight-only `
  --use-temp-db `
  --pretty
```

## Dashboard

AI Governance displays:

- Frozen Diagnostic Candidate;
- Shadow Scoring Enabled or Disabled;
- Candidate Contract Matched or Mismatched;
- Independent Evidence Pending or Available;
- Rules Authoritative; and
- Response Automation Disabled.

Only aggregate rows, queue rate, drift state, and rule/shadow disagreement are
shown. No row-level evidence is exposed.

## Verification

The final local verification matrix passed:

- focused v5.1-v5.8 governance tests: `61 passed`;
- new authenticated API and v5.8 tests: `6 passed`;
- authoritative backend suite: `700 passed, 1 skipped`;
- Ruff and compileall: passed;
- Alembic: no drift;
- React lint and production build: passed;
- Playwright: `26 passed, 1 skipped` (live-hardware test);
- controlled scenario corpus: `24/24`, 15 expected alerts, and zero response
  actions;
- controlled layered validation: `288/288`, zero false positives and zero
  false negatives;
- deterministic assistant QA: `20/20`, with no response, detection, label,
  model, alert, or log side effects;
- replay dry-run: two safe rows parsed and zero rows written;
- read-only performance smoke: no warnings, Overview `0.1546s`, cached
  Overview `0.0102s`, and AI Governance `1.1267s`; and
- official release gate: `ok: true` with no failed required checks.

Taskboard rendering/standard checks, tracked-file hygiene, and
`git diff --check` also passed. Generated telemetry and private evidence
remain ignored. No commit or push was performed.

## Remaining External Evidence

1. Two independently operated real source devices.
2. At least two new collection periods outside all v5.3-v5.7 evidence.
3. Provider- or human-confirmed PAN-OS-compatible labels.
4. Verified non-overlap and duplicate-family isolation.
5. Advisor acknowledgement before prediction freeze and approval before
   one-time label reveal.

Until those exist, the lifecycle remains `shadow_observation`. No commit or
push is authorized by this document.
