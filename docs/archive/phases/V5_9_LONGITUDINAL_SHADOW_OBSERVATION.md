# v5.9 Longitudinal Shadow Observation And Independent Evidence Acquisition

Date: 2026-07-27

## Decision

ATDR can now record bounded, append-only aggregate observations from the
frozen v5.6/v5.7 diagnostic candidate. The observation path is disabled by
default, source/time scoped, idempotent, retention controlled, and available
through a durable admin job. It does not expose row-level evidence or change
authoritative detection, labels, cases, models, or response state.

The supervised lifecycle remains `shadow_observation`. Deterministic rules
remain alert-authoritative, IsolationForest remains advisory, no model is
activated or promoted, response automation remains disabled, and real
firewall blocking remains disabled.

## Runtime Configuration

```text
GOVERNED_SHADOW_OBSERVATION_ENABLED=false
GOVERNED_SHADOW_OBSERVATION_RETENTION_DAYS=90
GOVERNED_SHADOW_OBSERVATION_TREND_LIMIT=30
```

`GOVERNED_SHADOW_SCORING_ENABLED` must also be explicitly enabled for a
recorded observation. Neither setting is enabled by default.

## Observation Contract

Each persisted observation contains only aggregate operational telemetry:

- frozen candidate identity and internal contract-match state;
- source ID and requested/observed time bounds;
- rows evaluated and advisory queue count/rate;
- score and confidence summary values;
- aggregate missing-feature count;
- application/schema drift state;
- aggregate rule agreement/disagreement;
- persisted IsolationForest aggregate;
- bounded runtime/failure state; and
- actor and creation timestamp.

An internal contract fingerprint supports idempotency but is not returned by
the API, CLI, job summary, or dashboard. Private paths, raw logs, IP
addresses, row values, row fingerprints, file fingerprints, feature lists,
labels, and secrets are excluded.

## API, Job, And CLI

Authenticated analyst/admin read access:

```text
GET /api/ml/supervised/shadow-observations
GET /api/ml/supervised/shadow-observations/summary
```

Admin-only retention:

```text
GET  /api/ml/supervised/shadow-observations/retention/preview
POST /api/ml/supervised/shadow-observations/retention/apply
```

Admin-only durable execution uses the existing job endpoint with
`job_type=shadow_observation`. Submission validates enablement, source,
chronological bounds, and row limits. Retry is safe because observation keys
are idempotent; running cancellation is checked before aggregate persistence.

Local status:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v59_longitudinal_shadow_observation --pretty
```

Explicitly enabled, bounded execution:

```powershell
$env:GOVERNED_SHADOW_SCORING_ENABLED="true"
$env:GOVERNED_SHADOW_OBSERVATION_ENABLED="true"
.\.venv\Scripts\python.exe -m atdr.scripts.run_v59_longitudinal_shadow_observation `
  --execute-shadow `
  --source-id <SOURCE_ID> `
  --start-at "<ISO_TIMESTAMP>" `
  --end-at "<ISO_TIMESTAMP>" `
  --limit 250 `
  --pretty
```

Retention is never automatic:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v59_longitudinal_shadow_observation `
  --retention-preview `
  --pretty
```

Applying retention requires an explicit `--retention-apply` command and
creates an audit event.

## Private Development-Evidence Result

The complete private PAN-OS file was inspected through an explicit CLI
argument in disposable storage. It was not imported into the configured
database and remains reused private development evidence, not an independent
holdout.

| Measure | Result |
| --- | ---: |
| Rows inspected | 773,551 |
| Timed / untimed rows | 773,551 / 0 |
| Chronological windows | 8 |
| Parser failures | 0 |
| Exact duplicates | 0 |
| Core-field missing rate | 0 |
| Maximum application-distribution shift | 0.117569 |
| Maximum schema-distribution shift | 0.001429 |
| Unknown-application rate range | 0.053364 to 0.080189 |
| Aggregate drift status | `Stable` |

The last window contains 3,092 rows and is a partial terminal window. The
result is aggregate parser/drift evidence only. The file has no independent
ground-truth labels, so no accuracy, false-positive, recall, F1, or
calibration claim is made.

The disposable pass returned no path, raw row, IP address, fingerprint, or
secret. It did not access or modify the configured database or model
artifacts.

## Dashboard

AI Governance now provides a compact longitudinal panel:

- observation count and bounded trend count;
- latest drift state;
- mean advisory queue rate;
- mean rule disagreement;
- queue/disagreement trend when at least two observations exist;
- `Rules Authoritative`;
- `No Model Activation`;
- `Response Automation Disabled`; and
- `Raw Evidence Excluded`.

The panel displays observed telemetry, not model accuracy.

## Independent Evidence Finding

An official-source review found several useful labeled network-security
datasets, but none is a newly acquired native PAN-OS, independently labeled,
multi-device corpus:

- CICIDS2017 and CSE-CIC-IDS2018 provide labeled flow/PCAP evidence;
- UNSW-NB15 provides labeled flow/packet evidence;
- CTU-13 provides labeled botnet, normal, and background captures; and
- Palo Alto documentation defines the native traffic/threat log contracts.

CSE-CIC-IDS2018 is already opened/locked ATDR evidence. Generic flow datasets
can support transfer testing but cannot satisfy the native PAN-OS independent
evidence gate. No new dataset was downloaded, no hash is claimed, and no
assisted review pack was generated because no genuinely new ambiguous PAN-OS
evidence exists.

See `docs/detection/V5_9_INDEPENDENT_EVIDENCE_ACQUISITION.md`.

## Verification

The final local verification matrix passed:

- taskboard render and standard checks: passed;
- Ruff and compileall: passed;
- focused v5.9/API backend tests: `8 passed`;
- authoritative backend suite: `708 passed, 1 skipped`;
- additive migration full-history upgrade/downgrade/re-upgrade: passed;
- current Alembic revision: `c5d6e7f8a9b0` at head with no drift;
- React lint and production build: passed;
- Playwright: `26 passed, 1 skipped` (live-hardware test);
- controlled scenario corpus: `24/24`;
- controlled layered validation: `288/288`, zero false positives and zero
  false negatives;
- deterministic assistant QA: `20/20`, with no response, detection, label,
  model, alert, or log side effects;
- replay dry-run: two safe rows parsed and zero rows written;
- complete private disposable preflight: all 773,551 rows parsed;
- official release gate: `ok: true`; and
- exact allowlist paths, protected-file ignore rules, and `git diff --check`:
  passed.

The first cold performance smoke reported one AI Governance advisory at
`11.7734s`. An immediate repeat had no warnings: Overview `0.1893s`, cached
Overview `0.0116s`, AI Governance `1.3571s`, alerts `0.0440s`, cases
`0.1075s`, and feature generation `0.0079s`. Cold large-SQLite initialization
remains an operational warning; the warm path is within the local budget.

The first full backend invocation used a long Windows temporary path and one
template backup test hit the platform path-length limit. The same test and
the complete suite passed under a short external temporary root; this was not
an application failure.

## Remaining External Gates

1. Two independently operated real firewall devices.
2. At least two new, non-overlapping collection periods.
3. Native or documented compatible PAN-OS evidence.
4. Human-, advisor-, or provider-confirmed labels hidden until prediction is
   frozen.
5. Provenance/license permission and local overlap/duplicate audit.
6. Advisor acknowledgement before freeze and approval before one-time reveal.

Until those exist, longitudinal observations support drift monitoring only.
No commit or push is authorized by this document.
