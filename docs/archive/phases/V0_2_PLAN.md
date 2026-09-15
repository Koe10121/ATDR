# ATDR v0.2 Phase 1 Plan

## Goal

Improve realistic lab ingestion and alert quality while preserving the v0.1 local workflow.

## Added In Phase 1

- Safe log replay command for dry-run, UDP syslog replay, and direct local import replay.
- Near-real-time ingestion validation flow in the lab runbook.
- Active-alert deduplication for repeated replay/live ingestion patterns.
- Better computed case summaries with related log counts, destination ports, actions, and recommended analyst focus.
- Overview ingestion quality snapshot for parser and dedup visibility.
- Parser warnings for malformed, incomplete, unknown-app, and missing-field rows.

## Added In Phase 2

- Ingestion run history for file import, direct replay, and syslog receiver batches.
- Detection run history for rule/hybrid detection runs.
- API endpoints:
  - `GET /api/ingestion/runs`
  - `GET /api/ingestion/runs/{id}`
  - `GET /api/detection/runs`
  - `GET /api/detection/runs/{id}`
- Overview **Operations Health** panel with latest run status, parse failures, alert creation, dedup counts, and runtime.
- Replay direct mode records run history when not in dry-run mode.
- Optional read-only performance smoke command:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --feature-limit 20 --pretty
```

## Added In Phase 3

- Added summary performance indexes for anomaly, model-run, label-review, raw-log import time, and alert status/severity queries.
- Reworked Overview ingestion statistics to use run-history duplicate counts instead of grouping the full raw log text table on every page load.
- Reworked AI Governance summary counting so large local datasets avoid repeated raw-log and JSON parser-error scans during normal dashboard use.
- Added short-lived React Query caching for ML Governance panels and a manual **Refresh ML Summary** action after training, scoring, or label import.
- Expanded `performance_smoke` to time:
  - Overview summary
  - ingestion run history
  - detection run history
  - alert list
  - case summary
  - ML Governance lightweight summary
  - supervised model report
  - feature generation sample

## Performance Budgets

- Overview summary should ideally load under `1s` on the local SQLite lab DB.
- ML Governance lightweight summary should ideally load under `2s`.
- Supervised model report/export can be slower because it is a heavier governance artifact.
- If a performance warning appears, treat it as a lab-readiness signal, not a security detection failure.

## Run History Interpretation

- `status`: `running`, `completed`, or `failed`.
- `parsed_successfully`: rows parsed into usable normalized fields.
- `parse_failures`: rows preserved as raw evidence with parser error metadata.
- `duplicate_raw_logs`: replay/import rows that matched an existing raw line.
- `alerts_created`: new alert groups created during the related run.
- `alerts_deduplicated`: existing active alerts updated instead of flooding the queue.
- `alerts_suppressed`: low-volume or suppression-rule-filtered groups.
- `runtime_seconds`: simple wall-clock duration for lab visibility, not a formal benchmark.

## What Remains Simulated

- Response actions remain simulated.
- Response requires analyst/admin approval and audit evidence.
- No real firewall enforcement is enabled.
- Docker/PostgreSQL remains optional for lab validation and is not required locally.

## What Still Requires Real Lab Hardware

- Forwarding syslog from an actual firewall/router to the ATDR receiver.
- Measuring sustained ingestion performance under lab traffic volume.
- Validating firewall connector design, allowlists, rollback, and change approval before any real blocking.

## Recommended Next Step

Continue with v0.3 source management. Validate that replay, file import, and syslog senders appear as tracked sources, then confirm source health and source-level parser quality stay understandable during lab ingestion.
