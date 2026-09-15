# T1 Change Title

v3.19 No-Hardware Soak, Parser Drift, And Alert Noise Stability

# T2 Requirement

Validate that ATDR can handle longer-running simulated live ingestion without real firewall hardware while preserving parser robustness, source health, alert deduplication, detection explanations, and safety.

# T3 Source Evidence

- `atdr/scripts/replay_logs.py`
- `atdr/scripts/run_source_scenario.py`
- `atdr/scripts/validate_parser_normalization.py`
- `atdr/scripts/validate_detection_quality.py`
- `atdr/app/parsers/paloalto_parser.py`
- `atdr/app/services/detection_service.py`
- `atdr/app/services/log_service.py`
- `atdr/app/services/source_service.py`
- `atdr/app/detection/explanations.py`
- `frontend/src/pages/ExecutiveOverview.tsx`
- `frontend/src/pages/LogExplorer.tsx`
- `frontend/src/pages/AlertsTriage.tsx`
- `docs/V3_18_DETECTION_CORPUS_AND_FP_FN_QA.md`
- `docs/DETECTION_RULE_CATALOG.md`
- `docs/tasks/tasklist-progress.md`

# T4 Current Behavior

ATDR already had controlled scenario validation, parser normalization checks, source health, source-scoped detection, alert deduplication, and explanation completeness checks. It did not have one command that simulates a multi-source no-hardware soak and reports parser drift, event-level FP/FN, dedup updates, source health, explanation completeness, and safety together.

# T5 Impacted Areas / Agents

- Orchestrator
- Backend / API
- Detection
- Parser / Data Quality
- QA / UAT
- Release-Ops
- Documentation

# T6 Scope

In scope:

- Add a safe `run_no_hardware_soak` CLI.
- Use only safe synthetic sample files.
- Support dry-run and temp-DB validation.
- Report source health, parser drift, alert noise, dedup, explanation completeness, and safety.
- Add backend tests and docs.

Out of scope:

- Detection threshold changes.
- ML retraining, activation, or promotion.
- Real firewall/router forwarding.
- Real response actions.
- External IAM/OIDC.
- Database reset or schema changes.

# T7 Functional Requirements

- The soak runner must support `--duration-seconds`, `--iterations`, `--source-count`, `--scenario-mix`, `--dry-run`, `--use-temp-db`, `--run-detection`, and `--pretty`.
- Dry-run must not write to the DB.
- Temp-DB validation must not mutate the current local DB.
- Parser drift report must include parser warnings, raw fallback, missing fields, unknown app count, and parse failures.
- Alert-noise report must include FP/FN scenario counts, unexpected attack types, alerts created, alerts deduplicated, and duplicate raw rows.
- Source report must include status, logs received, parse success/failure, unknown app rate, alert count, recent runs, latest errors, and warnings.
- Explanation report must verify dashboard-facing fields.
- Safety report must confirm zero response actions and zero ML model runs.

# T8 Acceptance Criteria

- `python -m atdr.scripts.run_no_hardware_soak --dry-run --iterations 1 --source-count 3 --pretty` returns `ok: true` and `current_database_mutated: false`.
- `python -m atdr.scripts.run_no_hardware_soak --use-temp-db --iterations 3 --source-count 3 --run-detection --pretty` returns `ok: true`.
- Response actions created equals 0.
- ML model runs created equals 0.
- Explanation completeness score equals 1.0 for created alerts.
- Backend tests pass.

# T9 API Contract

No API contract changes.

# T10 Data Model / Migration

No schema changes and no Alembic migration.

# T11 Backend Plan / Changes

- Add `atdr/scripts/run_no_hardware_soak.py`.
- Reuse existing source, parser, import, detection, and explanation services.
- Keep default behavior safe and explicit.

# T12 Frontend Plan / Changes

No frontend changes were required. Existing Overview, Log Explorer, Alerts, source detail, and Operations Health panels already expose the relevant data.

# T13 Security / Response / AI Safety

- No automatic response.
- No real firewall blocking.
- No external IAM/OIDC.
- No external LLM.
- No model activation, promotion, or retraining.
- Synthetic safe samples only.
- Temp-DB validation is the recommended mode.

# T14 Test Plan

- Dry-run no mutation.
- Temp-DB soak success.
- Parser drift rows do not crash.
- Raw fallback preserves evidence.
- Dedup updates occur under repeated traffic.
- Source health status is expected.
- Explanation completeness remains intact.
- Response and ML side effects remain zero.

# T15 Implementation Summary

Added `run_no_hardware_soak` and v3.19 tests/docs. The default pass/fail soak mix covers normal Palo Alto rows, incomplete application rows, generic syslog, raw fallback, malformed vendor-like fields, repeated suspicious traffic, scan-like traffic, denied SSH burst traffic, and C2-like beaconing. Targeted noisy edge cases remain available through `--scenario-mix`.

# T16 Tests Run / Evidence

Targeted:

- `ruff check atdr\scripts\run_no_hardware_soak.py atdr\tests\test_v319_no_hardware_soak.py`
- `python -m pytest atdr\tests\test_v319_no_hardware_soak.py -q`
- `python -m atdr.scripts.run_no_hardware_soak --use-temp-db --iterations 3 --source-count 3 --run-detection --pretty`

Final full verification evidence is recorded in `docs/tasks/tasklist-progress.md`.

# T17 PRD / Docs Updated

- `docs/V3_19_NO_HARDWARE_SOAK_AND_PARSER_DRIFT.md`
- `docs/changes/T1_T20_V3_19_NO_HARDWARE_SOAK_AND_PARSER_DRIFT.md`
- `docs/DETECTION_RULE_CATALOG.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/prd/PRD-ATDR.md`
- `docs/tasks/tasklist-progress.md`
- `docs/tasks/tasklist-progress.html`

# T18 Risks / Blockers / Assumptions / Decisions

- Real hardware syslog forwarding remains unvalidated.
- Scenario-level pass/fail is controlled lab QA, not production accuracy.
- The repeated benign internal-service scenario can become a connection-flood noise probe when repeated across soak iterations. It is kept available for targeted rule-noise analysis but excluded from the default pass/fail soak.
- Exfil-like rows can collide with C2-style grouping when mixed after C2 rows in the same source/window. That remains a future boundary/noise investigation, not a v3.19 threshold change.

# T19 Release / Rollback

Rollback is documentation/script-level: remove `atdr/scripts/run_no_hardware_soak.py`, `atdr/tests/test_v319_no_hardware_soak.py`, and the v3.19 docs updates. No migration rollback is required.

# T20 Final Handoff

v3.19 adds safe no-hardware soak validation. Use temp DB mode for release checks and dashboard-independent QA:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_no_hardware_soak --use-temp-db --iterations 3 --source-count 3 --run-detection --pretty
```

ATDR remains a controlled lab prototype. Production readiness is not claimed.
