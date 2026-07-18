# T1-T20: v4.8 End-to-End Product Acceptance

## T1 Change Title

v4.8 End-to-End Product Acceptance And Failure-Recovery Validation.

## T2 Requirement

Prove the implemented ATDR workflow from migrated storage and multi-source ingestion through detection, investigation, assistant use, observability, and recovery using only safe synthetic evidence and disposable databases.

## T3 Source Evidence

`atdr/app/main.py`, database engine/migrations/models, source/staging/job/worker/resumable-ingestion services, parser profiles, detection/alert/case/explanation services, assistant/LLM services, dashboard/metrics services, persistence service, v3.97 ingestion validator, v3.95 recovery drill, safe scenario files, related tests, and current runbooks.

## T4 Current Behavior

Individual subsystems had strong focused tests and separate validators, but no single fail-closed command proved their contracts together at practical scale with interruption, deduplication, assistant follow-ups, and backup/restore.

## T5 Impacted Areas / Agents

Orchestrator, Backend/API, Data/Database, Detection, Assistant/AI Safety, Security/Response Safety, QA/UAT, Release/Ops, and Documentation.

## T6 Scope

An isolated acceptance orchestrator, focused tests, practical-scale synthetic execution, measured evidence, workflow docs, traceability, compliance, task board, and exact commit boundary. Runtime API/UI behavior, schema, startup commands, detection logic, model logic, IAM, and response implementation are unchanged.

## T7 Functional Requirements

- Require explicit temporary-database confirmation.
- Migrate the disposable DB to Alembic head.
- Exercise real durable import jobs and parser profiles.
- Validate interruption, cancellation/resume, progress, and stale leases.
- Validate source-scoped detection, alert deduplication, cases, and explanation.
- Validate assistant context, citations, redaction, fallback, and read-only behavior.
- Validate metrics privacy and isolated backup/restore.
- Report counts, latency, throughput, checks, warnings, and safety state without private paths or evidence.

## T8 Acceptance Criteria

All requested log rows are preserved raw and normalized; source and parser accounting match; recovery is monotonic and exact; one port-scan alert is deduplicated to 20 occurrences/related logs; investigation is source-traceable; assistant fallback and citations pass without mutations; restore checksum/count/revision checks pass; configured DB remains unchanged; temp artifacts are removed; no ML/response/user side effect occurs.

## T9 API Contract

No API route or payload change. The new public interface is CLI-only: `python -m atdr.scripts.run_v48_product_acceptance` with the documented flags.

## T10 Data Model / Migration

No migration is added. The runner applies existing Alembic migrations only to a new temporary SQLite database and verifies the revision before acceptance.

## T11 Backend Plan / Changes

Compose existing source, staging, queue, worker, ingestion, detection, alert, case, explanation, assistant, metrics, dashboard, and persistence services in one sanitized fail-closed runner.

## T12 Frontend Plan / Changes

No frontend behavior change. Existing dashboard workflows are represented by their shared backend services; normal Playwright coverage remains part of release verification.

## T13 Security / Response / AI Safety

Configured DB targets are refused; private configuration is overridden with isolated safe settings; external IAM/SMTP/LLM calls are disabled; raw assistant context is disabled; provider failure is injected without network; no model or response action is allowed; no report exposes secrets, raw lines, IPs, or local paths.

## T14 Test Plan

Target refusal, option validation, migration head, exact counts, evidence preservation, source links, parser failures, duplicates, interruption/resume, cancel/resume, stale lease, source detection, dedup, case/explanation, assistant grounding/fallback, backup/restore, metrics privacy, side-effect invariants, report sanitization, practical 50k run, and full release matrix.

## T15 Implementation Summary

Added `run_v48_product_acceptance.py` and nine focused acceptance tests. The runner creates four sources and 50k synthetic rows, uses real durable jobs, detects/deduplicates a safe port scan, exercises assistant follow-ups and failure fallback, measures dashboard paths, validates backup/restore, and cleans all temporary state.

## T16 Tests Run / Evidence

Focused v4.8 tests passed `10`, including repeatability. The final 50,000-log run passed in `30.9894s` at `1,911.22` rows/second. Resume completion took `25.5329s`; source-scoped detection took `0.0360s`; backup/restore took `0.2018s`/`0.3923s`. Overview cold app-cache median/p95 were `0.0935s`/`0.1162s`; warm median/p95 were `0.0052s`/`0.0052s`. It produced exactly 50,000 raw and normalized rows, three intentional parser failures, one 20-occurrence port-scan alert/case chain, zero response actions/labels/model runs/users, a verified restore, an unchanged configured DB marker, and no retained temp artifacts. Full backend verification passed `612 passed, 1 skipped`; Alembic had no drift; replay and performance checks passed; release gate returned `ok=true` with no failed required checks. Frontend verification was not repeated because frontend behavior did not change.

## T17 PRD / Docs Updated

v4.8 canonical status, this T1-T20 record, exact cumulative allowlist, lab runbook, PRD, traceability, compliance checklist, and task board.

## T18 Risks / Blockers / Assumptions / Decisions

Evidence is synthetic and local SQLite. It cannot close approved-host PostgreSQL, real MFU provider, real-device syslog, external detection evidence, or production-response gates. Cases remain computed groups. These limits remain explicit rather than being inferred away.

## T19 Release / Rollback

No commit/push is authorized by documentation. The cumulative allowlist includes pending v4.7 and v4.8 paths because shared governance files contain both phases. Rollback is a source/docs revert; there is no schema or configured-data rollback.

## T20 Final Handoff

Run the documented 50k command, require `ok=true`, inspect `failed_checks`, retain only the sanitized terminal summary, and do not weaken temporary-target, assistant, model, or response safety controls. Move to approved-host/provider validation only when external access is available.
