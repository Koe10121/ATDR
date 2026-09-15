# T1-T20: v5.38 Product Reliability And Failure-Mode Lock

## T1 Change Title

v5.38 End-to-End Product Reliability and Failure-Mode Lock.

## T2 Requirement

Prove the supported ATDR analyst workflow and critical failure behavior in
disposable storage, repair only reproduced defects, preserve the configured
database, and leave detection, ML, Assistant, IAM, and response authority
unchanged.

## T3 Source Evidence

Current launcher/config scripts; FastAPI health, auth, Assistant, evidence
review, response, ingestion, detection, case, and audit services; React routes
and query error behavior; v4.8 disposable product acceptance; focused backend
and Playwright contracts; release gate; current runbooks and governance docs.

## T4 Current Behavior

The existing product workflow was broadly covered, but there was no single
v5.38 reliability summary. Startup could mistake a reused PID for a tracked
ATDR process. Overview, AI Governance, and Response & Audit did not show a
single page-level primary-query error. Viewport coverage omitted two critical
routes.

## T5 Impacted Areas / Agents

Release/Ops, startup lifecycle, backend acceptance tooling, frontend error
states, responsive QA, security/response safety, documentation, and
governance.

## T6 Scope

One disposable acceptance service/CLI, process-identity hardening, concise UI
error states, expanded viewport tests, focused backend tests, status/change
records, runbooks, traceability, compliance, taskboard, and exact allowlist.

Detection logic, parser logic, model training/activation, database schema,
external IAM, real response, and feature expansion are out of scope.

## T7 Functional Requirements

- Refuse configured-database execution and require `--use-temp-db`.
- Exercise the primary synthetic ingest-to-investigation workflow.
- Verify deduplication, cases, Why Flagged, Assistant context/citation/fallback,
  simulated response, audit, recovery, and cleanup.
- Cover bounded startup, access, UI, review-integrity, and failure contracts.
- Return concise gates without raw evidence, paths, IPs, or secrets.
- Perform no label, model, authoritative alert, or real response mutation.

## T8 Acceptance Criteria

All 11 v5.38 gates pass; configured database state is unchanged; temporary
artifacts are removed; failures are concise and safe; all core pages render
without incoherent horizontal overflow at projector, laptop, and mobile
sizes; real response/model activation counts remain zero.

## T9 API Contract

No route or response schema was added or changed. Existing APIs remain the
source of product behavior. The new interface is the local CLI module
`atdr.scripts.run_v538_product_reliability_acceptance`.

## T10 Data Model / Migration

No model or Alembic migration change. Acceptance uses isolated in-memory and
temporary SQLite databases only.

## T11 Backend Plan / Changes

Compose the v4.8 acceptance workflow, add bounded source-contract checks and
isolated failure probes, build an 11-gate redacted report, fail closed without
the disposable flag, and test preservation and authority invariants.

## T12 Frontend Plan / Changes

Give `ErrorBanner` alert semantics, add concise page-level failure states to
Overview, AI Governance, and Response & Audit, and include Response & Audit
and User Admin in multi-viewport overflow coverage.

## T13 Security / Response / AI Safety

No secrets, provider payloads, private paths, raw logs, IPs, or hidden review
data are returned. The Assistant uses deterministic mode during acceptance
and remains read-only. Response is denied without justification or for a
protected target; approved actions remain simulation records only. Rules stay
authoritative and supervised lifecycle remains `shadow_observation`.

## T14 Test Plan

Test disposable enforcement, source preflight, full gates, count and
explanation consistency, failure probes, simulated response/audit, report
redaction, stale-PID identity, critical frontend errors, and responsive core
routes. Then run the complete repository verification matrix.

## T15 Implementation Summary

Added the v5.38 service, CLI, and eight backend tests; hardened launcher
process identity; added three page-level query errors; improved alert
semantics; and expanded responsive coverage. No runtime authority or schema
was added.

## T16 Tests Run / Evidence

The canonical v5.38 run passes `11/11` gates. Focused backend checks pass
`19/19`; the broader targeted reliability set passes `29/29`. Ruff and source
compileall pass; backend and release each pass `918` tests with one intentional
skip; Alembic has no drift; React lint/build pass; Playwright passes `34` with
one live-source skip; controlled source acceptance passes; layered detection
passes `288/288`; Assistant QA passes `20/20`; replay stays dry-run;
performance has no warnings; and release returns `ok: true`.

## T17 PRD / Docs Updated

v5.38 status, this T1-T20 record, Quickstart, Lab Runbook, PRD, requirement
traceability, university compliance checklist, taskboard/HTML, and exact
commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Some startup checks are source-backed plus focused PowerShell tests rather
than a new physical clean-machine exercise. The product run is controlled
synthetic SQLite evidence. Genuine human review, second-device evidence,
institutional provider approval, and approved-host operations remain external
and must not be inferred from local passing gates.

## T19 Release / Rollback

No commit or push is authorized here. Release requires separate approval of
the exact allowlist. Rollback removes the new service/CLI/tests and reverts the
launcher/UI/test/doc changes. No data or model rollback exists.

## T20 Final Handoff

Run the canonical v5.38 command in disposable mode, review the concise gate
summary, and use normal shell startup for manual checks. Do not activate a
model, enable automation, or treat local acceptance as production readiness.
