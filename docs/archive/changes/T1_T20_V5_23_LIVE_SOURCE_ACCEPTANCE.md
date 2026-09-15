# T1-T20: v5.23 Live-Source Acceptance

## T1 Change Title

v5.23 Live-Source Acceptance.

## T2 Requirement

Prove ATDR's file, API, resumable, replay/UDP, source, detection,
investigation, and audit paths together while distinguishing local transport,
second-laptop transport, and real-device evidence.

## T3 Source Evidence

Existing import/replay/syslog services, authenticated routers, durable job and
worker services, source/parser quality, rule detection, deduplication, cases,
explanations, audit history, v4.8 product acceptance, and v5.14-v5.18 scale
evidence.

## T4 Current Behavior

Each capability existed and had focused tests, but no single current harness
proved all channels together or prevented loopback evidence from being
misstated as external/device validation.

## T5 Impacted Areas/Agents

Ingestion, API, worker operations, UDP syslog, source management, parser
quality, detection, investigation, security/privacy, QA, and documentation.

## T6 Scope

Add an isolated acceptance service and CLI, injectable/race-free UDP receiver
support, safe sender classification, focused tests, local/private-input runs,
external sender instructions, status, contract, governance updates,
taskboard, and cumulative allowlist.

## T7 Functional Requirements

Exercise exact file/API imports, queue pressure, committed-chunk recovery,
actual UDP datagrams, source health, parser quality, source-scoped detection,
deduplication, case/evidence linkage, explanations, recommendations, and audit
events without touching the configured database or unsafe authority state.

## T8 Acceptance Criteria

Every local channel check passes; all temporary artifacts are removed; the
configured database marker is unchanged; no private value is returned; no
response/label/model/user write occurs; and phase completion remains false
until a non-loopback external sender is observed.

## T9 API Contract

No production API behavior changes. Existing `/api/logs/import` and
`/api/jobs/import` routes are exercised through a disposable FastAPI app. The
new CLI is `python -m atdr.scripts.run_v523_live_source_acceptance`.

## T10 Data Model / Migration

No SQLAlchemy or Alembic change. Runtime acceptance uses disposable SQLite and
ignored aggregate reports.

## T11 Backend Plan / Changes

Inject a session factory/readiness callback into the UDP receiver; expose only
safe sender aggregates; build the disposable API/runtime; test backpressure,
worker release/resume, source detection, deduplication, and privacy.

## T12 Frontend Plan / Changes

No frontend behavior change in v5.23. Dashboard investigation quality is the
separate v5.24 phase after the external transport gate closes.

## T13 Security / Response / AI Safety

No configured-DB mutation, private path, raw row, address, fingerprint,
credential, model activation/promotion, response action, automation, or real
blocking. Rules stay authoritative and ML stays shadow-only.

## T14 Test Plan

Test fail-closed temp-DB use, external attestation, private-path redaction,
report serialization, all local channels, recovery, backpressure, source and
investigation traceability, zero side effects, configured-DB preservation,
cleanup, and transport-classification honesty.

## T15 Implementation Summary

The consolidated harness and CLI are implemented. The private-input local run
processed 53 disposable rows across four logical sources and passed every
implemented check. Local loopback is explicitly not phase completion.

## T16 Tests Run / Evidence

Focused v5.23/UDP tests pass `5/5`; local preflight and complete private-input
acceptance pass. Taskboard checks, Ruff, compileall, full backend and release
tests `812 passed, 1 skipped`, Alembic no drift, React lint/build, Playwright
`27 passed, 1 skipped`, controlled detection `23/23`, layered validation
`288/288`, Assistant QA `20/20`, bounded Gemini status/probe, replay dry-run,
warning-free performance smoke, release `ok=true`, exact 55-path allowlist,
privacy, staging, and diff checks pass. A first full pytest invocation hit only
the Windows legacy path-length ceiling from an overly long temporary root; its
isolated test and the complete short-root rerun pass.

## T17 PRD / Docs Updated

v5.23 status, live-source contract, this change record, PRD, traceability,
compliance, system status, lab runbook, docs index, taskboard, and exact
cumulative allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

A second laptop or real firewall/router has not sent the measured datagrams.
The local software path is green, but the phase remains externally gated. An
operator attestation is evidence metadata, not cryptographic device identity.
The owner explicitly deferred the non-loopback sender gate on 2026-08-02. This
permits v5.24 engineering work to proceed but does not close v5.23 or change its
transport/device claims.

## T19 Release / Rollback

No commit/push is authorized. Rollback removes the v5.23 service, CLI, tests,
and docs and reverts the additive UDP dependency-injection/sender-aggregate
fields; no database rollback is required.

## T20 Final Handoff

The documented second-laptop receiver/sender commands remain the closure step.
When a non-loopback run passes, record the evidence and close v5.23. Until then,
retain `phase_complete=false`, keep real-device validation false, and carry the
owner-approved deferral as an open external gate while v5.24 proceeds.
