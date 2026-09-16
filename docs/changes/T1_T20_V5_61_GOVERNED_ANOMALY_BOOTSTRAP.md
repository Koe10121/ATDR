# T1-T20: v5.61 Governed Advisory IsolationForest Bootstrap

## T1 Change Title

- Title: Governed Advisory IsolationForest Bootstrap and Capability Closure
- Date: 2026-09-16
- Owner / acting agent: Codex under project-owner direction
- Related version or sprint: v5.61

## T2 Requirement

Make the unsupervised anomaly capability reproducible on a clean clone without
silent training, committed artifacts, authoritative ML behavior, or private
evidence disclosure.

## T3 Source Evidence

| Source | Evidence |
| --- | --- |
| Published baseline | v5.60 commit `da7c2434962eec10c0fd7c6bbd9266c5dbebf2c6` |
| Anomaly implementation | `atdr/app/detection/ml_detector.py`, ML service/router/schema |
| Runtime authority | detection service and v5.58 runtime contract |
| Lifecycle | setup/start/check scripts and v5.60 clean-machine harness |
| UI | React AI Governance page and Playwright suite |
| Evidence | eight committed benign controlled scenario files |

## T4 Current Behavior

A clean clone safely runs deterministic rules without an anomaly artifact.
The old manual training command can write the configured model, but there was
no dedicated confirmation-gated, provenance-bearing clean-clone bootstrap.
The dashboard showed generic `Ready` or `Missing` wording.

## T5 Impacted Areas / Agents

| Area | Impact |
| --- | --- |
| Backend | new bootstrap service, CLI, status metadata, and health wording |
| Frontend | explicit advisory capability state and corrective command |
| Lifecycle | startup message only; normal command and behavior unchanged |
| Clean machine | optional five-stage extension; default stages unchanged |
| Database | disposable SQLite only during bootstrap acceptance |
| Artifacts | ignored model plus ignored sanitized manifest |
| Detection/response | authority and simulation invariants unchanged |

## T6 Scope

In scope: preflight, evidence gates, explicit confirmation, disposable
training, deterministic provenance, atomic install/rollback, advisory contract,
status wording, clean-machine extension, tests, and active documentation.

Out of scope: supervised activation, threat-accuracy claims, threshold tuning,
real-world anomaly qualification, automatic response, and firewall blocking.

## T7 Functional Requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-561-01 | Preflight without writes | Must |
| FR-561-02 | Exact execution confirmation | Must |
| FR-561-03 | Validate schema, parser, support, and duplicates | Must |
| FR-561-04 | Train only in disposable storage | Must |
| FR-561-05 | Install only ignored configured outputs | Must |
| FR-561-06 | Keep anomaly and hybrid advisory | Must |
| FR-561-07 | Prove no silent setup/start training | Must |
| FR-561-08 | Report exact safe operator recovery | Must |

## T8 Acceptance Criteria

Committed synthetic preflight passes with at least 20 eligible rows; execution
requires the exact confirmation; status transitions from unavailable to
governed advisory-ready; outputs contain no private source details; and zero
alerts, suppressions, labels, model runs, detection runs, or response actions
are created by disposable advisory acceptance.

## T9 API Contract

Authenticated anomaly status and the public health check gain additive safe
fields: capability state/label, bootstrap requirement/command, manifest
validity, decision-support role, and false threat-accuracy claim.

## T10 Data Model / Migration

No schema or migration change. Bootstrap uses `Base.metadata` only inside a
new temporary SQLite database and deletes that database after acceptance.

## T11 Backend Plan / Changes

Add evidence inspection, destination validation, deterministic manifest,
temporary training/scoring, advisory authority verification, atomic artifact
installation, safe errors, CLI, and v5.60 optional acceptance stages.

## T12 Frontend Plan / Changes

Replace generic model presence wording with the exact advisory capability
label, a threat-accuracy caveat, rules-authoritative badge, and preflight
command when bootstrap is required.

## T13 Security / Response / AI Safety

- Never emit evidence paths, raw logs, IPs, fingerprints, or secrets.
- Never access or modify the authoritative database during bootstrap.
- Never train from setup or startup.
- Never activate supervised ML.
- Never let anomaly or hybrid evidence create/suppress alerts.
- Keep response `simulation_only` and blocking disabled.

## T14 Test Plan

Cover deterministic preflight, support/parser/schema/duplicate gates, exact
confirmation, protected replacement, ignored-path enforcement, deterministic
manifest, disposable cleanup, no authoritative writes, status wording, startup
non-execution, optional clean-machine stages, API fields, and UI overflow.

## T15 Implementation Summary

The new operator path defaults to preflight, trains only after exact
confirmation, validates evidence twice, uses disposable SQLite, and atomically
installs only ignored outputs. Runtime and UI distinguish availability from
accuracy and authority.

## T16 Tests Run / Evidence

The complete local matrix passed: taskboard checks, repository/security
audits, Ruff, compileall, 1,102 backend tests with one skipped, Alembic check,
frontend lint/build, 43 Playwright tests with one skipped, controlled scenario,
288/288 layered validation, 30-case Assistant QA plus contextual sequence,
27/27 published clean-machine stages, isolated explicit anomaly bootstrap,
replay dry-run, performance smoke, deployment checks, and release gate. The
new opt-in 32-stage remote-clone rerun remains post-publication because
`origin/main` correctly excludes unapproved v5.61 files.

## T17 PRD / Docs Updated

Current state, AI/ML status, PRD, traceability, compliance, quickstart,
operations/AI runbooks, documentation index, taskboard, v5.61 status, and this
record.

## T18 Risks / Blockers / Assumptions / Decisions

The authoritative workspace already contains an older ignored anomaly
artifact without a v5.61 manifest. It is not replaced automatically. Clean
clone optional acceptance can execute against the genuine remote only after
publication; local disposable acceptance covers the implementation before
publication.

## T19 Release / Rollback

Normal setup/start commands do not change. Remove the ignored artifact and
manifest to return to unavailable advisory state. Replacement is atomic and
restores existing files if installation fails. No data rollback is needed.

## T20 Final Handoff

v5.61 closes the remaining Codex-owned clean-clone anomaly capability gap while
preserving rules as alert authority. Publication requires a separate exact
allowlist approval. Remaining acceptance tracks require external owners.
