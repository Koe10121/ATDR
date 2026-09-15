# T1-T20: v4.5 Reproducible Product Baseline

## T1 Change Title

v4.5 Reproducible Product Baseline and Executive SOC Experience.

## T2 Requirement

Make the exact current ATDR source and pinned dependency environment reproducible from a clean Windows copy, make evidence provenance unambiguous, tighten the read-only assistant, and verify the main SOC pages across presentation and mobile viewports.

## T3 Source Evidence

`scripts/*.ps1`, `config/mfu-shell-contract.json`, `atdr/app/routers/ml.py`, `atdr/app/services/ml_evidence_snapshot_service.py`, `frontend/src/pages/`, `frontend/src/components/`, backend/frontend tests, Git status, and the separately supplied approved shell structure.

## T4 Current Behavior

Before v4.5, the current source was spread across an uncommitted v3.97-v4.4 worktree; setup could be confused by an old Node runtime or broken venv; provider readiness was mixed with installation; ML Governance could mix historical report metrics; and visual screenshots could pass while showing loading skeletons.

## T5 Impacted Areas / Agents

Release/operations, backend/API, frontend/dashboard, AI/ML governance, assistant safety, QA/UAT, documentation, and security/IAM boundary review.

## T6 Scope

Repository/process hardening, Windows setup lifecycle, external-shell contract, canonical read-only ML evidence, UI hierarchy, assistant answer bounds, safe synthetic preparation, and verification. Detection thresholds, active models, response policy, and the configured database are out of scope.

## T7 Functional Requirements

- One setup command and one start command.
- Node `20.19+`, working pip, path-with-spaces support, and non-destructive venv recovery.
- Separate installation and provider readiness.
- Strict one-source ML evidence snapshot.
- Distinct anomaly, active supervised, and candidate states.
- Concise mutation-free assistant answers.
- Idempotent dry-run-first synthetic demo preparation.

## T8 Acceptance Criteria

Clean-room setup reaches Alembic head without private inputs; provider failure is concise and fail-closed; no metric fallback occurs; core pages render without page overflow at three viewport classes; assistant limits and safety controls hold; full verification passes.

## T9 API Contract

Adds authenticated `GET /api/ml/evidence-snapshot`. The response contains only non-secret provenance, metric ranges, operational state, safety state, and limitations. Missing canonical evidence returns `available: false`.

## T10 Data Model / Migration

No v4.5 schema change. The already-added additive raw-log fingerprint migration remains part of the v3.97 source boundary and is at head in the configured database.

## T11 Backend Plan / Changes

Add strict snapshot service/router, safe demo wrapper, idempotent scenario behavior, answer-length enforcement, and setup lifecycle tests.

## T12 Frontend Plan / Changes

Add one canonical evidence source to Overview and AI Governance, separate operational model states, a reusable current ML operating-policy panel, reusable bounded assistant answer/citation rendering, reusable `SocPageHeader` composition across the five primary SOC pages, MFU root overflow policy, and rendered-content multi-viewport tests.

## T13 Security / Response / AI Safety

No secrets returned, no raw assistant logs, no model activation, no automatic response, no real blocking, no provider bypass, no fake metrics, and no generated report committed.

## T14 Test Plan

Targeted backend tests, full backend suite, Alembic check, lint/build, Playwright, replay dry-run, safe-demo dry-run, performance smoke, release gate, hygiene audit, and disposable clean-room setup.

## T15 Implementation Summary

Implemented a pinned Python dependency lock, versioned shell contract, resilient setup checks, canonical ML evidence API/UI, removed live historical ML metric fallback chains from Overview and AI Governance, separated latest registered-run diagnostics, added a current-policy component, shared summary-first SOC page header, bounded assistant rendering, safe scenario preparation, and real rendered-page viewport tests.

## T16 Tests Run / Evidence

Targeted backend tests passed (`32 passed`). A disposable setup with no existing environment, dependencies, database, or private configuration reached Alembic head in approximately 699 seconds, and its focused pinned-environment suite passed `75 passed`. Final verification passed Ruff, compileall, PowerShell parsing, task-board checks, backend `589 passed, 1 skipped`, Alembic no drift, React lint/build, Playwright `25 passed, 1 skipped`, replay dry-run, safe-demo dry-run, warm performance smoke with no warnings, and release gate `ok: true`. GitHub Actions CI #55 passed all three jobs at public commit `1535a31`; its Linux backend recorded `589 passed, 1 skipped`. A separate clean public clone compiled and passed `63` focused baseline/auth/assistant tests with zero forbidden tracked artifacts or personal-machine paths. A separate cold-disk Overview run of `9.12s` remains documented as a large-SQLite risk.

## T17 PRD / Docs Updated

This record, v4.5 baseline/current-state/hygiene/allowlist docs, current-state lock, productization roadmap, task board, README, and teammate startup docs.

## T18 Risks / Blockers / Assumptions / Decisions

MFU OAuth client and account acceptance remain external blockers. The separately supplied shell has no published companion version/checksum. The active supervised artifact metadata is unknown. Diagnostic ML calibration/generalization remains insufficient for promotion. The legacy shell dependency tree reports deprecated packages.

## T19 Release / Rollback

The exact approved source allowlist was committed as `dd6ff01`. CI-only corrections `a407ca0` and `1535a31` changed only `.github/workflows/ci.yml`; all pushes were normal and no history was rewritten. Rollback is a normal source revert. Setup preserves existing `.env` backups and SQLite backups; v4.5 does not reset data.

## T20 Final Handoff

The v4.5 repository scope is complete and published at green public commit `1535a31`. A fresh clone receives the intended ATDR source and passes the focused distribution checks. Provider acceptance, versioned MFU-shell distribution, authorized real-source evidence, and approved-host validation remain external follow-up gates; production readiness is not claimed.
