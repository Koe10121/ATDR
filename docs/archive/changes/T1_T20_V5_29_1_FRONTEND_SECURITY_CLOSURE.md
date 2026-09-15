# T1-T20: v5.29.1 Frontend Dependency Security Closure

## T1 Change Title

v5.29.1 Frontend Dependency Security Closure.

## T2 Requirement

Remove the remaining React Router security advisories while preserving every
ATDR dashboard route, authentication/authorization boundary, MFU shell
handoff, deep link, Assistant session, and visible workflow.

## T3 Source Evidence

Source truth is `frontend/package.json`, `frontend/package-lock.json`,
`frontend/src/main.tsx`, `frontend/src/App.tsx`, `ProtectedRoute.tsx`,
`AdminRoute.tsx`, `LoginPage.tsx`, `AppShell.tsx`, Assistant session code,
Playwright tests, `.github/workflows/ci.yml`, npm audit output, and official
React Router package compatibility metadata.

## T4 Current Behavior

The original lock resolved React Router DOM/Router `6.30.4` and npm reported
two moderate advisory families. A transitional `7.18.0` install exposed a
newer high advisory fixed by `7.18.2`. Protected redirects also retained only
the pathname and could drop an alert/log query after login.

## T5 Impacted Areas/Agents

Frontend/dashboard, authentication navigation, MFU handoff continuity,
Assistant session continuity, security, QA/UAT, documentation, and release
operations.

## T6 Scope

In scope: dependency/lock update, safe internal redirect validation, complete
return-location preservation, route/history regression tests, security audit,
and governance evidence.

Out of scope: backend APIs, database schema/data, detection/ML logic, IAM
provider behavior, UI redesign, model activation, response automation, or real
blocking.

## T7 Functional Requirements

- Resolve all npm advisories at moderate or higher.
- Preserve all declarative routes and role guards.
- Preserve safe path/query/hash state through login.
- Reject external, backslash, scheme, colon, and control-character redirects.
- Preserve MFU handoff behavior and Assistant navigation state.
- Keep unknown routes and non-admin access fail-closed.

## T8 Acceptance Criteria

`npm audit --audit-level=moderate` returns zero findings; clean install,
lint/build, and all browser tests pass; protected deep links survive login;
malicious redirect state remains on the ATDR origin; browser history preserves
Assistant state; backend/release gates remain green; and no safety authority
changes.

## T9 API Contract

No API contract changed.

## T10 Data Model / Migration

No database model or migration changed. Alembic reports no drift.

## T11 Backend Plan / Changes

No backend source change was required. The full backend and release matrices
are retained as non-regression evidence.

## T12 Frontend Plan / Changes

Pin `react-router-dom@7.18.2`, regenerate the npm lock, preserve complete safe
return state in `ProtectedRoute`, harden `LoginPage` redirect validation, and
add focused Playwright route/security/history tests.

## T13 Security / Response / AI Safety

The dependency advisories are closed without granting new navigation, IAM,
Assistant, ML, or response authority. Raw logs, secrets, private paths, API
keys, database files, generated evidence, and model artifacts remain excluded.

## T14 Test Plan

Run clean install, moderate audit, lint, build, complete Playwright, Ruff,
compileall, full backend tests, Alembic check, release gate, taskboard checks,
diff validation, and repository hygiene checks.

## T15 Implementation Summary

Upgraded React Router DOM/Router from `6.30.4` to exact `7.18.2`, removed all
reported npm vulnerabilities, preserved query/hash login return state,
strengthened redirect validation, and added four browser regressions.

## T16 Tests Run / Evidence

Measured evidence: `npm ci` passed; npm audit reports `0` vulnerabilities;
React lint/build passed; Playwright `31 passed, 1 skipped`; Ruff and compileall
passed; backend `852 passed, 1 skipped`; Alembic no drift; and the official
release gate returned `ok: true` with no failed required checks. The Playwright
skip remains the external live-source gate.

## T17 PRD / Docs Updated

v5.29.1 status, this T1-T20 record, docs index, canonical taskboard/rendered
HTML, and an exact approval-gated commit allowlist.

## T18 Risks / Blockers / Assumptions / Decisions

Third-party advisory data can change, so moderate-level auditing remains a
continuous CI/release responsibility. No current route migration blocker is
present. External live-source, human supervised evidence, and provider-host
governance gates are unrelated and remain open.

## T19 Release / Rollback

No staging, commit, or push is authorized. Rollback restores the prior package
manifest/lock and two navigation files; no data rollback is required. Rolling
back would reintroduce known dependency vulnerabilities and is not recommended.

## T20 Final Handoff

Keep React Router pinned to a non-vulnerable supported version, retain the new
route regressions, run moderate-level npm audit in future closure work, and
continue with v5.30 independent supervised evidence rather than changing ML
authority.
