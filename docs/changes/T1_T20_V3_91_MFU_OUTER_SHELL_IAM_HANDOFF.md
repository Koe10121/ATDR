# T1-T20: v3.91 MFU Outer-Shell Secure Handoff

## T1 Change Title

MFU outer-shell secure one-time-code handoff.

## T2 Requirement

Use the official MFU template as the school identity entry shell and open ATDR only after a secure, non-URL credential handoff.

## T3 Source Evidence

`atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py`, `atdr/app/core/security.py`, `frontend/src/pages/LoginPage.tsx`, and official template IAM/login sources under `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response`.

## T4 Current Behavior

The old browser token path was retired. The outer shell creates an opaque, short-lived, single-use code; ATDR exchanges it server-to-server and sets an HttpOnly ATDR session cookie.

## T5 Impacted Areas/Agents

Security/IAM, backend/API, frontend, template shell, QA, documentation, and release operations.

## T6 Scope

Secure authentication handoff only. No detection, ML, response, database schema, or startup-command behavior changes.

## T7 Functional Requirements

- Preserve local ATDR login.
- Require exact allowed origin and approved return path.
- Store only a code hash in the template.
- Consume each code once with a short expiry.
- Map default external users to analyst; map admin only by approved group.
- Never expose a school token, bridge secret, password, or OTP to the browser URL or Git.

## T8 Acceptance Criteria

- Template handoff succeeds only with configured trusted services.
- ATDR creates an HttpOnly cookie session and redirects to an allowed React route.
- Replayed/untrusted codes fail safely.
- Local account privilege cannot be inherited solely from matching email.
- No response action, detection run, label update, or model activation occurs.

## T9 API Contract

Template: `POST /api/v1/atdr/handoff/start` and `POST /api/v1/atdr/handoff/exchange`.

ATDR: form `POST /api/auth/mfu-iam/handoff/consume` and authenticated `GET /api/auth/me`.

The retired direct external token-login route is not part of the v3.91 contract.

## T10 Data Model / Migration

The external template stores a hashed one-time-code record with expiry and consumed timestamp. ATDR schema changes are not required.

## T11 Backend Plan / Changes

Added secure status/config validation, server-side code exchange, origin/path validation, external-user linking safeguards, HttpOnly cookie authentication, and audit events.

## T12 Frontend Plan / Changes

The ATDR login page blocks legacy token-like URL parameters, shows shell handoff status, and does not store school credentials. User Admin shows secure handoff and IAM group mapping status.

## T13 Security / Response / AI Safety

No secrets are returned. Raw logs, model operations, response actions, firewall enforcement, and automation are outside the handoff scope and remain disabled or unchanged.

## T14 Test Plan

Focused ATDR handoff, bridge-contract, runtime-helper, configuration-helper, and API tests passed (`41 passed`). Full verification passed: Ruff, compileall, backend `492 passed, 1 skipped`, Alembic no drift, React lint/build/Playwright `19 passed, 1 skipped`, template Node contract tests `12 passed`, template Vue lint/preproduction build, replay dry-run, performance smoke without warnings, and release gate `ok: true`.

## T15 Implementation Summary

Implemented a server-mediated opaque-code bridge and removed the browser token-login route/API client path.

## T16 Tests Run / Evidence

Focused ATDR handoff and compatibility tests passed (`41 passed`). Full verification passed: Ruff, compileall, backend `492 passed, 1 skipped`, Alembic no drift, React lint/build/Playwright `19 passed, 1 skipped`, template Node contract tests `12 passed`, template Vue lint/preproduction build, replay dry-run, performance smoke without warnings, and release gate `ok: true`. The non-mutating provider/runtime probe deliberately reported the secure handoff incomplete because private bridge/origin/provider configuration is not set; it exposed no secret and made no provider call.

## T17 PRD / Docs Updated

`docs/V3_91_MFU_OUTER_SHELL_SECURE_HANDOFF.md`, `docs/security/ATDR_MFU_IAM_PREPROD_VALIDATION.md`, PRD, traceability, compliance checklist, tasklist, quickstart/runbook, and README.

## T18 Risks / Blockers / Assumptions / Decisions

Actual MFU provider values, template 2FA/session behavior, approved group identifiers, HTTPS routing, deprovisioning, and preproduction proof remain external validation work. The external template remains a separate Node/Vue/Mongo application shell; ATDR remains FastAPI/React/SQLAlchemy.

## T19 Release / Rollback

Disable the handoff flags in both private configurations and restart services. Local ATDR login remains. No database rollback is needed.

## T20 Final Handoff

Use the preproduction validation checklist before enabling school-email handoff outside local testing. Do not treat this implementation as production approval.
