# T1-T20: v3.14 Email Verification And Account Notification Foundation

## T1 Change Title

v3.14 Email Verification And Account Notification Foundation

## T2 Requirement

Add safe local-account email verification and notification groundwork so ATDR can later support university/school email workflows without adding OIDC/SSO, SMTP production email, automatic response, real firewall blocking, ML promotion, or startup command changes.

## T3 Source Evidence

| Area | Evidence |
| --- | --- |
| Config | `atdr/app/core/config.py`, `.env.example`, `.env.lab.example` |
| Auth/RBAC | `atdr/app/core/security.py`, `atdr/app/routers/auth.py`, `atdr/app/routers/users.py` |
| User model | `atdr/app/db/models.py`, `atdr/app/services/user_service.py` |
| Frontend admin | `frontend/src/pages/UserAdmin.tsx`, `frontend/src/lib/api.ts`, `frontend/src/hooks/useApiQueries.ts`, `frontend/src/types/api.ts` |
| Existing IAM docs | `docs/security/ATDR_EXTERNAL_IAM_PLAN.md`, `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| Test patterns | `atdr/tests/test_api.py`, `frontend/tests/smoke.spec.ts` |

## T4 Current Behavior

ATDR supports local JWT login, admin/analyst roles, user email fields, optional local email login, and disabled-by-default OIDC config/status groundwork. It does not send email or verify email through codes.

## T5 Impacted Areas / Agents

- Data Model / Database
- Backend / API
- Frontend / Dashboard
- Security / Response Safety
- QA/UAT
- Docs / Release-Ops

## T6 Scope

In scope:

- disabled-by-default config placeholders
- additive verification token and notification event tables
- hashed code creation and verification
- admin-only local dev outbox endpoint
- Admin dashboard status and Send verification action
- tests and documentation

Out of scope:

- OAuth/OIDC/SSO callback login
- real SMTP delivery
- password reset email
- login blocking based on email verification
- production IAM
- response automation or real firewall blocking

## T7 Functional Requirements

| ID | Requirement | Status |
| --- | --- | --- |
| FR-V314-001 | Email verification disabled by default | Implemented |
| FR-V314-002 | Status endpoint exposes no secrets | Implemented |
| FR-V314-003 | Admin can trigger verification for a user | Implemented |
| FR-V314-004 | User can verify own email with valid code | Implemented |
| FR-V314-005 | Invalid/expired codes fail cleanly and audit | Implemented |
| FR-V314-006 | Dev outbox is admin-only | Implemented |
| FR-V314-007 | Local username/email login remains unchanged | Implemented |

## T8 Acceptance Criteria

- Default `.env.example` does not send email.
- SMTP secrets are never returned by API.
- Admin User page shows notification/verification status.
- Verification code tokens are hashed in DB.
- Plaintext code appears only in explicit dev outbox mode.
- Analyst cannot view dev outbox.
- Response automation remains disabled.

## T9 API Contract

| Route | Method | Auth | Purpose |
| --- | --- | --- | --- |
| `/api/auth/email/status` | GET | analyst/admin | Non-secret email verification status |
| `/api/auth/email/request-verification` | POST | current user | Request verification for own email |
| `/api/auth/email/verify` | POST | current user | Verify own email code |
| `/api/users/{id}/send-verification` | POST | admin | Trigger verification for managed user |
| `/api/users/dev-email-outbox` | GET | admin | View local dev outbox events |

## T10 Data Model / Migration

Migration: `migrations/versions/c8d9e0f1a2b3_add_account_email_verification.py`

New tables:

- `account_email_verification_tokens`
- `email_notification_events`

The migration is additive and does not reset, delete, or rewrite existing users/logs/labels/alerts.

## T11 Backend Plan / Changes

- Add email settings and validation.
- Add Pydantic response/request schemas.
- Add `email_service.py` for status and safe notification event recording.
- Add `account_verification_service.py` for code generation, hashing, token creation, verification, and audit.
- Add auth/user endpoints.
- Reset `email_verified=false` when a user's email changes.

## T12 Frontend Plan / Changes

- Add email status/outbox API types and hooks.
- Add Account Notifications panel in User Admin.
- Add Send verification button for email-bearing users.
- Add collapsed dev outbox panel when `dev_outbox` is configured.

## T13 Security / Response / AI Safety

- No SMTP secrets exposed.
- No real email sent by default.
- Dev outbox is admin-only.
- Verification does not grant admin privileges.
- Login is not blocked by email verification in v3.14.
- No model activation, no automatic response, no real firewall blocking.

## T14 Test Plan

- Backend email status/defaults/secrets tests.
- Admin trigger and dev outbox RBAC tests.
- Valid/invalid/expired code tests.
- Local login regression tests.
- Frontend Admin panel rendering and no-secret tests.

## T15 Implementation Summary

v3.14 adds disabled-by-default local-account email verification groundwork with hashed tokens, admin-only dev outbox, safe status API, User Admin visibility, and audit events.

## T16 Tests Run / Evidence

Initial targeted checks:

- `ruff check atdr/app/core/config.py atdr/app/db/models.py atdr/app/routers/auth.py atdr/app/routers/users.py atdr/app/services/email_service.py atdr/app/services/account_verification_service.py atdr/tests/test_email_verification.py`
- `python -m compileall -q ...`
- `python -m pytest atdr/tests/test_email_verification.py -q`
- `cd frontend && npm.cmd run lint -- --quiet`

Full verification evidence should be recorded in `docs/tasks/tasklist-progress.md` after the full gate runs.

## T17 PRD / Docs Updated

- `docs/V3_14_EMAIL_VERIFICATION_AND_ACCOUNT_NOTIFICATIONS.md`
- `docs/security/ATDR_EXTERNAL_IAM_PLAN.md`
- `docs/security/ATDR_IAM_RBAC_MATRIX.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/prd/PRD-ATDR.md`
- `docs/tasks/tasklist-progress.md`

## T18 Risks / Blockers / Assumptions / Decisions

- Real SMTP is intentionally not implemented.
- Full school OIDC requires provider details and a separate reviewed phase.
- Dev outbox can expose local verification codes to admins and is only for development.
- Email verification does not imply production IAM readiness.

## T19 Release / Rollback

Rollback:

- Revert code/docs/UI changes.
- Downgrade Alembic revision `c8d9e0f1a2b3` if the new tables must be removed.

No existing operational data is deleted by the upgrade migration.

## T20 Final Handoff

ATDR now has email verification and account notification groundwork suitable for local lab testing. It remains FastAPI + React + SQLAlchemy/Alembic, local login remains active, SMTP and OIDC are disabled/future, response remains simulated, and ML remains decision support only.
