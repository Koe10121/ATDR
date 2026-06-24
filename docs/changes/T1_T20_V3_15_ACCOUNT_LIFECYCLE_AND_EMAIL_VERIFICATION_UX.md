# T1 Change Title

v3.15 Account Lifecycle And Email Verification UX Hardening

# T2 Requirement

Make ATDR's local account and email verification workflow clearer, safer, and closer to school-email IAM expectations without enabling SMTP delivery, OAuth/OIDC/SSO, automatic response, real firewall blocking, ML activation, or production promotion.

# T3 Source Evidence

- Backend config: `atdr/app/core/config.py`
- Email status service: `atdr/app/services/email_service.py`
- Email verification service: `atdr/app/services/account_verification_service.py`
- Auth routes: `atdr/app/routers/auth.py`
- User admin routes: `atdr/app/routers/users.py`
- Frontend shell: `frontend/src/components/AppShell.tsx`
- User Admin page: `frontend/src/pages/UserAdmin.tsx`
- Frontend API/types: `frontend/src/lib/api.ts`, `frontend/src/types/api.ts`
- Tests: `atdr/tests/test_email_verification.py`, `frontend/tests/smoke.spec.ts`

# T4 Current Behavior

v3.14 provided disabled-by-default verification settings, hashed verification tokens, a dev outbox, and admin-triggered verification. The dashboard exposed these controls, but verification policy status and account lifecycle wording needed clearer presentation.

# T5 Impacted Areas / Agents

- Backend / API
- Frontend / Dashboard
- Security / Response Safety
- QA / UAT
- Documentation / Governance

# T6 Scope

In scope:

- Add status-only verification-required flags.
- Expose non-secret account/email policy status.
- Improve account lifecycle visibility in the React dashboard.
- Disable verification actions when verification is disabled.
- Update docs, task board, and tests.

Out of scope:

- Real SMTP email delivery.
- OIDC/SSO provider integration.
- Password reset email flow.
- Login blocking based on email verification.
- Schema changes.
- Response automation or real firewall actions.

# T7 Functional Requirements

- Local username/password login must continue to work.
- Local email login must continue to work.
- Email verification remains disabled by default.
- Verification-required flags must default to false and must not enforce blocking behavior.
- Admin UI must clearly show verification status and policy.
- Secrets must not be exposed in API responses or UI.

# T8 Acceptance Criteria

- Email status endpoint includes safe verification policy fields.
- Admin page shows concise account lifecycle and school-email policy status.
- `Send verification` is disabled when verification is disabled.
- Dev outbox remains hidden unless explicitly configured.
- Backend and frontend tests pass.
- Release gate passes.

# T9 API Contract

Existing endpoint extended:

- `GET /api/auth/email/status`

New non-secret fields:

- `verification_required_for_login`
- `verification_required_for_admin_actions`
- `school_email_domains`
- `require_school_email`
- `local_email_login_enabled`

# T10 Data Model / Migration

No database migration is required for v3.15. v3.14 tables remain:

- `account_email_verification_tokens`
- `email_notification_events`

# T11 Backend Plan / Changes

- Add status-only config fields to `Settings`.
- Include policy fields in email delivery status.
- Validate unsafe combinations where verification is required while verification is disabled.
- Keep login behavior unchanged.

# T12 Frontend Plan / Changes

- Add account email status badge to the dashboard shell.
- Improve User Admin policy cards and action availability.
- Keep page concise and avoid exposing secrets.

# T13 Security / Response / AI Safety

- No SMTP sending is enabled.
- No OIDC/SSO login is added.
- No response action can be triggered by account/email workflow.
- ML model state is not changed.
- Real firewall blocking remains disabled.

# T14 Test Plan

Backend:

- Email verification status remains safe.
- Local username and email login still work.
- Verification-required defaults do not block login.
- Analyst cannot access admin-only outbox.
- Audit behavior remains covered by v3.14 tests.

Frontend:

- Account/admin email status UI renders.
- Dev outbox hidden when disabled.
- Verification action disabled when verification is disabled.
- Secrets are not shown.

# T15 Implementation Summary

Implemented status-only verification-required flags, extended safe status payloads, added compact account verification badges, improved User Admin lifecycle cards, disabled verification actions while verification is disabled, and updated docs/tests.

# T16 Tests Run / Evidence

- `node scripts/render-tasklist-progress-html.js .` - pass
- `node scripts/check-tasklist-progress-standard.js .` - pass
- `ruff check .` - pass
- `python -m compileall -q atdr migrations` - pass
- `python -m pytest atdr/tests -q --basetemp .pytest_tmp\v315-full -p no:cacheprovider` - `290 passed, 1 skipped`
- `alembic check` - pass, no new upgrade operations detected
- `cd frontend && npm.cmd run lint` - pass
- `cd frontend && npm.cmd run build` - pass
- `cd frontend && npm.cmd run test:e2e` - `14 passed, 1 skipped`
- `python -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty` - pass, dry-run wrote no DB rows
- `python -m atdr.scripts.performance_smoke --pretty` - pass, no warnings
- `python -m atdr.scripts.verify_release` - pass, `ok: true`

# T17 PRD / Docs Updated

- `docs/V3_15_ACCOUNT_LIFECYCLE_AND_EMAIL_VERIFICATION_UX.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/security/ATDR_IAM_RBAC_MATRIX.md`
- `docs/security/ATDR_EXTERNAL_IAM_PLAN.md`
- `docs/tasks/tasklist-progress.md`

# T18 Risks / Blockers / Assumptions / Decisions

- Real SMTP requires provider details and approved secret handling.
- OIDC/SSO requires university/provider details.
- Verification-required enforcement remains future work because it can lock out existing users if enabled without a rollout plan.

# T19 Release / Rollback

Rollback is low risk: remove UI status cards and config status fields. No v3.15 migration is required.

# T20 Final Handoff

ATDR v3.15 improves account lifecycle and school-email verification UX while preserving local login, disabled-by-default notifications, simulated response, and decision-support-only ML.
