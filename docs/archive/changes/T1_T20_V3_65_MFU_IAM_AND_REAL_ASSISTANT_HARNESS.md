# T1-T20: v3.65 MFU IAM And Real Assistant Harness

## T1 Change Title

v3.65 MFU school-email token-login harness and real LLM assistant provider probe.

## T2 Requirement

Use the supervisor MFU IAM template evidence to add an ATDR-specific, disabled-by-default school-email IAM token path and a safe real LLM provider test harness without migrating ATDR to Node/Vue/MongoDB or enabling unsafe automation.

## T3 Source Evidence

- Supervisor template env and IAM files under `<MFU_SHELL_ROOT>`
- `backend-node/server/integrations/iam/iam-sdk-adapter.js`
- `backend-node/server/integrations/iam/b2b-auth-middleware.js`
- `frontend-vue/src/projects/components/dialog/SignIn.vue`
- `frontend-vue/src/projects/components/dialog/TwoFA.vue`
- `atdr/app/core/config.py`
- `atdr/app/routers/auth.py`
- `atdr/app/services/mfu_iam_service.py`
- `atdr/app/services/assistant_llm.py`
- `frontend/src/pages/LoginPage.tsx`
- `frontend/src/pages/UserAdmin.tsx`

## T4 Current Behavior

Before this change, ATDR displayed non-secret MFU IAM readiness status but did not provide a login handoff endpoint. The assistant had real LLM provider adapters but no standalone provider probe command.

## T5 Impacted Areas / Agents

- Backend / API
- Security / IAM
- Frontend / Dashboard
- SOC Assistant
- QA
- Documentation / Governance

## T6 Scope

In scope:

- Public non-secret MFU IAM readiness for login page.
- MFU IAM token-login endpoint behind `MFU_IAM_ENABLED=true`.
- Tests-only mock token provider behind `MFU_IAM_MOCK_ENABLED=true`.
- Local user creation/update from verified school-email identity.
- Explicit admin email allowlist.
- Audit events.
- Frontend login/Admin visibility.
- Assistant LLM provider probe script.

Out of scope:

- Full Google/MFU OAuth redirect/callback UI.
- Real SMTP/OTP enforcement.
- External IAM group synchronization.
- Stack migration.
- Response automation or firewall blocking.

## T7 Functional Requirements

- Local login must continue to work.
- External token login must be disabled unless configured.
- Allowed school domains must be enforced.
- New external users must default to analyst unless explicitly mapped to admin.
- Status endpoints must hide secrets.
- Assistant provider probe must not expose API keys or raw logs.

## T8 Acceptance Criteria

- `GET /api/auth/mfu-iam/public-status` works without auth and returns safe readiness only.
- `POST /api/auth/mfu-iam/token-login` rejects when disabled or domain is not allowed.
- Mock token `mock:user@allowed-domain` works only when `MFU_IAM_MOCK_ENABLED=true`.
- Login page keeps local login visible and shows school login only when ready.
- Admin page shows token-login readiness and explicit admin mapping state.
- LLM provider probe is status-only unless `--execute` is passed.

## T9 API Contract

- `GET /api/auth/mfu-iam/public-status`
- `POST /api/auth/mfu-iam/token-login`
- Existing `GET /api/auth/mfu-iam/status` remains authenticated and non-secret.

## T10 Data Model / Migration

No migration required. Existing `users.email`, `users.email_verified`, `users.auth_provider`, and `users.external_subject` fields are used.

## T11 Backend Plan / Changes

- Extended `Settings` with `MFU_IAM_MOCK_ENABLED` and `MFU_IAM_ADMIN_EMAILS`.
- Added token validation, mock identity, domain validation, user upsert, and audit helpers.
- Added token-login/public-status routes.
- Added assistant LLM provider probe script.

## T12 Frontend Plan / Changes

- Added school-email login readiness panel to `LoginPage`.
- Added token handoff form only when backend status says ready.
- Added Admin MFU IAM readiness fields for token login, mock/test harness, and admin mapping.

## T13 Security / Response / AI Safety

- No secrets returned.
- No `.env` values copied into docs.
- No automatic response.
- No real firewall blocking.
- No ML activation or promotion.
- Assistant remains read-only.
- External LLM calls remain disabled by default.

## T14 Test Plan

- MFU public status safe without auth.
- MFU mock token login creates external analyst.
- Explicit admin mapping is required for external admin.
- Denied domain returns generic failure and is audited.
- Local login remains unchanged.
- Assistant provider probe hides secrets and can execute mock provider without raw logs.

## T15 Implementation Summary

Implemented the disabled-by-default MFU token-login harness, login/Admin UI status, explicit role mapping, audit behavior, and a safe real LLM provider probe command.

## T16 Tests Run / Evidence

- `python -m compileall -q atdr\app\core\config.py atdr\app\routers\auth.py atdr\app\services\mfu_iam_service.py atdr\app\schemas\auth.py atdr\scripts\test_assistant_llm_provider.py`
- `python -m pytest atdr\tests\test_api.py -q -k "mfu_iam or oidc_status or local_login"`: passed
- `python -m pytest atdr\tests\test_assistant.py -q -k "llm_provider_probe or mock_llm_adapter or status_is_disabled"`: passed

## T17 PRD / Docs Updated

- `docs/V3_65_MFU_IAM_AND_REAL_ASSISTANT_HARNESS.md`
- `docs/security/ATDR_MFU_IAM_IMPLEMENTATION_PLAN.md`
- `docs/security/ATDR_REAL_LLM_ASSISTANT_PLAN.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/tasks/tasklist-progress.md`

## T18 Risks / Blockers / Assumptions / Decisions

- Real MFU IAM token behavior still depends on provider availability and contract.
- Mock mode is for tests/local harness only.
- Admin mapping uses explicit email allowlist until IAM groups are confirmed.
- Real LLM use requires API key handling and data-sharing approval.

## T19 Release / Rollback

Rollback is code-only: remove v3.65 auth route/service additions and frontend login panel. No schema rollback is needed.

## T20 Final Handoff

ATDR now has a safe, disabled-by-default path to test school-email token login and real assistant provider readiness. It remains FastAPI + React + SQLAlchemy/Alembic, local login is preserved, and no automation or production claim was introduced.
