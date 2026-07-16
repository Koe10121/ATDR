# T1-T20 Change Document: v3.64 MFU IAM Template Adapter

## T1 Change Title

v3.64 MFU IAM Template Adapter

## T2 Requirement

Adapt the supervisor NewSystem IAM template information to ATDR without migrating ATDR to Node/Vue/MongoDB and without enabling real external login by default.

## T3 Source Evidence

- Supervisor template env profiles under `<MFU_SHELL_ROOT>\backend-node\.env.*`
- Supervisor IAM SDK: `backend-node/server/integrations/iam/iam-sdk-adapter.js`
- Supervisor B2B middleware: `backend-node/server/integrations/iam/b2b-auth-middleware.js`
- Supervisor project IAM service: `backend-node/server/integrations/iam/project-iam-service.js`
- Supervisor Google/MFU Mail login UI: `frontend-vue/src/projects/components/dialog/SignIn.vue`
- Supervisor OTP/2FA UI: `frontend-vue/src/projects/components/dialog/TwoFA.vue`
- ATDR config/auth: `atdr/app/core/config.py`, `atdr/app/routers/auth.py`, `atdr/app/schemas/auth.py`
- ATDR Admin UI: `frontend/src/pages/UserAdmin.tsx`

Secret values were not copied into this document.

## T4 Current Behavior

ATDR supported local JWT login, local username/email login, OIDC status placeholders, and a shallow MFU IAM status endpoint. It did not understand the supervisor template env names directly and did not show MFU B2B/admin/permission readiness in the dashboard.

## T5 Impacted Areas / Agents

- Backend / API
- Security / IAM
- Frontend / Dashboard
- QA
- Documentation / Process

## T6 Scope

In scope:
- Read supervisor-style IAM env names through ATDR settings.
- Return non-secret readiness booleans.
- Show compact MFU IAM readiness in Admin.
- Add tests and docs.

Out of scope:
- Real Google/MFU Mail callback login.
- Real external token login activation.
- SMTP/OTP enforcement.
- Node/Vue/MongoDB migration.

## T7 Functional Requirements

- Local login must keep working.
- MFU IAM must remain disabled by default.
- Status endpoint must require authentication.
- Status endpoint must not expose secrets.
- Admin UI must show readiness without raw `.env` values.

## T8 Acceptance Criteria

- `IAM_SDK_*`, `IAM_ADMIN_*`, and `PROJECT_PERMISSION_*` env names are accepted.
- `/api/auth/mfu-iam/status` reports B2B/admin/permission readiness.
- Dashboard shows MFU IAM adapter state.
- Tests prove secrets are hidden.

## T9 API Contract

`GET /api/auth/mfu-iam/status`

Returns non-secret fields only, including:
- `enabled`
- `b2b_ready`
- `admin_api_ready`
- `permission_bootstrap_ready`
- `allowed_domains`
- `domain_hints`
- `secrets_exposed=false`

## T10 Data Model / Migration

No schema change.

## T11 Backend Plan / Changes

- Add supervisor env aliases in `atdr/app/core/config.py`.
- Add `atdr/app/services/mfu_iam_service.py`.
- Update `atdr/app/routers/auth.py`.
- Expand `MfuIamStatusRead`.

## T12 Frontend Plan / Changes

- Add `MfuIamStatus` type.
- Add `api.mfuIamStatus`.
- Add `useMfuIamStatus`.
- Add Admin page readiness panel.

## T13 Security / Response / AI Safety

- No real external IAM login is enabled automatically.
- No secret values are returned or logged.
- Response automation remains disabled.
- Real firewall blocking remains disabled.
- ML activation/promotion is unchanged.

## T14 Test Plan

- Backend tests for authenticated status and supervisor env alias mapping.
- Frontend mocked route coverage for Admin panel.
- Targeted lint/build/e2e where changed.

## T15 Implementation Summary

ATDR now maps the supervisor IAM template into safe ATDR config/status surfaces while preserving the current stack and local login workflow.

## T16 Tests Run / Evidence

- `.\.venv\Scripts\python.exe -m compileall -q atdr\app\core\config.py atdr\app\routers\auth.py atdr\app\services\mfu_iam_service.py atdr\app\schemas\auth.py`
- `.\.venv\Scripts\python.exe -m pytest atdr\tests\test_api.py -q -k "mfu_iam or oidc_status or local_login or school_email"`

Full verification should be run before release.

## T17 PRD / Docs Updated

- `docs/V3_64_MFU_IAM_TEMPLATE_ADAPTER.md`
- `docs/security/ATDR_MFU_IAM_IMPLEMENTATION_PLAN.md`
- `docs/ATDR_TEMPLATE_MERGE_ANALYSIS.md`
- tasklist/progress board

## T18 Risks / Blockers / Assumptions / Decisions

- The supervisor env includes sensitive values; these must remain outside Git and should be rotated before shared/preprod/prod use.
- The template gives B2B/admin service integration details, but user-facing school-email login still needs a callback/token flow.
- ATDR remains FastAPI + React.

## T19 Release / Rollback

Rollback is safe by reverting the config/status/UI changes. No database migration is involved.

## T20 Final Handoff

ATDR is now closer to the supervisor IAM template: it can understand the template IAM env naming and display readiness safely. Real external login remains a separate, reviewed implementation phase.
