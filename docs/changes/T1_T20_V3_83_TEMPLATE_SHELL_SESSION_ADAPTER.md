# T1-T20 Change Document: v3.83 Template Shell Session Adapter

## T1 Change Title

v3.83 Template Shell Session Adapter

## T2 Requirement

Use the supervisor template as the outer login/account shell and allow ATDR to accept a verified template session handoff without migrating ATDR to Node/Vue/MongoDB or duplicating the template registration flow.

## T3 Source Evidence

- Supervisor template runtime path: `<MFU_SHELL_ROOT>`
- Template profile endpoint evidence: `backend-node/server/Project/accounts/accounts.routes.js`
- Template launcher target: `frontend-vue/src/projects/views/mfuaidrivenlogbasedthreatdetectionandresponse/MFUAIDRIVENLOGBASEDTHREATDETECTIONANDRESPONSERegistry.vue`
- ATDR auth router: `atdr/app/routers/auth.py`
- ATDR MFU IAM service: `atdr/app/services/mfu_iam_service.py`
- ATDR login receiver: `frontend/src/pages/LoginPage.tsx`

## T4 Current Behavior

ATDR already had local login, disabled-by-default MFU IAM token login, public/private IAM status endpoints, and a frontend handoff receiver. The template launcher had been applied to the external template copy. The missing bridge was that the template `x-access-token` is a template session token, not guaranteed to be directly introspectable by MFU IAM.

## T5 Impacted Areas / Agents

- Backend / API
- Security / IAM
- Frontend / Dashboard
- QA / UAT
- Release / Lab Validation
- Documentation / Governance

## T6 Scope

In scope:

- Template-shell session validation path.
- Non-secret status fields.
- Admin dashboard readiness visibility.
- Tests for status, success, and failure.

Out of scope:

- Full OAuth/OIDC browser callback.
- Migration to template Node/Vue/MongoDB runtime.
- Real firewall blocking.
- Automatic response.
- Model activation/promotion.

## T7 Functional Requirements

- Keep local login working.
- Accept template-session handoff only when explicitly enabled.
- Call the configured template profile endpoint using the configured header.
- Map verified school-domain email to an ATDR user.
- Default school users to analyst.
- Grant admin only through explicit configured allowlist.
- Hide secrets and handoff values from responses/audit details.

## T8 Acceptance Criteria

- Status endpoint reports template-shell readiness without exposing secrets.
- Successful template profile response creates/maps an external ATDR user.
- Failed template profile response returns a safe authentication failure.
- Token values are not written to audit details.
- Local login fallback remains available.

## T9 API Contract

Existing endpoint reused:

```text
POST /api/auth/mfu-iam/token-login
```

Safe status fields added to existing MFU IAM status endpoints:

- `template_shell_enabled`
- `template_shell_ready`
- `template_shell_base_url_configured`
- `template_shell_me_path`
- `template_shell_header`

No secret values are returned.

## T10 Data Model / Migration

No schema migration. Existing `users` and `audit_logs` tables are reused.

## T11 Backend Plan / Changes

- Added template-shell settings in `atdr/app/core/config.py`.
- Added template-shell readiness/status fields in `atdr/app/services/mfu_iam_service.py`.
- Added template-shell profile validation path in `authenticate_mfu_iam_token`.
- Added schema fields in `atdr/app/schemas/auth.py`.

## T12 Frontend Plan / Changes

- Updated API types for template-shell fields.
- Updated Admin / Settings MFU IAM panel to show template shell handoff readiness.

## T13 Security / Response / AI Safety

- No response automation enabled.
- No real firewall blocking enabled.
- No model activation or promotion.
- Local fallback remains available.
- Handoff token is used only for validation and not logged.
- Admin mapping remains explicit.

## T14 Test Plan

- Status endpoint shows template shell ready when configured.
- Token login maps verified school email from template profile.
- Failed template validation hides token and returns generic failure.
- Local login/auth behavior remains covered by existing tests.

## T15 Implementation Summary

Implemented a safe session-adapter mode so ATDR can validate the supervisor template's current session through the template backend profile endpoint and create an ATDR session from the verified school email.

## T16 Tests Run / Evidence

```powershell
.\.venv\Scripts\python.exe -m pytest atdr\tests\test_api.py -q --basetemp .pytest_tmp\template-shell-api -p no:cacheprovider
.\.venv\Scripts\ruff.exe check atdr\app\core\config.py atdr\app\services\mfu_iam_service.py atdr\app\schemas\auth.py atdr\tests\test_api.py
.\.venv\Scripts\python.exe -m compileall -q atdr\app\core\config.py atdr\app\services\mfu_iam_service.py atdr\app\schemas\auth.py atdr\tests\test_api.py
```

Focused results:

- Backend focused tests: `38 passed`
- Ruff: passed
- Compileall: passed

## T17 PRD / Docs Updated

- `docs/V3_83_TEMPLATE_SHELL_SESSION_ADAPTER.md`
- `docs/ATDR_TEMPLATE_SHELL_INTEGRATION_PLAN.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/AI-DOCS-INDEX.md`
- `docs/tasks/tasklist-progress.md`

## T18 Risks / Blockers / Assumptions / Decisions

- Live end-to-end validation still requires the template backend/frontend running and a valid template session.
- Production/preprod URLs must be configured privately.
- Any shared secret-like values from the template must be confirmed/rotated by advisor/provider before real deployment.
- Decision: ATDR will validate the template session rather than treating the template `x-access-token` as an MFU B2B token.

## T19 Release / Rollback

No schema migration. Disable the feature by setting:

```env
MFU_IAM_TEMPLATE_SHELL_ENABLED=false
```

Local login remains available.

## T20 Final Handoff

ATDR now has the safer backend bridge needed for the advisor's intended flow: login in the supervisor template first, then open ATDR as the SOC module after session validation. Next step is live runtime validation with both systems running.

