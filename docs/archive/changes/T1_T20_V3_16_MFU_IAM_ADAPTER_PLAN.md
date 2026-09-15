# T1-T20: v3.16 MFU IAM Adapter Planning And Non-Secret Status Groundwork

## T1. Change Title

v3.16 MFU IAM Adapter Planning And Non-Secret Status Groundwork

## T2. Requirement

Map the supervisor NewSystem IAM guidance to ATDR safely without enabling real external IAM, OAuth/OIDC, Google SSO, B2B token introspection, SMTP, automatic response, real firewall blocking, or ML activation.

## T3. Source Evidence

| Area | Evidence |
| --- | --- |
| Supervisor IAM docs | `<MFU_SHELL_ROOT>\backend-node\docs\IAM_PRD.md`, `IAM_SYSTEM_OVERVIEW.md`, `IAM_RECOMMENDATIONS.md` |
| Supervisor IAM source | `backend-node/server/integrations/iam/*`, `backend-node/server/Project/security/*` |
| Supervisor sign-in/2FA UI | `frontend-vue/src/projects/components/dialog/SignIn.vue`, `TwoFA.vue`, `frontend-vue/src/store/modules/Security/*` |
| ATDR config/auth | `atdr/app/core/config.py`, `atdr/app/routers/auth.py`, `atdr/app/schemas/auth.py`, `atdr/app/services/user_service.py` |
| ATDR IAM docs | `docs/security/ATDR_EXTERNAL_IAM_PLAN.md`, `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| ATDR workflow docs | `docs/ATDR_AI_WORKFLOW.md`, `docs/prd/PRD-ATDR.md`, `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |

Secret-bearing `.env` files were not read or copied.

## T4. Current Behavior

ATDR uses local JWT authentication with `admin` and `analyst` roles. Generic OIDC and email verification placeholders exist but are disabled by default. Local username/email login remains active. No real SMTP, OAuth, OIDC, Google SSO, MFU IAM SDK, or B2B introspection flow is active.

## T5. Impacted Areas / Agents

| Area | Impact |
| --- | --- |
| Backend / API | Adds disabled-by-default MFU IAM and Google SSO settings plus non-secret status endpoint |
| Security / IAM | Documents mapping from supervisor IAM guidance to ATDR |
| Docs / Governance | Updates PRD, traceability, compliance, tasklist, and IAM docs |
| QA | Adds regression tests for status endpoint and disabled-login behavior |

## T6. Scope

In scope:

- Add disabled-by-default config placeholders.
- Add authenticated non-secret status endpoint.
- Add adapter plan and provider-detail checklist.
- Update governance docs.
- Add tests.

Out of scope:

- Real MFU IAM login.
- Google OAuth callback flow.
- Token introspection.
- SMTP/OTP enforcement.
- External network calls.
- Database schema changes.
- Response automation.
- ML promotion or activation.

## T7. Functional Requirements

- ATDR must expose MFU IAM readiness without exposing secrets.
- Disabled external IAM must not alter local login.
- Documentation must clearly state provider details required before real implementation.
- Supervisor IAM concepts must be mapped to ATDR roles, routes, and safety controls.

## T8. Acceptance Criteria

- `/api/auth/mfu-iam/status` requires authentication.
- Endpoint returns configured/not-configured booleans, allowed domains, default role, and `secrets_exposed=false`.
- Endpoint does not return `MFU_IAM_CLIENT_SECRET`, `GOOGLE_CLIENT_ID`, or `.env` content.
- Local username login still works when MFU IAM is disabled.
- Docs clearly state external IAM is not enabled.

## T9. API Contract

`GET /api/auth/mfu-iam/status`

Response fields:

- `enabled`
- `base_url_configured`
- `client_id_configured`
- `audience_configured`
- `allowed_domains`
- `default_role`
- `google_sso_enabled`
- `google_client_id_configured`
- `mode`
- `secrets_exposed`

The endpoint is authenticated and uses existing analyst/admin access.

## T10. Data Model / Migration

No schema change and no Alembic migration.

## T11. Backend Plan / Changes

- Add settings in `atdr/app/core/config.py`.
- Add `MfuIamStatusRead` in `atdr/app/schemas/auth.py`.
- Add `/api/auth/mfu-iam/status` in `atdr/app/routers/auth.py`.
- Keep all real external IAM behavior disabled.

## T12. Frontend Plan / Changes

No frontend runtime change required in this phase. Existing Admin / Settings IAM panels remain generic and safe.

## T13. Security / Response / AI Safety

- No secrets are exposed.
- No external auth provider is called.
- No real response connector is enabled.
- Response automation remains disabled.
- ML remains decision support only.
- Local login remains default.

## T14. Test Plan

- Endpoint authentication and secret non-disclosure test.
- Disabled MFU IAM local login regression test.
- Existing IAM/RBAC/email/login tests.
- Release gate and frontend regression gates.

## T15. Implementation Summary

Added disabled-by-default MFU IAM and Google SSO config placeholders, an authenticated non-secret status endpoint, source-backed adapter planning docs, provider-details checklist, and regression tests.

## T16. Tests Run / Evidence

Verification commands are recorded in `docs/tasks/tasklist-progress.md`.

## T17. PRD / Docs Updated

- `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md`
- `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md`
- `docs/security/ATDR_EXTERNAL_IAM_PLAN.md`
- `docs/security/ATDR_IAM_RBAC_MATRIX.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/ATDR_AI_WORKFLOW.md`
- `docs/AI-DOCS-INDEX.md`
- `README.md`

## T18. Risks / Blockers / Assumptions / Decisions

| Item | Status |
| --- | --- |
| Provider choice unknown | Open |
| Client ID/secret and callback URL unknown | Open |
| IAM group-to-role mapping unknown | Open |
| SMTP/OTP policy unknown | Open |
| Decision | Keep adapter disabled until advisor/provider details are approved |

## T19. Release / Rollback

Rollback is straightforward because there is no migration. Remove the status endpoint, schema, settings, tests, and docs if the advisor rejects MFU IAM adapter planning.

## T20. Final Handoff

ATDR now has a safe MFU IAM adapter plan and provider checklist. Real external IAM remains future work and must not be enabled until the provider details are approved and tested.

