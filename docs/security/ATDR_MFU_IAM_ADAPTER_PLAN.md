# ATDR MFU IAM Adapter Plan

## Status

This document maps the supervisor MFU IAM template to ATDR. ATDR remains a FastAPI + React + SQLAlchemy/Alembic system. Its normal local authentication path is local JWT login; the optional v3.91 MFU outer-shell handoff is the school-identity path when the two services are explicitly configured.

Current implementation status:

- `MFU_IAM_HANDOFF_ENABLED=false` by default.
- `GOOGLE_SSO_ENABLED=false` by default.
- The template, not ATDR, owns school sign-in and 2FA. ATDR consumes only a short-lived opaque one-time code and exchanges it server-to-server.
- No external IAM network calls are made during normal local startup.
- No IAM client secrets are returned by APIs or committed to Git.
- Local username/password and local email login remain the working login methods.
- New MFU users map to `analyst`; an approved IAM group is required for `admin`.
- Response automation remains disabled.

The canonical implementation and operating documents are `docs/V3_91_MFU_OUTER_SHELL_SECURE_HANDOFF.md` and `docs/security/ATDR_MFU_IAM_PREPROD_VALIDATION.md`. Earlier token/session handoff documents are historical evidence only.

## Source Evidence Reviewed

| Evidence | Source |
| --- | --- |
| Supervisor IAM PRD | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\backend-node\docs\IAM_PRD.md` |
| Supervisor IAM overview | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\backend-node\docs\IAM_SYSTEM_OVERVIEW.md` |
| Supervisor IAM recommendations | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\backend-node\docs\IAM_RECOMMENDATIONS.md` |
| Supervisor IAM SDK and B2B middleware | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\backend-node\server\integrations\iam\*` |
| Supervisor security permission services | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\backend-node\server\Project\security\*` |
| Supervisor Vue sign-in dialogs | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\frontend-vue\src\projects\components\dialog\SignIn.vue`, `TwoFA.vue` |
| Supervisor Vue security store | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\frontend-vue\src\store\modules\Security\*` |
| ATDR auth/config | `atdr/app/core/config.py`, `atdr/app/core/security.py`, `atdr/app/routers/auth.py`, `atdr/app/services/user_service.py` |
| ATDR IAM docs | `docs/security/ATDR_EXTERNAL_IAM_PLAN.md`, `docs/security/ATDR_IAM_RBAC_MATRIX.md` |

No `.env` values or secret files were copied into this plan.

## What The Supervisor IAM Template Expects

The NewSystem template describes a larger IAM ecosystem:

- MFU IAM service integration through an SDK-style client.
- Google SSO / MFU Mail login using Google ID token behavior and audience checks.
- Email/password login.
- Email OTP / 2FA.
- Trusted device behavior.
- Account lifecycle and account invite flow.
- Permission matrix with menu/path/action/data-scope concepts.
- Project-scoped groups and assignments.
- B2B token introspection with active/audience/scope validation.
- Audit logging for authentication, permission, and account actions.
- Environment configuration for IAM base URL, client ID, client secret, audience, Google client ID, and permission source.

This does not mean ATDR should migrate to Node, Vue, MongoDB, or the NewSystem runtime stack. It means ATDR should adapt the identity concepts safely.

## What ATDR Already Supports

| Area | Current ATDR Support |
| --- | --- |
| Local authentication | Local JWT login with username/password and optional local email login |
| Roles | `admin` and `analyst` |
| Route authorization | FastAPI dependencies such as `require_admin` and `require_analyst_or_admin` |
| User lifecycle | Local user creation, update, disable, password reset, email, email verified flag, auth provider metadata |
| Email verification groundwork | Disabled-by-default verification, hashed tokens, admin-only dev outbox, audit events |
| Generic external IAM placeholders | Disabled-by-default OIDC config/status endpoint |
| MFU outer-shell handoff | Disabled-by-default opaque code, form POST, exact-origin/path checks, server-side exchange, HttpOnly session cookie, audit, analyst default, and group-based admin mapping |
| Response safety | Simulated response only, admin-only response actions, justification required, protected IP denial, audit logs |
| Audit | Audit records for login failures, user actions, verification actions, response attempts, assistant questions, and other workflows |
| Permission documentation | ATDR IAM/RBAC matrix and permission path registry |

## What ATDR Is Missing

ATDR does not yet have operating proof or implementation for:

- Provider-backed preproduction validation of the v3.91 handoff.
- A direct ATDR-owned Google SSO or MFU Mail login.
- Direct ATDR OAuth/OIDC redirect and callback routes.
- External logout/session synchronization beyond clearing the ATDR cookie.
- Full email OTP/2FA enforcement in ATDR; the template owns its own 2FA behavior.
- Trusted device management.
- Invite flow connected to a real email provider.
- Fine-grained permission matrix in the database.
- Verified live IAM group identifiers and lifecycle synchronization.
- B2B client credentials or service-token support.
- Real SMTP delivery.

These require approved provider configuration, group policy, and preproduction evidence. They are not implied by the source implementation.

## Safe Mapping To ATDR

### Identity Mapping

| Supervisor IAM Concept | ATDR Mapping |
| --- | --- |
| MFU outer-shell identity | Local `users` row linked to sanitized email/subject returned by the one-time-code exchange |
| Google/MFU Mail identity | Template-owned school identity; ATDR receives no browser credential |
| Account invite | Future admin-created local user plus email verification/invite notification |
| Active account | `User.is_active=true` |
| Disabled/deprovisioned account | `User.is_active=false` with `disabled_at` |

### Role Mapping

| Supervisor IAM Group / Scope | Proposed ATDR Role |
| --- | --- |
| MFU ATDR Admin / org-wide access | `admin` |
| MFU ATDR Manager / unit-level access | likely `analyst` unless advisor approves a future manager role |
| MFU ATDR Staff / self-level access | `analyst` or future `viewer` depending on required access |
| B2B Client | Future service account, not a dashboard user |

Default external role should remain `analyst`. External login must never auto-grant `admin` without an explicit approved group mapping.

### Permission Matrix Mapping

ATDR currently uses route-level roles. A future external IAM permission matrix can map supervisor-style paths to ATDR areas:

| ATDR Area | Current Route/UI Evidence | Future Permission Path Example |
| --- | --- | --- |
| Overview | `frontend/src/pages/ExecutiveOverview.tsx`, `atdr/app/routers/dashboard.py` | `/atdr/overview:view` |
| Alerts | `frontend/src/pages/AlertsTriage.tsx`, `atdr/app/routers/alerts.py` | `/atdr/alerts:view`, `/atdr/alerts:update` |
| Investigation | `frontend/src/pages/LogExplorer.tsx`, `atdr/app/routers/logs.py` | `/atdr/logs:view` |
| AI Governance | `frontend/src/pages/MLGovernance.tsx`, `atdr/app/routers/ml.py` | `/atdr/ml:view`, `/atdr/ml:train` |
| Response & Audit | `frontend/src/pages/ResponseCenter.tsx`, `atdr/app/routers/response.py`, `audit.py` | `/atdr/response:simulate`, `/atdr/audit:view` |
| Admin/User Admin | `frontend/src/pages/UserAdmin.tsx`, `atdr/app/routers/users.py` | `/atdr/admin:manage-users` |
| Source Management | `frontend/src/pages/ExecutiveOverview.tsx`, `atdr/app/routers/sources.py` | `/atdr/sources:view`, `/atdr/sources:manage` |

The current path registry is `docs/security/ATDR_PERMISSION_PATHS.md`.

### OTP / 2FA Mapping

The supervisor template has email OTP/2FA. ATDR currently has local email verification groundwork, not login 2FA:

- Current: verification-code tokens are hashed.
- Current: dev outbox is admin-only and disabled by default.
- Current: no real SMTP and no login blocking.
- Future: real 2FA would need SMTP/provider approval, lockout controls, rate limits, recovery flow, audit rules, and rollout rules.

### Token Introspection Mapping

B2B token introspection can map to future service-to-service endpoints only. It should not be mixed with dashboard login until the provider contract is clear.

Future requirements:

- Introspection URL.
- Required audience.
- Required scopes.
- Token caching policy.
- Timeout and failure behavior.
- Audit log behavior.
- Deny-by-default route policy.

## Safe Configuration Placeholders

ATDR now reserves the following disabled-by-default fields:

```env
MFU_IAM_ENABLED=false
MFU_IAM_BASE_URL=""
MFU_IAM_CLIENT_ID=""
MFU_IAM_CLIENT_SECRET=""
MFU_IAM_AUDIENCE=""
MFU_IAM_SCOPE=""
MFU_IAM_TOKEN_PATH="/api/v1/b2b/token"
MFU_IAM_INTROSPECT_PATH="/api/v1/b2b/introspect"
MFU_IAM_PROFILE_PATH="/api/v1/b2b/me"
MFU_IAM_ADMIN_BASE_PATH="/api/v1"
MFU_IAM_ALLOWED_DOMAINS=""
MFU_IAM_DEFAULT_ROLE="analyst"
GOOGLE_SSO_ENABLED=false
GOOGLE_CLIENT_ID=""
```

These fields are planning/configuration placeholders only. They do not enable real external login. The implementation sequence and current evidence are tracked in `docs/security/ATDR_MFU_IAM_IMPLEMENTATION_PLAN.md`.

## Safe Status Surface

ATDR exposes a non-secret authenticated status endpoint:

```text
GET /api/auth/mfu-iam/status
```

It returns only:

- enabled
- base_url_configured
- client_id_configured
- audience_configured
- allowed_domains
- default_role
- google_sso_enabled
- google_client_id_configured
- mode
- secrets_exposed=false

It does not return `MFU_IAM_CLIENT_SECRET`, `GOOGLE_CLIENT_ID`, OAuth secrets, SMTP passwords, or `.env` content.

## Provider Details Required Before Real Implementation

Real implementation must wait until the advisor/university confirms:

- Approved provider type: MFU IAM SDK, Google Workspace, generic OIDC, or a combination.
- Approved base URL / issuer URL.
- Token, introspection, userinfo, authorization, and logout endpoint behavior.
- Client ID.
- Secret delivery and storage process.
- Redirect/callback URLs for local, preprod, and any shared lab environment.
- Allowed email domains.
- Group-to-role mapping for `admin` and `analyst`.
- Whether students can access preprod IAM.
- Whether SMTP/OTP email is allowed.
- Audit and retention requirements.

## Must Stay Disabled Until Approved

- Real OAuth/OIDC/Google/MFU IAM login.
- Automatic external account provisioning.
- Automatic admin assignment.
- Real SMTP delivery.
- Email verification or 2FA login enforcement.
- B2B token introspection on production-like routes.
- Real firewall blocking.
- Automatic response.
- ML activation or production promotion.

## Recommended Implementation Order

1. Confirm provider details using `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md`.
2. Add a mock-provider integration test suite.
3. Implement token validation or OIDC discovery in a disabled-by-default branch.
4. Add callback/login routes behind `MFU_IAM_ENABLED` or `OIDC_ENABLED`.
5. Map external identity to local users by verified email and external subject.
6. Add group-to-role mapping with default `analyst`.
7. Add audit events for external login attempts.
8. Add frontend login button only when the provider is configured.
9. Run security review before shared lab use.
