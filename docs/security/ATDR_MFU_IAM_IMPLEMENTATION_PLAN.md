# ATDR MFU IAM Implementation Plan

## Status

ATDR has disabled-by-default MFU IAM and Google SSO configuration/status groundwork. Real external login is not enabled yet. Local username/password login and local email login remain the active authentication paths.

This plan converts the supervisor template IAM evidence into an ATDR-specific implementation path.

## Current ATDR Support

| Capability | Status | Evidence |
| --- | --- | --- |
| Local JWT login | Implemented | `atdr/app/routers/auth.py`, `atdr/app/core/security.py` |
| Local username login | Implemented | `atdr/app/services/user_service.py` |
| Local email login | Implemented when `LOCAL_EMAIL_LOGIN_ENABLED=true` | `atdr/app/services/user_service.py` |
| Admin/analyst RBAC | Implemented | `docs/security/ATDR_IAM_RBAC_MATRIX.md`, `atdr/app/core/security.py` |
| School-email metadata | Implemented | `atdr/app/db/models.py`, `frontend/src/pages/UserAdmin.tsx` |
| Email verification foundation | Disabled by default | `atdr/app/services/account_verification_service.py` |
| MFU IAM status endpoint | Implemented, non-secret | `GET /api/auth/mfu-iam/status` |
| Supervisor env alias support | Implemented for status/readiness | `atdr/app/core/config.py` |
| MFU IAM readiness service | Implemented, no startup network call | `atdr/app/services/mfu_iam_service.py` |
| Admin dashboard readiness panel | Implemented | `frontend/src/pages/UserAdmin.tsx` |
| OIDC status endpoint | Implemented, non-secret | `GET /api/auth/oidc/status` |

## Supervisor Template IAM Evidence

The supervisor template includes:

- MFU IAM SDK/client integration in `backend-node/server/integrations/iam/*`.
- IAM admin client and permission proxy behavior in `backend-node/server/Project/security/service/iam-admin-client.js`.
- B2B token introspection middleware in `backend-node/server/integrations/iam/b2b-auth-middleware.js`.
- Google sign-in UI behavior in `frontend-vue/src/projects/components/dialog/SignIn.vue`.
- OTP/2FA UI behavior in `frontend-vue/src/projects/components/dialog/TwoFA.vue`.
- Permission matrix stores under `frontend-vue/src/store/modules/Security/*`.
- IAM docs under `backend-node/docs/IAM_PRD.md`, `IAM_SYSTEM_OVERVIEW.md`, and `IAM_RECOMMENDATIONS.md`.

## Template Env Names Mapped To ATDR

| Supervisor Variable Family | ATDR Equivalent |
| --- | --- |
| `IAM_SDK_BASE_URL` / `IAM_SDK_*` | Accepted directly by ATDR as aliases for `MFU_IAM_BASE_URL`, `MFU_IAM_CLIENT_ID`, `MFU_IAM_CLIENT_SECRET`, `MFU_IAM_AUDIENCE`, `MFU_IAM_SCOPE`, and timeout/path fields |
| `IAM_ADMIN_*` | Accepted directly by ATDR as aliases for admin client ID/secret/audience/scope and admin API readiness |
| Token/introspection/profile paths | `MFU_IAM_TOKEN_PATH`, `MFU_IAM_INTROSPECT_PATH`, `MFU_IAM_PROFILE_PATH`, `MFU_IAM_ADMIN_BASE_PATH` |
| `GOOGLE_CLIENT_ID`, `VUE_APP_CLIENTID` | `GOOGLE_CLIENT_ID` |
| Project permission source/paths | Accepted by ATDR status/readiness through `PROJECT_PERMISSION_SOURCE`, `PROJECT_PERMISSION_BOOTSTRAP_MODE`, `PROJECT_PERMISSION_ROOT_PATH`, and `PROJECT_PERMISSION_PATHS` |
| Initial admin email lists | Accepted for readiness/status only; not automatic admin grant |
| `PROJECT_AUTH_REQUIRE_2FA` | Accepted for readiness/status only; current ATDR verification is not login 2FA |

## Safe Config Fields

These settings are supported for status/planning. They do not enable real external login by themselves:

```env
MFU_IAM_ENABLED=false
MFU_IAM_BASE_URL=""
MFU_IAM_CLIENT_ID=""
MFU_IAM_CLIENT_SECRET=""
MFU_IAM_AUDIENCE=""
MFU_IAM_SCOPE=""
MFU_IAM_TIMEOUT_MS=5000
MFU_IAM_TOKEN_PATH="/api/v1/b2b/token"
MFU_IAM_INTROSPECT_PATH="/api/v1/b2b/introspect"
MFU_IAM_PROFILE_PATH="/api/v1/b2b/clients/me"
MFU_IAM_ADMIN_BASE_PATH="/api/v1/b2b/admin"
MFU_IAM_ADMIN_CLIENT_ID=""
MFU_IAM_ADMIN_CLIENT_SECRET=""
MFU_IAM_ADMIN_AUDIENCE=""
MFU_IAM_ADMIN_SCOPE=""
MFU_IAM_COMPAT_PROFILE=""
MFU_IAM_ALLOWED_DOMAINS=""
MFU_IAM_DEFAULT_ROLE="analyst"
MFU_IAM_PERMISSION_SOURCE=""
MFU_IAM_PERMISSION_BOOTSTRAP_MODE=""
MFU_IAM_PERMISSION_ROOT_PATH=""
MFU_IAM_PERMISSION_PATHS=""
MFU_IAM_PROJECT_ACCOUNT_EMAIL=""
MFU_IAM_AUTH_REQUIRE_2FA=false
MFU_IAM_AUDIT_RETENTION_DAYS=90
MFU_IAM_MANAGED_CLIENT_ID=""
MFU_IAM_MANAGED_CLIENT_ENDPOINT=""
MFU_IAM_MANAGED_CLIENT_OWNER_EMAIL=""
MFU_IAM_MANAGED_CLIENT_ALLOWED_SCOPES=""
MFU_IAM_MANAGED_CLIENT_ALLOWED_AUDIENCES=""
MFU_IAM_INIT_ADMIN_EMAILS=""
MFU_IAM_INIT_SEED_ADMIN_EMAIL=""
GOOGLE_SSO_ENABLED=false
GOOGLE_CLIENT_ID=""
```

`GET /api/auth/mfu-iam/status` returns only booleans and non-secret policy fields. It must never expose `MFU_IAM_CLIENT_SECRET`, `GOOGLE_CLIENT_ID`, or any `.env` value.

ATDR also accepts the supervisor template names `IAM_SDK_*`, `IAM_ADMIN_*`, and `PROJECT_PERMISSION_*` in a private local `.env`. These aliases are used for status/readiness and do not require migrating to the template's Node/Vue/MongoDB stack.

## Recommended Implementation Order

1. Keep local login as fallback.
2. Add a mock MFU IAM provider test harness.
3. Implement token validation against configured MFU IAM endpoints behind `MFU_IAM_ENABLED=true`.
4. Map verified school email and external subject to a local `users` row.
5. Default newly provisioned external users to `analyst`.
6. Add explicit admin group mapping only after advisor approval.
7. Add frontend `School Email Login` button only when status reports enough configuration.
8. Add audit events for external login success/failure, role mapping, and denied domain.
9. Add email OTP/2FA enforcement only after SMTP/provider policy and lockout/recovery rules are approved.

## Current Recommendation

Use MFU IAM SDK/token introspection as the first real IAM path because the supervisor template contains IAM SDK/admin configuration and token/introspection/profile paths. Treat Google/MFU Mail as a second path because the checked Google client ID env fields are present but not configured.

v3.64 improves readiness for that path by making ATDR understand the supervisor env names directly and exposing readiness in Admin. It still does not perform real login or external token validation during normal startup.

## Still Required From Advisor / Provider

- Approved MFU IAM base URL for local/preprod.
- Approved client ID and secure client secret delivery.
- Audience and scope values for ATDR.
- Token, introspection, profile, and admin endpoint contract.
- Allowed domains, including whether `lamduan.mfu.ac.th` is the correct student domain.
- Group-to-role mapping for `admin` and `analyst`.
- Callback URL and frontend login behavior if using OAuth/OIDC/Google.
- Whether automatic user provisioning is allowed.
- Whether OTP/2FA is required.
- Audit and retention policy for external login.

## Explicit Non-Goals For This Phase

- No real external login is enabled.
- No Google/MFU Mail OAuth callback is enabled.
- No secrets are copied from the supervisor template.
- No external network call is made by default.
- No automatic admin role assignment occurs.
- No automatic response or firewall blocking is enabled.
