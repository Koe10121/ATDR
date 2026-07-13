# ATDR Template Shell Integration Plan

Date: 2026-07-11

## Purpose

ATDR will use the official supervisor template system as the outer application shell and school-email IAM gateway, then open ATDR as the protected SOC module after successful authentication.

This plan is source-backed and intentionally keeps ATDR's current runtime stack:

- FastAPI backend
- React SOC dashboard
- SQLAlchemy/Alembic database workflow
- SQLite for normal local development, optional PostgreSQL later
- Python parser, detection, ML, and SOC Assistant services

ATDR should not be blindly migrated to the supervisor template's Node/Vue/MongoDB stack. The template should be reused for identity, shell, permission, and workflow concepts where they fit.

## Source Evidence Reviewed

Supervisor template source path:

`C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response`

Supervisor template files reviewed without printing secret values:

- `backend-node/docs/IAM_SYSTEM_OVERVIEW.md`
- `backend-node/docs/IAM_PRD.md`
- `backend-node/docs/IAM_RECOMMENDATIONS.md`
- `docs/IAM-UPGRADE.md`
- `backend-node/server/integrations/iam/b2b-auth-middleware.js`
- `backend-node/server/integrations/iam/iam-sdk-adapter.js`
- `backend-node/server/integrations/iam/project-iam-service.js`
- `backend-node/server/integrations/iam/sdk.js`
- `backend-node/server/Project/accounts/service/account.js`
- `backend-node/server/Project/security/service/authorization.js`
- `backend-node/server/Project/security/service/account-access.js`
- `backend-node/server/Project/security/service/iam-admin-client.js`
- `backend-node/server/Project/security/service/bootstrap-access.js`
- `backend-node/server/Project/security/service/audit.js`
- `frontend-vue/src/projects/components/dialog/SignIn.vue`
- `frontend-vue/src/projects/components/dialog/TwoFA.vue`
- `frontend-vue/src/router/index.js`
- `frontend-vue/src/store/modules/Authen/*`
- `frontend-vue/src/store/modules/Security/*`

Current ATDR files reviewed:

- `atdr/app/core/config.py`
- `atdr/app/core/security.py`
- `atdr/app/routers/auth.py`
- `atdr/app/services/mfu_iam_service.py`
- `frontend/src/pages/LoginPage.tsx`
- `frontend/src/lib/api.ts`
- `frontend/src/App.tsx`
- `docs/security/ATDR_MFU_IAM_IMPLEMENTATION_PLAN.md`
- `docs/V3_64_MFU_IAM_TEMPLATE_ADAPTER.md`
- `docs/V3_65_MFU_IAM_AND_REAL_ASSISTANT_HARNESS.md`
- `docs/V3_74_MFU_IAM_VALIDATION_HARNESS.md`
- `docs/V3_77_MFU_IAM_CONFIG_DOCTOR_VISIBILITY.md`

## What The Supervisor Template Provides

The supervisor template provides a complete outer application identity and authorization pattern:

- User sign-in flow through the template account service.
- Google/MFU Mail style sign-in path in the frontend login dialog.
- Optional two-factor verification dialog.
- Trusted device/session behavior.
- Permission matrix concepts with path/action checks.
- Route guard behavior that loads permissions before allowing application routes.
- B2B bearer-token middleware that performs token introspection.
- IAM SDK adapter boundaries for token, introspection, profile, and admin endpoints.
- Audit logging expectations for login, authorization, account, and permission operations.
- Project permission ownership concepts for IAM-managed permission groups.

The template env files also identify the variable names expected by the MFU IAM SDK and project permission bootstrap flow. Secret-looking values may exist in the template files, but they must not be copied into ATDR docs, committed, or printed. Any exposed or shared secret-like value should be treated as needing advisor/provider confirmation and possible rotation before real use.

## What ATDR Already Supports

ATDR already has the safe groundwork needed for a school-email IAM bridge:

- Local JWT username/password login.
- Admin and analyst roles.
- Email fields and local email-login support.
- MFU IAM status and token-login endpoints:
  - `GET /api/auth/mfu-iam/public-status`
  - `POST /api/auth/mfu-iam/token-login`
  - `GET /api/auth/mfu-iam/status`
- Disabled-by-default MFU IAM settings and supervisor-template env aliases.
- Token validation service that can call MFU IAM token introspection and profile endpoints when enabled.
- Safe local user upsert from a verified external identity.
- Explicit admin email mapping and default analyst role for school-email users.
- Audit logging for MFU IAM login success/failure.
- Config doctor visibility for MFU IAM readiness without exposing secrets.
- Real LLM SOC Assistant adapter that is disabled by default and remains read-only.

## Recommended Architecture

### Recommended Pattern: Template Shell Plus Redirect/Token Handoff

The recommended integration is:

1. User opens the supervisor template application.
2. User signs in through the template's school-email/IAM flow.
3. Template verifies 2FA/OTP/trusted-device requirements when configured.
4. Template checks the user's route/permission access.
5. Template launches ATDR as a protected module.
6. Template gives ATDR a short-lived IAM-backed handoff token or an introspectable school IAM token.
7. ATDR validates the token through `POST /api/auth/mfu-iam/token-login`.
8. ATDR maps the verified school identity to a local ATDR user.
9. ATDR issues its own local JWT for SOC routes.
10. ATDR audits the handoff login.

This avoids duplicating registration and account lifecycle inside ATDR while preserving ATDR's existing SOC pipeline.

### Preferred Deployment Shape

For local development:

- Supervisor template backend can run on its configured local port.
- Supervisor template frontend can run as documented by that project.
- ATDR backend remains:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

- ATDR frontend remains:

```powershell
cd frontend
npm.cmd run dev
```

- The template can open ATDR at `http://127.0.0.1:5173`.
- Until the real provider flow is verified, ATDR local login remains the fallback.

For preprod/prod:

- Prefer a same-domain reverse proxy:
  - template shell at the main application domain
  - ATDR React module under a route such as `/atdr`
  - ATDR API under a route such as `/atdr-api`
- Use HTTPS only.
- Restrict CORS to approved template/ATDR origins.
- Use private environment variables for IAM secrets.
- Disable mock mode.
- Keep local login only as approved break-glass access if the advisor/team approves it.

## Handoff Options

| Option | Recommendation | Reason |
| --- | --- | --- |
| Redirect plus token handoff | Recommended | Fits current ATDR `mfu-iam/token-login` endpoint, avoids iframe issues, preserves current stack. |
| Reverse proxy same-origin module | Recommended for preprod/prod | Simplifies CORS/cookies/origin policy and makes ATDR feel like a module inside the supervisor shell. |
| API bridge from template backend to ATDR backend | Useful when token cannot be exposed to browser | Template can exchange/validate IAM token server-side, then issue a short-lived ATDR handoff token. |
| iframe embedding | Not recommended | Higher risk for clickjacking, CSP, auth/session confusion, and poor UX. Use only if advisor requires it. |
| Full migration to Node/Vue/MongoDB | Not recommended | ATDR has mature FastAPI/React/SQLAlchemy parser/detection/ML/audit behavior. Migration would add risk without solving IAM faster. |
| Duplicating template registration in ATDR | Not recommended | Conflicts with the new direction: template owns registration/account lifecycle. |

## Recommended Handoff Flow

### Browser Token Handoff Flow

Use this if the template can provide an IAM token that ATDR is allowed to introspect:

1. Template user clicks an ATDR/SOC module link.
2. Template frontend obtains the current IAM token or session handoff token.
3. Template redirects to ATDR:

```text
http://127.0.0.1:5173/login?mode=mfu-handoff
```

4. ATDR React handoff receiver calls:

```text
POST /api/auth/mfu-iam/token-login
```

5. ATDR backend introspects/validates the token.
6. ATDR validates allowed domain, audience, and active status.
7. ATDR creates or updates a local user:
   - default role: analyst
   - admin only if explicitly configured in private env
8. ATDR stores the returned ATDR JWT and opens `/overview`.

### Server-Side Bridge Flow

Use this if the template token must not be passed to ATDR React:

1. Template backend validates current template/IAM session.
2. Template backend calls ATDR handoff endpoint or creates a signed short-lived handoff token.
3. Browser redirects to ATDR with a one-time handoff code.
4. ATDR backend validates the one-time code against the template backend or configured signing key.
5. ATDR issues its own JWT and audits the login.

This is safer if the supervisor template already owns the browser session and can act as a trusted gateway.

## What To Reuse From The Template

Reuse these concepts and contracts:

- Outer application shell and route guard pattern.
- School-email sign-in entry point.
- Google/MFU Mail login concept, if provider details are approved.
- 2FA/OTP account flow, if the template's provider policy applies.
- Permission matrix language: path/action permissions.
- B2B token introspection contract.
- IAM SDK endpoint variable names.
- Account lifecycle ownership.
- Audit expectations for login, token validation, permission checks, and account events.

## What Not To Copy Into ATDR

Do not copy:

- Template secret values.
- Template `.env` files.
- Template MongoDB data model for ATDR SOC data.
- Node controllers as replacements for ATDR parser/detection/ML services.
- Vue UI as a wholesale replacement for the React SOC dashboard.
- Any route wording that claims production readiness.
- Any registration flow that duplicates the template's account lifecycle.
- Any real response automation or firewall blocking behavior.

## Required Private Configuration

ATDR can read either ATDR-native or supervisor-template env names. These must be configured only in private `.env` or deployment secrets:

- `MFU_IAM_ENABLED=true`
- `MFU_IAM_BASE_URL` or `IAM_SDK_BASE_URL`
- `MFU_IAM_CLIENT_ID` or `IAM_SDK_CLIENT_ID`
- `MFU_IAM_CLIENT_SECRET` or `IAM_SDK_CLIENT_SECRET`
- `MFU_IAM_AUDIENCE` or `IAM_SDK_AUDIENCE`
- `MFU_IAM_SCOPE` or `IAM_SDK_SCOPE`
- `MFU_IAM_TOKEN_PATH` or `IAM_SDK_TOKEN_PATH`
- `MFU_IAM_INTROSPECT_PATH` or `IAM_SDK_INTROSPECT_PATH`
- `MFU_IAM_PROFILE_PATH` or `IAM_SDK_PROFILE_PATH`
- `MFU_IAM_ALLOWED_DOMAINS`
- `MFU_IAM_DEFAULT_ROLE=analyst`
- `MFU_IAM_ADMIN_EMAILS` for explicit admin mapping
- optional `GOOGLE_SSO_ENABLED` and `GOOGLE_CLIENT_ID` only if Google/MFU Mail browser login is approved

Do not hard-code any individual school email as the only accepted user. A school email may be used as a configured test/admin mapping in private env.

## v3.83 Template Shell Session Adapter

The supervisor template's frontend stores and sends an `x-access-token` for the template's own protected API. That value should not be blindly treated as a direct MFU B2B token. ATDR now supports a safer adapter mode where it validates that token against the template backend's current-profile endpoint and maps the verified school email into ATDR.

Private local configuration for this mode:

```env
MFU_IAM_ENABLED=true
MFU_IAM_TEMPLATE_SHELL_ENABLED=true
MFU_IAM_TEMPLATE_SHELL_BASE_URL=http://127.0.0.1:8214
MFU_IAM_TEMPLATE_SHELL_ME_PATH=/api/v1/auth/me
MFU_IAM_TEMPLATE_SHELL_HEADER=x-access-token
MFU_IAM_ALLOWED_DOMAINS=lamduan.mfu.ac.th
MFU_IAM_DEFAULT_ROLE=analyst
```

This mode lets the supervisor template remain responsible for school login, 2FA, and account lifecycle. ATDR validates the template session, creates its own SOC JWT, audits success/failure, and keeps admin role mapping explicit.

## What Still Requires Advisor Or Provider Confirmation

Before real school-email login can be called complete, confirm:

- Which token ATDR will receive:
  - MFU IAM access token
  - Google ID token
  - template `x-access-token`
  - short-lived template handoff code
- Whether that token is introspectable by the IAM endpoint.
- Approved local callback URL.
- Approved preprod callback URL.
- Approved production callback URL.
- Allowed email domains.
- Group-to-role mapping for ATDR admin and analyst.
- Whether students can access the preprod IAM client.
- Whether provider-managed 2FA is required.
- Whether the template backend or ATDR backend should perform token exchange.
- Audit retention and privacy requirements.
- Whether any visible/shared secret-like template values must be rotated before use.

## Current Recommended Next Implementation Slice

The ATDR handoff receiver, template launcher helper, and template shell session adapter now exist. The next slice is live runtime validation:

1. Start the template backend and frontend.
2. Start the ATDR backend and frontend.
3. Configure private ATDR `.env` for template-shell handoff.
4. Sign in through the template shell.
5. Click `Open ATDR SOC Dashboard`.
6. Confirm ATDR receives the handoff, clears token-like URL data, validates `/api/v1/auth/me`, maps the school email, and opens the SOC dashboard.
7. Confirm failed/expired template sessions are rejected without exposing tokens.

## Safety Boundaries

- Local login remains available.
- MFU IAM remains disabled unless `MFU_IAM_ENABLED=true`.
- Mock IAM must never be used for production-like configuration.
- No response automation is enabled.
- No real firewall blocking is enabled.
- Chatbot remains read-only.
- Raw logs are not sent to external LLMs by default.
- External LLM provider keys stay in private `.env`.
- ATDR remains a SOC module, not the owner of school account registration.

## Decision

ATDR should integrate with the supervisor template through a protected module handoff, not by merging the whole runtime stack. The supervisor template should own school login, account lifecycle, 2FA/OTP, and permission shell. ATDR should own SOC ingestion, parsing, detection, ML governance, assistant explanations, simulated response, and audit. The immediate next phase is the handoff receiver and end-to-end mock/real-provider validation, using private configuration only.
