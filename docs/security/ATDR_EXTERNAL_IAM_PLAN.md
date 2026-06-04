# ATDR External IAM Groundwork

## Status

ATDR currently uses local JWT authentication with `admin` and `analyst` roles. External school-email login is planned as a future OIDC integration, but it is disabled by default and no OAuth/OIDC redirect or callback flow is active yet.

This plan keeps the current local workflow intact:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
cd frontend
npm.cmd run dev
```

## Current Groundwork

The backend supports configuration placeholders only:

```env
OIDC_ENABLED=false
OIDC_PROVIDER_NAME=""
OIDC_CLIENT_ID=""
OIDC_CLIENT_SECRET=""
OIDC_ISSUER_URL=""
OIDC_ALLOWED_DOMAINS=""
OIDC_DEFAULT_ROLE="analyst"
SCHOOL_EMAIL_DOMAINS=""
REQUIRE_SCHOOL_EMAIL=false
LOCAL_EMAIL_LOGIN_ENABLED=true
SMTP_ENABLED=false
SMTP_HOST=""
SMTP_PORT=587
SMTP_USERNAME=""
SMTP_PASSWORD=""
SMTP_FROM_EMAIL=""
```

The safe status endpoint is:

```text
GET /api/auth/oidc/status
```

It requires an authenticated `admin` or `analyst` user and returns only non-secret values:

- enabled
- provider_name
- issuer_configured
- client_configured
- allowed_domains
- default_role
- mode
- school_email_domains
- require_school_email
- local_email_login_enabled
- smtp_enabled

It does not expose `OIDC_CLIENT_SECRET`.

## Local School-Email Accounts

v0.4 adds local account fields for a more realistic school/lab IAM experience:

- email
- email_verified
- auth_provider
- external_subject
- last_login_at
- invited_at
- disabled_at

Local users can still sign in with username and password. If `LOCAL_EMAIL_LOGIN_ENABLED=true`, local users can also sign in with their email address. `REQUIRE_SCHOOL_EMAIL=false` by default so class demos and local testing are not blocked. If `REQUIRE_SCHOOL_EMAIL=true`, new or updated user emails must match `SCHOOL_EMAIL_DOMAINS`.

`auth_provider=external` is only a placeholder for future OIDC mapping. External users do not gain a working external-login flow until the OIDC provider details and callback implementation are added.

## Invitation And SMTP Groundwork

SMTP settings are placeholders only. ATDR does not send invite or reset emails by default.

Future invite/reset email work should require:

- `SMTP_ENABLED=true`
- approved SMTP host and sender address
- secret handling outside Git
- audit entries for invite/reset events
- rate limiting and token expiry

## Recommended Future Provider Strategy

Use generic OIDC first so ATDR can support one of these later without changing the product model:

- Google Workspace school accounts
- Microsoft Entra ID
- university-provided OIDC provider

Full login implementation should wait until these details are known:

- provider issuer URL
- redirect/callback URL
- client ID
- client secret
- allowed email domains
- role mapping policy
- account provisioning policy
- sign-out/session policy

## Safety Rules

- Local username/password login remains the default.
- OIDC is disabled unless `OIDC_ENABLED=true`.
- Do not commit `.env` or provider secrets.
- Do not grant `admin` by default from external login.
- Use `OIDC_DEFAULT_ROLE=analyst` unless a formal role-mapping policy exists.
- Response actions remain simulated and analyst-approved.
- External IAM does not enable automatic response or real firewall blocking.

## Remaining Work

- Implement OIDC discovery and token validation.
- Add `/api/auth/oidc/login` and callback routes.
- Add frontend login button only when OIDC is configured.
- Enforce allowed email domains.
- Map school identities to ATDR roles.
- Map verified email from the external provider to the local user record.
- Add audit events for external login attempts.
- Add integration tests with a mock OIDC provider.
