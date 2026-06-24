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
EMAIL_NOTIFICATIONS_ENABLED=false
EMAIL_VERIFICATION_ENABLED=false
EMAIL_DELIVERY_MODE="disabled"
SMTP_ENABLED=false
SMTP_HOST=""
SMTP_PORT=587
SMTP_USERNAME=""
SMTP_PASSWORD=""
SMTP_FROM_EMAIL=""
SMTP_USE_TLS=true
EMAIL_VERIFICATION_CODE_TTL_MINUTES=15
EMAIL_VERIFICATION_CODE_LENGTH=6
EMAIL_VERIFICATION_REQUIRED_FOR_LOGIN=false
EMAIL_VERIFICATION_REQUIRED_FOR_ADMIN_ACTIONS=false
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
- email verification enabled
- email notification delivery mode
- dev outbox availability
- verification-required policy flags

It does not expose `OIDC_CLIENT_SECRET`, `SMTP_PASSWORD`, or any assistant/email provider secret.

## MFU IAM / Google SSO Adapter Groundwork

The supervisor NewSystem template includes MFU IAM service integration, Google/MFU Mail login, OTP/2FA, account invites, permission-matrix concepts, and B2B token introspection. ATDR does not copy the NewSystem runtime stack, but it now documents a safe ATDR-specific adapter path:

- `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md`
- `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md`

ATDR also exposes a non-secret authenticated status endpoint:

```text
GET /api/auth/mfu-iam/status
```

It reports only configured/not-configured booleans, allowed domains, default role, Google SSO enabled state, and `secrets_exposed=false`. It does not perform external network calls and does not return `MFU_IAM_CLIENT_SECRET`, `GOOGLE_CLIENT_ID`, or `.env` values.

Disabled-by-default placeholder settings:

```env
MFU_IAM_ENABLED=false
MFU_IAM_BASE_URL=""
MFU_IAM_CLIENT_ID=""
MFU_IAM_CLIENT_SECRET=""
MFU_IAM_AUDIENCE=""
MFU_IAM_ALLOWED_DOMAINS=""
MFU_IAM_DEFAULT_ROLE="analyst"
GOOGLE_SSO_ENABLED=false
GOOGLE_CLIENT_ID=""
```

Real MFU IAM, Google SSO, OAuth/OIDC callback login, token introspection, or OTP/2FA enforcement must wait until the provider details checklist is answered and an approved T1-T20 change record exists.

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

## Email Verification And Notification Groundwork

v3.14 adds local-account email verification groundwork. It is disabled by default and does not send real email.

Current safe endpoints:

- `GET /api/auth/email/status`
- `POST /api/auth/email/request-verification`
- `POST /api/auth/email/verify`
- `POST /api/users/{id}/send-verification`
- `GET /api/users/dev-email-outbox`

The implementation stores verification codes as hashes in `account_email_verification_tokens`. Plaintext codes are visible only in explicit `EMAIL_DELIVERY_MODE=dev_outbox` mode for local admin testing. `email_notification_events` records local/dev notification attempts. SMTP production delivery remains future work.

v3.15 adds account lifecycle and verification UX hardening. `EMAIL_VERIFICATION_REQUIRED_FOR_LOGIN` and `EMAIL_VERIFICATION_REQUIRED_FOR_ADMIN_ACTIONS` are status-only, disabled by default, and do not block login or admin actions. Enforcement is future work because it needs a rollout plan that avoids locking out existing users.

Future invite/reset email work should require:

- approved SMTP host and sender address
- secret handling outside Git
- real SMTP send implementation and tests
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
- Email verification is disabled unless `EMAIL_VERIFICATION_ENABLED=true`.
- Verification-required policy flags remain false by default and are not enforced in v3.15.
- Real email delivery is disabled unless a future SMTP implementation is explicitly approved.
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
- Add real SMTP delivery only after a mail provider, secret-management policy, rate limiting, and abuse controls are approved.
