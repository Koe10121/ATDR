# v3.14 Email Verification And Account Notification Foundation

## Status

v3.14 adds safe local-account email verification groundwork for ATDR. It does not add OAuth, OIDC login, SSO, SMTP production email, real firewall blocking, automatic response, or ML promotion.

Normal local startup remains unchanged:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
cd frontend
npm.cmd run dev
```

## What Changed

- Added disabled-by-default email notification and verification settings in `.env.example` and `.env.lab.example`.
- Added `account_email_verification_tokens` for hashed verification codes.
- Added `email_notification_events` as a safe local/dev notification outbox.
- Added read-only status endpoint: `GET /api/auth/email/status`.
- Added authenticated self-service endpoints:
  - `POST /api/auth/email/request-verification`
  - `POST /api/auth/email/verify`
- Added admin endpoints:
  - `POST /api/users/{id}/send-verification`
  - `GET /api/users/dev-email-outbox`
- Updated User Admin to show email verification status, delivery mode, SMTP configured/not configured, and Send verification actions.

## Safety Defaults

Default local settings:

```env
EMAIL_NOTIFICATIONS_ENABLED=false
EMAIL_VERIFICATION_ENABLED=false
EMAIL_DELIVERY_MODE="disabled"
SMTP_HOST=""
SMTP_PASSWORD=""
```

With these defaults, ATDR does not create verification tokens and does not send email. Local username/password login and optional email login remain unchanged.

## Dev Outbox Mode

For local testing only, a developer can use:

```env
EMAIL_NOTIFICATIONS_ENABLED=true
EMAIL_VERIFICATION_ENABLED=true
EMAIL_DELIVERY_MODE="dev_outbox"
```

In dev outbox mode, verification codes are stored in the admin-only dashboard outbox. No real email is sent. The outbox is for local lab testing and must not be treated as production email delivery.

## Token Handling

- Verification codes are random numeric codes.
- Codes are hashed before storage in `account_email_verification_tokens`.
- Plaintext codes are only visible in `dev_outbox` mode for local testing.
- Tokens expire according to `EMAIL_VERIFICATION_CODE_TTL_MINUTES`.
- Used, expired, missing, and invalid tokens are handled cleanly and audited.

## Auditing

ATDR records audit events for:

- verification request skipped because verification is disabled
- verification requested
- notification event recorded
- verification code generated in log-only mode
- verification failures
- successful email verification

## Current Limitations

- Real SMTP sending is not implemented in v3.14.
- Full external OIDC/SSO school-email login is not implemented.
- Email verification does not block login by default.
- No password reset email workflow is implemented.
- No production IAM claim is made.

## Manual Test

1. Start backend and frontend normally.
2. Login as admin.
3. Open Admin / User Admin.
4. Confirm Account Notifications shows `Verification disabled` and `Delivery Mode: Disabled`.
5. Create or edit a user with an email address.
6. Confirm email status appears in the users table.
7. Optionally enable dev outbox in local `.env`, restart backend, and trigger Send verification for a user.
8. Confirm the dev outbox shows a local verification code and no SMTP secret is displayed.

## Verification Scope

v3.14 should be verified with backend tests, Alembic check, React lint/build/Playwright, replay dry-run, performance smoke, and release gate. This is an account-notification foundation only; response automation and real firewall blocking remain disabled.
