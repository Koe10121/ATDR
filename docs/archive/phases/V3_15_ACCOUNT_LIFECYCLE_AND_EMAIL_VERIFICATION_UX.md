# v3.15 Account Lifecycle And Email Verification UX Hardening

## Status

v3.15 hardens the local account lifecycle and school-email verification user experience. It keeps the v3.14 safety boundary: no real SMTP delivery, no OAuth/OIDC/SSO login, no automatic response, no real firewall blocking, no ML activation, and no production-readiness claim.

Normal startup remains unchanged:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
cd frontend
npm.cmd run dev
```

## What Changed

- Added status-only configuration flags:
  - `EMAIL_VERIFICATION_REQUIRED_FOR_LOGIN=false`
  - `EMAIL_VERIFICATION_REQUIRED_FOR_ADMIN_ACTIONS=false`
- Exposed those flags through the authenticated email status endpoint without enforcing them.
- Expanded the safe email status payload with school-domain and local-email-login policy status.
- Added compact account email verification status to the dashboard header.
- Improved Admin / User Admin lifecycle visibility:
  - active users
  - verified email count
  - email verified/unverified badges
  - account status
  - last login
  - local email login policy
  - verification requirement status
  - allowed school domains
- Disabled the `Send verification` button when email verification is disabled.
- Kept the dev email outbox hidden unless `EMAIL_DELIVERY_MODE=dev_outbox`.

## Safety Behavior

- Email verification is optional by default.
- Verification-required flags are status-only in v3.15 and do not block login or admin actions.
- Admin-triggered verification remains disabled unless `EMAIL_VERIFICATION_ENABLED=true`.
- Real SMTP remains future work.
- OIDC/SSO school login remains future work.
- API secrets are never returned by status endpoints.

## Manual Dashboard Test

1. Start backend and frontend normally.
2. Login as admin.
3. Confirm the dashboard header shows the current account and an email status badge.
4. Open Admin / User Admin.
5. Confirm Account Notifications shows:
   - Verification disabled by default
   - Delivery Mode: Disabled
   - Login Requirement: Not required
   - Admin Action Requirement: Not required
   - SMTP: Not configured
6. Confirm `Send verification` is visible but disabled while verification is disabled.
7. Confirm dev outbox is hidden unless `EMAIL_DELIVERY_MODE=dev_outbox`.

## Future Work

- Real SMTP delivery after provider, sender, secret handling, and audit policy are approved.
- School OIDC/SSO after issuer URL, client ID/secret, redirect URI, allowed domains, and role mapping are known.
- Optional enforcement of verified email for login/admin actions only after a migration and operator communication plan.
