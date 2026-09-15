# v3.64 MFU IAM Template Adapter

## Status

Implemented as safe groundwork. ATDR can now read the supervisor template IAM environment variable names and report non-secret readiness in the Admin dashboard. Real external school-email login is still disabled by default.

## What Changed

- ATDR settings now accept supervisor template aliases such as `IAM_SDK_*`, `IAM_ADMIN_*`, and `PROJECT_PERMISSION_*`.
- `GET /api/auth/mfu-iam/status` reports:
  - B2B client readiness
  - admin API readiness
  - permission bootstrap readiness
  - 2FA policy flag from the template
  - domain hints from configured project emails
  - configured/not-configured booleans for secrets
- The React Admin page now has a compact **MFU IAM Adapter** readiness panel.
- `.env.example` and `.env.lab.example` include safe placeholders for the additional MFU IAM fields.

## What Is Still Disabled

- No real MFU IAM login is enabled automatically.
- No Google/MFU Mail login callback is enabled.
- No real SMTP/OTP login enforcement is enabled.
- No external network call is made by the normal dashboard startup.
- No admin role is granted from a school email automatically.

## Supervisor Template Evidence Used

- `backend-node/.env.local`, `.env.preprod`, `.env.prod`
- `backend-node/server/integrations/iam/iam-sdk-adapter.js`
- `backend-node/server/integrations/iam/b2b-auth-middleware.js`
- `backend-node/server/integrations/iam/project-iam-service.js`
- `frontend-vue/src/projects/components/dialog/SignIn.vue`
- `frontend-vue/src/projects/components/dialog/TwoFA.vue`
- `backend-node/docs/IAM_SYSTEM_OVERVIEW.md`

Secret values from the template are not copied into ATDR docs or source code.

## Manual Test

1. Keep normal local workflow:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
cd frontend
npm.cmd run dev
```

2. Log in as admin.
3. Open `Admin`.
4. Check **MFU IAM Adapter**.
5. Confirm:
   - local login remains active
   - secrets show as hidden
   - B2B/Admin/Permission readiness reflects the local `.env`

## Security Notes

- Keep `.env` private.
- The pasted/template admin client secret should be treated as sensitive and rotated before any shared/preprod/prod use.
- Real school-email login requires an approved callback flow, token validation policy, role mapping, and audit review.
