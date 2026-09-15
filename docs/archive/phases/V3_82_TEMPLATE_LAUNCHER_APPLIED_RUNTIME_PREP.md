# v3.82 Template Launcher Applied And Runtime Prep

Date: 2026-07-11

## Summary

v3.82 applies the v3.81 launcher helper to the official supervisor template copy.

The template can now show an **Open ATDR SOC Dashboard** button on the authenticated project registry page. This moves the integration from planning/dry-run into a practical local runtime bridge while keeping ATDR unchanged as FastAPI + React + SQLAlchemy/Alembic.

## External Template Change

Changed external file:

```text
<MFU_SHELL_ROOT>\frontend-vue\src\projects\views\mfuaidrivenlogbasedthreatdetectionandresponse\MFUAIDRIVENLOGBASEDTHREATDETECTIONANDRESPONSERegistry.vue
```

Backup created:

```text
<MFU_SHELL_ROOT>\frontend-vue\src\projects\views\mfuaidrivenlogbasedthreatdetectionandresponse\MFUAIDRIVENLOGBASEDTHREATDETECTIONANDRESPONSERegistry.vue.bak-20260711T125345Z
```

The external template folder is not part of the ATDR Git repo. The backup file should stay outside ATDR and should not be committed.

## What Was Added To The Template

The authenticated registry page now includes:

- an `Open ATDR SOC Dashboard` button
- a `canOpenAtdr` computed value
- `getTemplateAccessToken()`
- `openAtdrSocDashboard()`
- default ATDR dashboard target:

```text
http://127.0.0.1:5173
```

The launcher reads the template login session from:

- Vuex `XAccessToken`, or
- browser `localStorage["x-access-token"]`

Then it opens:

```text
http://127.0.0.1:5173/login?mfu_token=<template-session-value>&next=/assistant&source=template-shell
```

ATDR receives that through the v3.79 handoff receiver, clears token-like values from the URL, and calls the backend token-login path only when MFU IAM is configured as ready.

## Safety Notes

- The helper did not print the token value.
- The patch does not contain hard-coded student emails.
- The patch does not contain API keys, client secrets, or `.env` values.
- Local ATDR login remains available.
- ATDR response automation remains disabled.
- Real firewall blocking remains disabled.
- SOC Assistant remains read-only.
- The production-like recommendation remains short-lived handoff code exchange instead of long bearer tokens in URLs.

## Runtime Test Steps

Start ATDR backend:

```powershell
cd <ATDR_ROOT>
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Start ATDR frontend:

```powershell
cd <ATDR_ROOT>\frontend
npm.cmd run dev
```

Start the supervisor template backend:

```powershell
cd <MFU_SHELL_ROOT>\backend-node
npm.cmd install
npm.cmd run start:local
```

Start the supervisor template frontend:

```powershell
cd <MFU_SHELL_ROOT>\frontend-vue
npm.cmd install
npm.cmd run serve:local
```

After template login succeeds:

1. open the project registry page
2. click **Open ATDR SOC Dashboard**
3. confirm ATDR opens `/assistant`
4. confirm the browser URL no longer contains `mfu_token`
5. confirm ATDR local fallback remains available if IAM is not ready

## Current Verification

Commands run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.apply_template_atdr_launcher --write --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.apply_template_atdr_launcher --pretty
Select-String ... -Pattern 'Open ATDR SOC Dashboard','openAtdrSocDashboard','VUE_APP_ATDR_DASHBOARD_URL','handoffValue','mfu_token'
```

Results:

```text
write: ok true, changed true, backup created
post-write dry-run: ok true, already_installed true, would_change false
markers present: Open ATDR SOC Dashboard, openAtdrSocDashboard, VUE_APP_ATDR_DASHBOARD_URL, handoffValue, mfu_token
secrets_exposed: false
```

## Remaining Work

The next step is live runtime validation:

- start the template backend/frontend
- complete template login and 2FA or mock login
- click the ATDR launcher
- verify ATDR accepts or cleanly rejects the handoff depending on MFU IAM readiness
- if the template token is not acceptable to ATDR, add a short-lived code exchange or provider-specific token adaptation after confirming the real token payload and provider behavior without exposing secrets
