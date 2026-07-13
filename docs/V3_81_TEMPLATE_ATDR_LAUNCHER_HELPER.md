# v3.81 Template ATDR Launcher Helper

Date: 2026-07-11

## Summary

v3.81 adds a safe helper that can patch the official supervisor template registry page with an **Open ATDR SOC Dashboard** launcher.

The helper defaults to dry-run mode. It does not modify the template unless `--write` is explicitly passed.

## Why This Exists

The target architecture is:

1. user logs into the official supervisor template
2. template handles school email, account lifecycle, 2FA/OTP, and permission matrix
3. template opens ATDR as the SOC module
4. ATDR receives the template session material through the v3.79 handoff receiver
5. ATDR validates through `POST /api/auth/mfu-iam/token-login`

v3.80 proved the source-level contract exists. v3.81 makes the template-side launch step practical.

## New Command

Dry-run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.apply_template_atdr_launcher --pretty
```

Apply to the official template copy:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.apply_template_atdr_launcher --write --pretty
```

The write mode creates a backup file beside the changed Vue file unless `--no-backup` is passed.

## What The Patch Adds

The helper targets:

```text
C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\frontend-vue\src\projects\views\mfuaidrivenlogbasedthreatdetectionandresponse\MFUAIDRIVENLOGBASEDTHREATDETECTIONANDRESPONSERegistry.vue
```

It adds:

- an `Open ATDR SOC Dashboard` button
- a safe token lookup from Vuex `XAccessToken` or browser `x-access-token`
- a redirect to the ATDR handoff receiver:

```text
http://127.0.0.1:5173/login?mfu_token=<template-token>&next=/assistant&source=template-shell
```

## Template Env Hint

For local template frontend testing, add this to the template frontend env file:

```text
VUE_APP_ATDR_DASHBOARD_URL=http://127.0.0.1:5173
```

Do not commit real env files or secrets.

## Safety Notes

- The helper does not read or print token values.
- Dry-run is the default.
- Write mode creates a backup.
- ATDR still clears token-like values from its URL after receiving them.
- This is acceptable for controlled local validation.
- For production-like deployment, a short-lived server-side handoff code is still preferred over a long bearer token in a URL.

## Current Dry-Run Result

Current dry-run against the official template path:

```text
ok: true
target_exists: true
would_change: true
changed: false
secrets_exposed: false
```

This means the helper can patch the current template copy when `--write` is explicitly used.

## Verification

Commands run:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.apply_template_atdr_launcher --pretty
.\.venv\Scripts\python.exe -m pytest atdr\tests\test_template_atdr_launcher.py -q --basetemp .pytest_tmp\template-launcher -p no:cacheprovider
.\.venv\Scripts\ruff.exe check atdr\scripts\apply_template_atdr_launcher.py atdr\tests\test_template_atdr_launcher.py
```

Results:

```text
dry-run: ok true
tests: 3 passed
ruff: passed
```
