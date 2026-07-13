# v3.79 Template-to-ATDR Handoff Receiver

Date: 2026-07-11

## Summary

v3.79 adds the ATDR-side frontend receiver for the supervisor template shell handoff.

The supervisor template remains the intended outer application shell and school-email IAM gateway. ATDR remains the SOC module. This phase does not enable real MFU IAM by default; it makes ATDR ready to receive a token or one-time-code style handoff when the template/provider flow is configured.

## What Changed

The ATDR React login page now detects explicit shell handoff URL parameters:

- `mfu_token`
- `iam_token`
- `handoff_token`
- `atdr_handoff_token`
- `x_access_token`
- `access_token`
- `token`
- `handoff_code`
- `atdr_handoff_code`
- `code`

The token/code may be in the query string or URL fragment. Optional redirect targets are accepted only when they are same-app paths:

- `next`
- `redirect`
- `return_to`
- `returnTo`

Unsafe redirect targets are ignored.

## Runtime Behavior

When ATDR opens `/login` with a handoff token or code:

1. ATDR fetches the public MFU IAM status.
2. ATDR immediately clears token-like URL values from the browser address bar.
3. If MFU IAM token login is not ready, ATDR shows a clear fallback message and keeps local login available.
4. If MFU IAM token login is ready, ATDR calls:

```text
POST /api/auth/mfu-iam/token-login
```

5. On success, ATDR stores the normal ATDR session token and opens the requested safe path or `/overview`.
6. On failure, ATDR shows a clean error and keeps local login available.

## What Did Not Change

- Local username/password login remains available.
- The normal backend/frontend startup commands are unchanged.
- No database schema changed.
- No external IAM login is enabled by default.
- No template secrets or `.env` values are committed.
- No response automation is enabled.
- No real firewall blocking is enabled.
- The SOC Assistant remains read-only.
- The LLM provider remains controlled by private `.env` configuration.

## Safety Notes

The handoff receiver never displays the handoff token/code. It clears token-like URL values before continuing, so screen sharing or browser history is less likely to expose sensitive values.

The backend still owns actual validation through `POST /api/auth/mfu-iam/token-login`. In live mode that endpoint must validate the token against the MFU IAM provider. In local mock mode it may accept mock tokens only when explicitly configured.

## Manual Test

With MFU IAM mock mode configured in private `.env`, a local test URL can look like:

```text
http://127.0.0.1:5173/login?mfu_token=mock:student@lamduan.mfu.ac.th&next=/assistant&source=template-shell
```

Expected behavior:

- URL is cleaned after the handoff attempt.
- ATDR logs in through the MFU token-login endpoint if mock/live IAM is ready.
- ATDR opens `/assistant`.
- If IAM is not ready, ATDR remains on `/login` and local login still works.

Do not use real provider tokens in shared screenshots, docs, Git commits, or chat.

## Remaining Work

The handoff receiver is ready, but complete school-email IAM still requires:

- exact token type from the supervisor shell
- approved local/preprod/prod callback URLs
- confirmed allowed domains
- approved admin/analyst group-role mapping
- live provider validation using private `.env`
- optional same-domain reverse proxy integration
- advisor/provider decision on whether the template backend or ATDR backend performs token exchange

## Verification

This phase adds Playwright coverage for:

- successful template handoff
- token-login call with the handoff token
- URL token cleanup
- disabled-IAM fallback without calling token-login
- local login availability after fallback

Full verification should include:

```powershell
node scripts/render-tasklist-progress-html.js .
node scripts/check-tasklist-progress-standard.js .
cd frontend
npm.cmd run lint
npm.cmd run build
npm.cmd run test:e2e
cd ..
.\.venv\Scripts\python.exe -m atdr.scripts.config_doctor --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release
```
