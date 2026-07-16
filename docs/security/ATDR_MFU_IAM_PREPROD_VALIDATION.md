# ATDR MFU IAM Preproduction Validation

## Purpose

This checklist validates the v3.91 secure outer-shell handoff, composed locally through the v4.3 portable runtime, in an approved MFU preproduction environment. It does not authorize production deployment, automatic response, or real firewall blocking.

## Current Template Configuration Evidence

The official template source supports end-user email/password and Google sign-in, email OTP/2FA, IAM-backed permissions, and B2B token introspection. Its Node configuration also contains the v3.91 `ATDR_HANDOFF_*` integration surface.

The current source and private-local audit establishes the following without recording any value:

- The approved private local shell profile contains non-placeholder IAM proxy/admin field names required by the scoped sign-in implementation.
- Environment-specific `VUE_APP_CLIENTID` and `GOOGLE_CLIENT_ID` are blank. v4.4 removed the legacy source fallback, so setup/start now fail closed until one approved OAuth Web client is configured identically in both private files.
- v4.3 injects local `ATDR_HANDOFF_*` settings into shell child processes from ignored ATDR configuration, so those values are neither committed nor copied into the external shell.
- Preproduction and production provider credentials, callbacks, Google client approval, and account/group assignments have not been independently accepted by this ATDR verification pass.

Only variable names and configured/placeholder state were inspected; no secret value is recorded here. `check_system.cmd` reports provider configuration separately from provider acceptance. The template owner or MFU IAM administrator must approve the Google client and assign test accounts to the project scope before live acceptance can pass.

## Required Provider Inputs

Obtain these from the authorized MFU IAM/template owner without committing them:

- Exact template frontend and backend preproduction origins.
- One approved Google OAuth Web client ID for the shell frontend and backend audience check.
- Approved school-email domains.
- Approved ATDR application/registry route and callback/consume URL.
- An approved ATDR admin-group identifier or written policy that all school users remain analysts.
- A fresh bridge secret shared only between the template backend and ATDR backend.
- 2FA, session expiry, logout, recovery, and deprovisioning policy.
- Confirmation that the template account email and group values are authoritative for ATDR.
- Confirmation that any IAM administrator credential previously disclosed outside the approved secret channel has been revoked and replaced.

## Configuration Rules

- Configure the same bridge secret in both services only through private environment management.
- Configure the same approved Google client ID as `VUE_APP_CLIENTID` and `GOOGLE_CLIENT_ID`; validate agreement with `template_auth_doctor` without displaying it.
- Authorize `http://localhost:8080` as the local JavaScript origin. Do not use `127.0.0.1` for the Google sign-in page.
- Use exact allowed origins; do not use `*`.
- Use HTTPS and `MFU_IAM_HANDOFF_COOKIE_SECURE=true` outside local development.
- Keep `MFU_IAM_HANDOFF_ALLOWED_RETURN_PATHS` to known React routes.
- Configure `MFU_IAM_ADMIN_GROUPS` only after group values are approved. Email address alone must not grant admin.
- Keep local account recovery separate and audited.

## Preproduction Test Cases

| Test | Expected Evidence |
| --- | --- |
| Existing approved school user opens ATDR from template | One single-use handoff succeeds, ATDR session cookie is HttpOnly, user enters `/overview` or requested allowed route. |
| Replay a consumed code | ATDR rejects it; no new user/session/action is created. |
| Invalid or expired code | Safe actionable failure code only; no code, secret, or account data is returned. |
| Unapproved origin | ATDR redirects safely and writes denied-handoff audit event. |
| Unapproved email domain | Template rejects before code issue; ATDR must not create an external user. |
| Default school user | Maps to ATDR `analyst`. |
| Approved admin group | Maps to ATDR `admin`; record the group identifier and approval evidence. |
| Matching local account email | Is rejected until explicitly linked; no privilege inheritance occurs. |
| Logout | ATDR cookie clears; template-session logout behavior follows template policy. |
| Assistant and response pages | Assistant remains read-only; response automation remains disabled; no real firewall call is possible. |

## Required Evidence

- `validate_template_shell_runtime --check-runtime --pretty` output with `secrets_exposed: false`.
- Template and ATDR service health checks.
- A redacted audit record for successful and denied handoff.
- Screenshot or browser evidence that no credential is present in the URL.
- Role mapping test evidence for analyst and, if approved, admin group mapping.
- Security review sign-off for allowed origins, cookie mode, and secret rotation.
- Rotation evidence for any previously exposed administrator credential; never include the old or replacement value in the evidence pack.

## Stop Conditions

Stop and rollback to local ATDR login if any of the following occur:

- The template returns a 404, sign-in failure, or an unverified user identity.
- The bridge secret appears in logs, browser tools, API output, or Git status.
- A session code is reusable or long-lived.
- Role mapping grants admin without an approved IAM group.
- The preproduction site lacks HTTPS or uses permissive CORS/origin policy.

## Local Team Runtime Versus Provider Acceptance

The v4.4 lifecycle validates matching Google client configuration before the four local services can start through `setup_team.cmd`, `start_system.cmd`, and `check_system.cmd`. This proves the local shell contract, not external MFU provider acceptance. Provider-backed sign-in, 2FA, group-role mapping, recovery, and deprovisioning require the acceptance evidence in this document.

## Rollback

Stop the launcher-owned services. For an authorized recovery event only, select `ATDR_AUTH_MODE=local_recovery` in the private ATDR environment and start the ATDR components directly. Do not silently fall back from shell mode. No ATDR database reset is required.

## v3.96 Environment Finding

The private local profile inspected on 2026-07-13 had MFU IAM enabled while neither a complete B2B profile nor the secure handoff was ready. This is a fail-closed configuration finding, not successful provider validation. For ordinary local SQLite use, override `MFU_IAM_ENABLED=false`. For preproduction, configure the approved v3.91 one-time-code handoff privately and require `run_v396_preproduction_preflight --require-accepted` to pass. Do not copy any credential value into this document or a support message.
