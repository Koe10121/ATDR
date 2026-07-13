# ATDR MFU IAM Preproduction Validation

## Purpose

This checklist validates the v3.91 secure outer-shell handoff in an approved MFU preproduction environment. It does not authorize production deployment, automatic response, or real firewall blocking.

## Current Template Configuration Evidence

The official template source supports end-user email/password and Google sign-in, email OTP/2FA, IAM-backed permissions, and B2B token introspection. Its Node configuration also contains the v3.91 `ATDR_HANDOFF_*` integration surface.

As of the v3.91 source audit, the checked template environment files are **not sufficient for a live preproduction handoff**:

- The preproduction and production direct IAM SDK client-secret entries are placeholders, not approved deployed credentials.
- Google client configuration is absent, so Google/MFU Mail sign-in cannot be assumed to work.
- The template backend private environment files do not yet define `ATDR_HANDOFF_*` settings.
- The template frontend private environment files do not yet define `VUE_APP_ATDR_HANDOFF_*` settings.

Only variable names and configured/placeholder state were inspected; no secret value is recorded here. The template owner or MFU IAM administrator must provide the approved values through a secret-management channel before any live validation.

## Required Provider Inputs

Obtain these from the authorized MFU IAM/template owner without committing them:

- Exact template frontend and backend preproduction origins.
- Approved school-email domains.
- Approved ATDR application/registry route and callback/consume URL.
- An approved ATDR admin-group identifier or written policy that all school users remain analysts.
- A fresh bridge secret shared only between the template backend and ATDR backend.
- 2FA, session expiry, logout, recovery, and deprovisioning policy.
- Confirmation that the template account email and group values are authoritative for ATDR.

## Configuration Rules

- Configure the same bridge secret in both services only through private environment management.
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
| Invalid or expired code | Generic failure only; no code, secret, or account data is returned. |
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

## Stop Conditions

Stop and rollback to local ATDR login if any of the following occur:

- The template returns a 404, sign-in failure, or an unverified user identity.
- The bridge secret appears in logs, browser tools, API output, or Git status.
- A session code is reusable or long-lived.
- Role mapping grants admin without an approved IAM group.
- The preproduction site lacks HTTPS or uses permissive CORS/origin policy.

## Rollback

Set `MFU_IAM_HANDOFF_ENABLED=false` in ATDR and `ATDR_HANDOFF_ENABLED=false` in the template, then restart both services. Local ATDR credentials remain available. No ATDR database reset is required.

## v3.96 Environment Finding

The private local profile inspected on 2026-07-13 had MFU IAM enabled while neither a complete B2B profile nor the secure handoff was ready. This is a fail-closed configuration finding, not successful provider validation. For ordinary local SQLite use, override `MFU_IAM_ENABLED=false`. For preproduction, configure the approved v3.91 one-time-code handoff privately and require `run_v396_preproduction_preflight --require-accepted` to pass. Do not copy any credential value into this document or a support message.
