# ATDR School Email IAM Readiness Audit

Date: 2026-06-21

This audit answers one question: can ATDR safely connect to school email / MFU IAM right now?

Short answer: not yet. ATDR has the local account, email metadata, verification foundation, and disabled external-IAM placeholders needed to prepare for integration. The supervisor template provides useful IAM patterns. But ATDR still lacks approved provider details, client registration, redirect URLs, role mapping, and security policy needed for real external login.

## Current ATDR IAM State

| Area | Current State | Evidence |
| --- | --- | --- |
| Local login | Username/password and email/password login supported through local JWT auth | `atdr/app/routers/auth.py`, `atdr/app/core/security.py` |
| Roles | `admin` and `analyst` supported; viewer is future work | `atdr/app/core/security.py`, `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| User admin | Admin can manage users and account/email fields | `atdr/app/routers/users.py`, `frontend/src/pages/UserAdmin.tsx` |
| Email verification foundation | Disabled by default; dev/log outbox only when configured | `atdr/app/services/account_verification_service.py`, `atdr/app/services/email_service.py` |
| OIDC status | Non-secret status endpoint exists, disabled by default | `atdr/app/routers/auth.py`, `atdr/app/core/config.py` |
| MFU IAM status | Non-secret status endpoint exists, disabled by default | `atdr/app/routers/auth.py`, `atdr/app/core/config.py` |
| Response safety | IAM cannot enable automatic response; response remains simulated/manual | `atdr/app/services/response_service.py`, `atdr/tests/test_response_safety.py` |

## Supervisor Template IAM Information Found

| Supervisor IAM Topic | What Exists In Template | ATDR Relevance |
| --- | --- | --- |
| MFU/IAM SDK adapter | IAM adapter/service files and IAM SDK docs exist | Useful as architecture reference, not directly imported into FastAPI |
| Google / MFU Mail sign-in | Vue sign-in component shows Google ID token flow | Useful for future frontend login UX and callback/token validation planning |
| Email OTP / 2FA | Vue TwoFA component and IAM PRD describe OTP/trusted-device concepts | Maps to future ATDR verification/2FA work |
| Permission matrix | Template uses path/action permissions, groups, assignments, data scopes | Maps to future ATDR permission path registry and possible fine-grained RBAC |
| B2B token introspection | Middleware pattern exists for token introspection, audience, scopes | Future only; not needed for current ATDR local lab |
| Audit expectations | IAM docs require audit for auth, permission, and account actions | ATDR already audits key local actions and should extend audit if external IAM is added |
| Security recommendations | Rate limiting, secret handling, HTTPS, audit integrity, bootstrap controls | Useful for production-readiness backlog |

No template `.env` secret values should be copied into ATDR.

## What Is Enough To Use Now

The template is enough for:

- Writing an ATDR-specific IAM adapter plan.
- Listing provider questions for the advisor.
- Adding non-secret config/status placeholders.
- Designing a future school-email login UX.
- Designing future admin/analyst/viewer group mappings.
- Writing tests that prove external IAM remains disabled by default.
- Keeping local login working while external IAM is planned.

## What Is Missing Before Real School Email Login

| Missing Item | Why It Blocks Implementation |
| --- | --- |
| Approved provider choice | ATDR must know whether to integrate MFU IAM SDK, Google Workspace, generic OIDC, or both. |
| Issuer/base URL and metadata | Token validation cannot be implemented safely without the approved issuer or IAM base URL. |
| Client ID | The school/provider must register ATDR as an app/client. |
| Client secret delivery method | Secrets must come from `.env` or a secret manager, never committed to Git. |
| Redirect/callback URLs | OAuth/OIDC/Google flows require exact approved URLs for local, preprod, and future deployment. |
| Allowed domains | ATDR needs official student/staff email domain policy. |
| Group/role mapping | ATDR needs to know which school IAM groups map to `admin`, `analyst`, and any future `viewer`. |
| Auto-provision policy | ATDR needs rules for creating local users from external identities and default role assignment. |
| Token validation contract | ATDR needs JWKS/introspection, audience, issuer, expiry, and scope rules. |
| 2FA/OTP policy | ATDR needs to know whether the school provider handles 2FA or ATDR should enforce its own email OTP. |
| Audit and retention policy | External identity events may require special audit retention/privacy handling. |
| Approval for external network calls | Current ATDR does not call external IAM providers by default. |

## Recommended Safe Adapter Shape

| Layer | Recommended Direction |
| --- | --- |
| Backend config | Keep `MFU_IAM_ENABLED=false`, `GOOGLE_SSO_ENABLED=false`, and `OIDC_ENABLED=false` by default. |
| Status endpoints | Continue exposing only non-secret status values and `secrets_exposed=false`. |
| Login integration | Future implementation should add a provider callback/token verification path only after provider details are known. |
| User mapping | Match external identity to local user by verified email and stable provider subject. |
| Role mapping | Default to `analyst`; never auto-create `admin` without approved group mapping. |
| Account lifecycle | Keep local admin override, but record external source and audit every provisioning/update event. |
| 2FA | Prefer provider-managed 2FA if available; otherwise extend ATDR email verification foundation carefully. |
| Audit | Audit external login success/failure, role mapping, provisioning, verification, and admin overrides. |
| Safety | External IAM must not affect ML activation, response automation, or real firewall blocking. |

## Go / No-Go Decision

Current decision: no-go for real school-email external login until provider details are confirmed.

Safe work that can continue now:

- Improve local account UX.
- Improve docs and provider checklist.
- Add mocked-provider tests later.
- Keep disabled config/status groundwork.
- Prepare a T1-T20 change plan for external IAM implementation.

Unsafe work to avoid now:

- Enabling Google/MFU/OIDC login with guessed provider URLs.
- Copying template secrets.
- Auto-assigning admin roles from email domain alone.
- Making external network calls in default local workflow.
- Blocking existing local users with new verification requirements by surprise.

## Advisor Questions To Resolve

Use `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md` as the canonical question list. Minimum questions before implementation:

1. Should ATDR use MFU IAM SDK, Google Workspace, generic OIDC, or both?
2. What are the approved issuer/base URL and metadata endpoints?
3. What client ID and redirect URLs are approved for local/lab testing?
4. How will secrets be delivered securely?
5. Which school email domains are allowed?
6. Which IAM groups map to ATDR admin/analyst/viewer?
7. Is provider-managed 2FA required or should ATDR implement OTP?
8. What audit retention and privacy rules apply?

