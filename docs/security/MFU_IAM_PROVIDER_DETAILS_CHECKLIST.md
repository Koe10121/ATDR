# MFU IAM Provider Details Checklist

Use this checklist before implementing real external school-email IAM in ATDR. Do not enable real OAuth/OIDC/Google/MFU IAM login until these questions are answered and approved.

## Provider Choice

| Question | Answer / Owner |
| --- | --- |
| Should ATDR use the MFU IAM SDK/service, Google Workspace, generic OIDC, or both? | TBD |
| Is there an approved preprod/sandbox IAM environment for student projects? | TBD |
| Can ATDR student developers access the preprod IAM environment? | TBD |
| Is the supervisor NewSystem template IAM code a required runtime dependency or only a reference implementation? | TBD |

## Endpoints And Metadata

| Question | Answer / Owner |
| --- | --- |
| What is the approved issuer URL or base URL? | TBD |
| What is the authorization endpoint? | TBD |
| What is the token endpoint? | TBD |
| What is the userinfo/profile endpoint? | TBD |
| Is token introspection available? If yes, what endpoint should be used? | TBD |
| Is logout/session revocation required? | TBD |
| What token algorithms and JWKS endpoint should be trusted? | TBD |

## Client Registration

| Question | Answer / Owner |
| --- | --- |
| What client ID should ATDR use for local development? | TBD |
| What client ID should ATDR use for preprod/shared lab? | TBD |
| How will client secrets be delivered securely? | TBD |
| Where should secrets be stored for lab use? | TBD |
| What are the approved redirect/callback URLs for local development? | TBD |
| What are the approved redirect/callback URLs for shared lab/preprod? | TBD |
| Are PKCE and refresh tokens required? | TBD |

## Domains And User Mapping

| Question | Answer / Owner |
| --- | --- |
| Which email domains are allowed? | TBD |
| Are both student and staff domains allowed? | TBD |
| Which email claim should ATDR trust? | TBD |
| Is email verification guaranteed by the provider? | TBD |
| Which external subject claim should be stored in `User.external_subject`? | TBD |
| Should ATDR auto-create local users after first external login? | TBD |
| If auto-create is allowed, what default role should be assigned? | Recommended default: `analyst` |

## Role And Permission Mapping

| Question | Answer / Owner |
| --- | --- |
| Which IAM group maps to ATDR `admin`? | TBD |
| Which IAM group maps to ATDR `analyst`? | TBD |
| Is a future read-only/viewer role required? | TBD |
| Should data scopes such as `self`, `unit`, and `org` be enforced in ATDR? | TBD |
| Should ATDR register permission paths with MFU IAM? | TBD |
| Who approves admin access? | TBD |

## OTP / 2FA / Email

| Question | Answer / Owner |
| --- | --- |
| Does the provider already enforce 2FA? | TBD |
| Should ATDR implement its own email OTP/2FA, or rely on the provider? | TBD |
| Is SMTP allowed for student project use? | TBD |
| What sender address should be used for OTP/invite emails? | TBD |
| What rate limits and lockout policy are required for OTP? | TBD |
| What recovery process exists if a user loses access? | TBD |

## B2B Token Introspection

| Question | Answer / Owner |
| --- | --- |
| Does ATDR need B2B/service-token access in this project phase? | TBD |
| What audience should ATDR require for service tokens? | TBD |
| What scopes should map to ATDR API actions? | TBD |
| How should token introspection failures be logged? | TBD |
| What timeout and retry policy is approved? | TBD |

## Audit, Privacy, And Operations

| Question | Answer / Owner |
| --- | --- |
| What IAM login events must ATDR audit? | TBD |
| What failed-login and permission-denial events must ATDR audit? | TBD |
| What audit retention policy applies? | TBD |
| Are IP addresses or raw logs allowed in IAM/audit payloads? | TBD |
| What incident response process applies if IAM is unavailable? | TBD |
| Is local username/password fallback allowed when external IAM is enabled? | TBD |

## Implementation Approval Gate

Before real implementation starts, the T1-T20 change record must include:

- Confirmed provider choice.
- Confirmed endpoints and client registration.
- Secret-management plan.
- Role/group mapping.
- Callback URL approval.
- Mock provider tests.
- Security review.
- Rollback plan.

