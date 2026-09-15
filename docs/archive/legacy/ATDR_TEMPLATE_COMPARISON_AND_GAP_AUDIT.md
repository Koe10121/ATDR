# ATDR Supervisor Template Comparison And Gap Audit

Date: 2026-06-21

This audit compares the supervisor-provided project template at `<MFU_SHELL_ROOT>` with the current ATDR repository at `<ATDR_ROOT>`.

The template is a Node/Vue/MongoDB/IAM reference. ATDR remains a FastAPI + React + SQLAlchemy/Alembic defensive SOC prototype. This audit adapts process, security, IAM, and workflow expectations without migrating ATDR to the template stack.

## Source Evidence Reviewed

| Area | Evidence |
| --- | --- |
| Supervisor IAM PRD | `<MFU_SHELL_ROOT>\backend-node\docs\IAM_PRD.md` |
| Supervisor IAM architecture | `<MFU_SHELL_ROOT>\backend-node\docs\IAM_SYSTEM_OVERVIEW.md` |
| Supervisor IAM recommendations | `<MFU_SHELL_ROOT>\backend-node\docs\IAM_RECOMMENDATIONS.md` |
| Supervisor IAM adapter/source patterns | `backend-node/server/integrations/iam/*`, `backend-node/server/Project/security/*` in the supervisor template |
| Supervisor frontend IAM UI | `frontend-vue/src/projects/components/dialog/SignIn.vue`, `frontend-vue/src/projects/components/dialog/TwoFA.vue`, `frontend-vue/src/store/modules/Security/*` in the supervisor template |
| Archived supervisor workflow/change examples | `docs/reference/NewSystem/workflow/AI-WORKFLOW.md`, `docs/reference/NewSystem/workflow/T1-T20-change-document.md`, `docs/reference/NewSystem/workflow/agents/sprint-task-template.md` |
| Active ATDR progress-board process | `docs/tasks/tasklist-progress.md`, `scripts/render-tasklist-progress-html.js`, `scripts/check-tasklist-progress-standard.js` |
| ATDR runtime truth | `atdr/app/main.py`, `atdr/app/routers/*.py`, `atdr/app/core/security.py`, `atdr/app/core/config.py`, `atdr/app/db/models.py` |
| ATDR dashboard truth | `frontend/src/App.tsx`, `frontend/src/components/AppShell.tsx`, `frontend/src/pages/*`, `frontend/src/lib/api.ts` |
| ATDR governance truth | `docs/ATDR_AI_WORKFLOW.md`, `docs/prd/PRD-ATDR.md`, `docs/ATDR_REQUIREMENT_TRACEABILITY.md`, `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`, `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md` |

No supervisor `.env` secrets were copied into ATDR docs or code.

## High-Level Comparison

| Capability / Pattern | Supervisor Template | ATDR Current State | Status |
| --- | --- | --- | --- |
| Backend stack | Node/Express-style backend | FastAPI backend | Intentionally different |
| Frontend stack | Vue/Vuex frontend | React dashboard | Intentionally different |
| Database | MongoDB-oriented template | SQLAlchemy/Alembic with SQLite locally and optional PostgreSQL later | Intentionally different |
| Project process | PRD, T1-T20, tasklist/progress board, agents | ATDR-specific PRD, T1-T20 template/examples, tasklist/progress board, agent model | Implemented |
| Authentication | Email/password, Google SSO/MFU Mail, IAM SDK possibilities | Local JWT login, username/email login, school-email metadata, OIDC/MFU IAM placeholders disabled | Partially implemented |
| Authorization | Permission path/action matrix, group assignment, data scopes | Admin/analyst RBAC enforced by FastAPI dependencies and documented permission matrix | Partially implemented |
| External IAM | IAM SDK, token introspection, B2B auth, Google ID token flow | Planning/status placeholders only; no external network calls or login callback | Future work |
| Email OTP/2FA | Email OTP flow, trusted device, resend/cooldown patterns | Email verification foundation/dev outbox disabled by default | Partial foundation |
| Account lifecycle | Invite/status/lifecycle flows | Local user admin, role, email, email verified status, active/disabled concepts where supported | Partial foundation |
| Audit | Auth, permission, account, response audit expectations | Audit logs for auth-related actions, assistant, response, detection/user workflows where implemented | Implemented for lab scope |
| Source/log ingestion | Not the main template focus | Log import, replay, syslog test support, source health, parser profiles | Strong ATDR-specific implementation |
| Detection | Not the main template focus | Rule detection, anomaly scoring, supervised ML, hybrid risk, controlled QA scenarios | Strong ATDR-specific implementation |
| Response | Template IAM/action control concepts | Simulated, analyst-approved response only; protected IP denial; audit | Implemented safely |

## What ATDR Has Completed Well

| Area | Completed Evidence |
| --- | --- |
| Local SOC workflow | Import/replay/syslog-test logs, parse/normalize, run detection, alert/case investigation, simulated response, audit trail |
| Parser and source handling | Palo Alto parser, generic/raw fallback behavior, parser profiles, source management, source health, source-aware detection |
| Detection quality | Rule catalog, controlled detection corpus, scenario expectations, false-positive/false-negative QA, no-hardware soak |
| Explainability | Alert "Why flagged", log-level explanations, behavior evidence, ATT&CK-style context, assistant alert explainer |
| ML governance | Label review, supervised ML diagnostics, readiness gates, no production promotion, decision support wording |
| Response safety | Manual approval, simulated mode, no automatic response, protected IP controls, audited denied attempts |
| Local IAM/RBAC | Local JWT, admin/analyst roles, admin-only user controls, response permission tests |
| School-email groundwork | Email field, email login, email verified status, disabled verification foundation, dev outbox when configured |
| External IAM groundwork | OIDC/MFU IAM/Google SSO config placeholders and non-secret status endpoints, disabled by default |
| University workflow | ATDR PRD, workflow doc, agent model, T1-T20 template/examples, tasklist/progress board, traceability, compliance checklist |

## What Is Partial

| Area | Current Gap |
| --- | --- |
| External school-email login | No real MFU IAM SDK integration, Google SSO callback, OIDC login, token validation, or external network call is enabled. |
| Fine-grained IAM permissions | ATDR currently has role-based admin/analyst enforcement, not a database-backed path/action/group permission matrix. |
| Email OTP/2FA | ATDR has email verification groundwork, but real OTP/2FA enforcement, trusted devices, resend throttling policy, and SMTP delivery are future work. |
| Account lifecycle | Local user creation/editing exists, but invite flow, password reset email, last-login policy, deprovisioning policy, and external account sync are future work. |
| B2B token introspection | Template includes B2B introspection patterns; ATDR has no B2B client API or introspection endpoint. |
| Real source validation | ATDR has no-hardware and controlled replay validation; sustained real router/firewall forwarding still needs hardware/lab access. |
| PostgreSQL/shared lab | Optional readiness work exists, but local workflow remains SQLite and PostgreSQL validation depends on a running lab DB. |

## What Is Not Started Or Intentionally Not Implemented

- Migration to Node, Vue, Vuex, or MongoDB.
- Real OAuth/OIDC/Google/MFU IAM login.
- Real SMTP email delivery.
- Real firewall blocking or automatic response.
- External LLM assistant calls by default.
- Production deployment claim.
- Production IAM claim.
- Production accuracy claim for ML.

## School Email / IAM Readiness Finding

The supervisor template contains enough information to understand the expected IAM shape:

- MFU IAM SDK style adapter and env variable names.
- Google SSO / MFU Mail login pattern.
- Email OTP / 2FA UI pattern.
- Account lifecycle and audit expectations.
- Permission matrix and data-scope concepts.
- B2B token introspection concept.

It does not contain enough approved deployment information to safely enable real school-email login in ATDR today.

ATDR still needs advisor/provider confirmation for:

- Approved provider: MFU IAM SDK, Google Workspace, generic OIDC, or a combination.
- Approved issuer/base URL and metadata endpoints.
- Client ID for ATDR.
- Secret delivery method that does not commit secrets.
- Local/preprod/prod callback URLs.
- Allowed email domains.
- Group-to-role mapping for ATDR admin/analyst/viewer.
- Token validation, JWKS/introspection, audience, and scope requirements.
- OTP/2FA responsibility: provider-managed or ATDR-managed.
- Audit, privacy, retention, and data-sharing requirements.

## Recommended Next Sequence

1. Keep current local JWT + email-login workflow as the default.
2. Ask advisor/provider to complete `docs/security/MFU_IAM_PROVIDER_DETAILS_CHECKLIST.md`.
3. After provider details are approved, implement a disabled-by-default external IAM prototype behind config.
4. Add callback/token validation tests using mocked provider responses only.
5. Keep admin auto-provisioning disabled until group mapping is approved.
6. Keep response automation disabled regardless of IAM integration.

## Decision

ATDR should continue to follow the supervisor template at the process, governance, IAM-planning, permission-matrix, audit, and safety-control level.

ATDR should not be migrated to the supervisor template stack. The current FastAPI + React + SQLAlchemy/Alembic architecture is appropriate for ATDR's log ingestion, relational audit trail, labels, alerts, sources, jobs, and ML governance workflows.
