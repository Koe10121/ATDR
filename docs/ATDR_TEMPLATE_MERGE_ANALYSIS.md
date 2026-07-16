# ATDR Template Merge Analysis

## Status

ATDR should merge the useful supervisor-template requirements and patterns without migrating runtime stacks. The supervisor package at `<MFU_SHELL_ROOT>` is a NewSystem-style Node/Vue/MongoDB template with IAM, 2FA, permission-matrix, B2B, and process guidance. ATDR remains the working FastAPI + React + SQLAlchemy/Alembic system.

Current decision:

- Keep ATDR runtime: FastAPI backend, React dashboard, SQLAlchemy/Alembic, SQLite local, optional PostgreSQL later.
- Do not migrate ATDR to Node, Vue, or MongoDB.
- Use the supervisor template as an IAM/process/UI reference.
- Implement external school-email IAM only through disabled-by-default ATDR adapters until provider details are explicitly configured.
- Implement real LLM support only through a disabled-by-default assistant adapter with privacy and safety controls.

## Source Evidence Reviewed

| Area | Evidence |
| --- | --- |
| ATDR backend runtime | `atdr/app/main.py`, `atdr/app/core/config.py`, `atdr/app/routers/auth.py`, `atdr/app/routers/assistant.py` |
| ATDR frontend runtime | `frontend/src/App.tsx`, `frontend/src/pages/AssistantPage.tsx`, `frontend/src/pages/UserAdmin.tsx` |
| ATDR IAM groundwork | `docs/security/ATDR_EXTERNAL_IAM_PLAN.md`, `docs/security/ATDR_MFU_IAM_ADAPTER_PLAN.md`, `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| ATDR process docs | `docs/ATDR_AI_WORKFLOW.md`, `docs/tasks/tasklist-progress.md`, `docs/prd/PRD-ATDR.md` |
| Supervisor IAM docs | `backend-node/docs/IAM_PRD.md`, `backend-node/docs/IAM_SYSTEM_OVERVIEW.md`, `backend-node/docs/IAM_RECOMMENDATIONS.md` under the supervisor template path |
| Supervisor IAM code | `backend-node/server/integrations/iam/*`, `backend-node/server/Project/security/*` |
| Supervisor login UI | `frontend-vue/src/projects/components/dialog/SignIn.vue`, `frontend-vue/src/projects/components/dialog/TwoFA.vue`, `frontend-vue/src/store/modules/Authen/index.js`, `frontend-vue/src/store/modules/Security/*` |
| Supervisor env profiles | `.env.local`, `.env.preprod`, `.env.prod`, `backend-node/.env.*`, `frontend-vue/.env.*` under the supervisor template path |

Secret values were not copied into ATDR and must not be committed.

## What The Template Adds Conceptually

| Template Area | ATDR Mapping |
| --- | --- |
| IAM service / SDK | Future `MFU_IAM_*` adapter using ATDR FastAPI routes and config |
| Google SSO / MFU Mail | Future OIDC/Google login path if an approved client ID and callback policy exist |
| Email OTP / 2FA | Current ATDR email verification/dev-outbox groundwork; login 2FA remains future |
| Permission matrix | Current admin/analyst RBAC plus `docs/security/ATDR_PERMISSION_PATHS.md`; full path/action matrix remains future |
| B2B token introspection | Future service-token mode only; not dashboard login |
| Account invites/lifecycle | ATDR local user admin plus email/status fields; real SMTP invite remains future |
| Audit | ATDR audit logs already cover login, response, email verification, assistant questions, and other critical actions |

## IAM Details Found Without Secret Values

The supervisor env profiles contain configured IAM SDK/admin variable names for base URL, client ID, client secret, audience, scope, token path, introspection path, profile path, admin base path, permission source, project permission paths, managed client metadata, initial admin emails, and 2FA requirement flags.

The checked Google client ID fields are present but not configured in the env profiles. That means the MFU IAM SDK/token-introspection route is currently better evidenced than Google SSO, but real use still requires safe secret provisioning and advisor-approved callback/login behavior.

## Enough To Implement Now?

Enough for:

- Safe config placeholders.
- Safe status endpoints that report configured/not configured without secrets.
- Documentation of implementation order.
- Tests proving disabled IAM and local login continue to work.
- Direct ATDR support for supervisor env aliases such as `IAM_SDK_*`, `IAM_ADMIN_*`, and `PROJECT_PERMISSION_*`.
- Admin dashboard readiness visibility for MFU IAM B2B client, admin API, and permission bootstrap.

Not enough for:

- Enabling real MFU IAM login.
- Enabling Google/MFU Mail OAuth login.
- Enabling email OTP/2FA login enforcement.
- Automatic external user provisioning.
- External group-to-admin mapping.

Blocking details:

- ATDR-specific callback URL and route contract.
- Secret delivery method outside Git.
- Allowed school domains.
- Exact group-to-role mapping.
- Token validation and session mapping policy.
- Failure/lockout/2FA rollout rules.
- Audit/privacy requirements for real provider traffic.

v3.64 closes the template-env compatibility gap. The remaining real-login gap is now the user-facing school-email/OAuth token flow and approved role mapping, not lack of template IAM variable names.

## Test School Account Policy

`student.test@lamduan.mfu.ac.th` is the synthetic account used in local test examples. It must not be hard-coded as the only user. School-email rules allow approved domains and map roles through configuration or an advisor-approved IAM group policy.

## Merge Rules

- Template concepts can be adopted when they improve ATDR.
- Template stack and routes are reference-only unless explicitly reimplemented in ATDR.
- No secrets from the template are copied into Git.
- Local JWT login must remain available as a fallback until real IAM is proven.
- Response automation remains disabled.
- The assistant remains read-only.
