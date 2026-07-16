# ATDR Productization Template Gap Analysis

Date: 2026-06-27

Scope: Phase 1 audit comparing the current ATDR repository with the official supervisor template at `<MFU_SHELL_ROOT>`. This document is a planning artifact only. No files were deleted and no runtime behavior was changed.

## Evidence Inspected

| Evidence | Notes |
| --- | --- |
| Current ATDR README | `README.md` |
| ATDR PRD and traceability | `docs/prd/PRD-ATDR.md`, `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |
| ATDR backend app/routes | `atdr/app/main.py`, `atdr/app/routers/*.py` |
| ATDR database models | `atdr/app/db/models.py` |
| ATDR frontend routes | `frontend/src/App.tsx`, `frontend/src/pages/*` |
| ATDR CI | `.github/workflows/ci.yml` |
| ATDR template docs | `docs/ATDR_TEMPLATE_MERGE_ANALYSIS.md`, `docs/security/ATDR_MFU_IAM_IMPLEMENTATION_PLAN.md` |
| Official supervisor template root | `<MFU_SHELL_ROOT>` |
| Supervisor IAM docs | `backend-node/docs/IAM_PRD.md`, `backend-node/docs/IAM_SYSTEM_OVERVIEW.md`, `backend-node/docs/IAM_RECOMMENDATIONS.md` |
| Supervisor IAM integration source | `backend-node/server/integrations/iam/*` |
| Supervisor security/account source | `backend-node/server/Project/security/*`, `backend-node/server/Project/accounts/*` |
| Supervisor login/2FA UI source | `frontend-vue/src/projects/components/dialog/SignIn.vue`, `TwoFA.vue` |
| Supervisor process docs | `docs/tasks/*`, `docs/templates/*`, `docs/AI-WORKFLOW.md`, `docs/agents/*` |
| Supervisor environment key families | Root, `backend-node`, and `frontend-vue` `.env*` files inspected by variable name only |

Secret values were not printed or copied. Environment files were inspected only for variable names and configuration families.

## What The Supervisor Template Provides

The official supervisor template provides:

- Node.js backend scaffold.
- Vue frontend scaffold.
- MongoDB-oriented data model.
- Docker/GitLab deployment examples.
- IAM-first permission model with local fallback.
- Google SSO UI path.
- Email/password sign-in.
- Email OTP / 2FA UI path.
- Device trust and session concepts.
- B2B token introspection concepts.
- Permission matrix with path/action checks.
- Account lifecycle and invite concepts.
- Audit log and retention concepts.
- MFU project permission ownership variables.
- Managed IAM client registration variables and scripts.
- Process docs: AI workflow, agents, T1-T20 change docs, tasklist/progress board, render/check scripts.

Important supervisor env variable families found by name:

- Root/wrapper env files: `BACKEND_*`, `FRONTEND_*`, `BASE_SERVER_URL`, `GOOGLE_CLIENT_ID`, `GOOGLE_OAUTH_*`, `FRONTEND_PROJECT_*`.
- Frontend Vue env files: `VUE_APP_API_BASE_URL`, `VUE_APP_AUTH_SYSTEM`, `VUE_APP_CLIENTID`, `VUE_APP_PROJECT_*`, `VUE_APP_SCOPE`, `VUE_APP_PROMPT`.
- Backend Node env files:
- `IAM_SDK_*`
- `IAM_ADMIN_*`
- `PROJECT_PERMISSION_*`
- `PROJECT_IAM_*`
- `PROJECT_INIT_ADMIN_EMAILS`
- `PROJECT_AUTH_REQUIRE_2FA`
- `PROJECT_AUDIT_RETENTION_DAYS`
- `GOOGLE_CLIENT_ID`

## What ATDR Already Has

ATDR already has a large amount of product-relevant functionality that the generic template does not provide:

- FastAPI defensive SOC backend.
- React SOC dashboard.
- SQLAlchemy/Alembic relational model.
- SQLite local workflow and optional PostgreSQL shared-lab path.
- Palo Alto parser, generic syslog profile, raw fallback profile.
- Raw evidence preservation.
- Source management and source health.
- Ingestion/replay/syslog lab tooling.
- Rule detection, alert deduplication, case grouping, and explanations.
- IsolationForest anomaly scoring.
- Supervised ML diagnostic workflow and model registry.
- AI Governance and review-label workflow.
- SOC Assistant with deterministic fallback, external LLM adapter, citations, audit, and feedback review.
- Simulated analyst-approved response and audit trail.
- Scenario validation and no-hardware source pilot tooling.
- University workflow docs and ATDR-specific T1-T20/tasklist compliance.
- Supervisor IAM config aliases for many `IAM_SDK_*`, `IAM_ADMIN_*`, `PROJECT_PERMISSION_*`, `PROJECT_IAM_*`, `PROJECT_INIT_*`, and `PROJECT_AUTH_REQUIRE_2FA` names in `atdr/app/core/config.py`.
- Detection/ML productization evaluator and AI Governance dashboard panel separating diagnostic evidence from model promotion.
- Release gate, backend tests, frontend lint/build/e2e tests, performance smoke.

## What ATDR Is Missing For SaaS-Like Productization

### IAM / School Email

ATDR has a strong start, but it is not complete:

- Full Google/MFU Mail OAuth browser redirect/callback login is not implemented.
- Real MFU IAM token introspection has not been live-validated.
- External IAM group-to-role mapping is not implemented.
- Provider-managed 2FA/OTP is not implemented.
- Real SMTP for verification/invites is disabled and not configured by default.
- Viewer/read-only role is missing.
- Permission model is still role-based `admin` / `analyst`, not full path/action/data-scope matrix.
- The supervisor template has enough variable names and flow evidence to build a Python MFU IAM adapter, but live completion still depends on private client secrets, approved callback behavior if using OAuth, and confirmed token/profile response contracts.

### Assistant / Real AI

ATDR has a real-provider adapter, but product-grade assistant work remains:

- Follow-up context needs continued hardening for alert/log/source continuity.
- External provider failure handling should be tested regularly.
- Raw-log privacy policy must remain explicit before any raw context is allowed.
- Assistant should keep improving citations, investigation briefs, and answer quality evaluation.
- There is no tenant/team-specific assistant memory or knowledge base yet.

### Detection / ML

ATDR is strong for controlled validation, but product-grade detection still needs:

- More real-source validation.
- More durable false-positive and false-negative analysis on independent data.
- Better supervised SOC queue design and calibration.
- Clear separation between diagnostic candidates and active model artifacts.
- Formal rule catalog lifecycle and owner review.
- Long-duration drift monitoring.
- Governance visibility now exists in AI Governance, but the next ML productization step should focus on stable SOC queue model design rather than more broad dashboard polish.

### SaaS / Operations

Major production-style gaps remain:

- Multi-tenant model is not designed.
- PostgreSQL deployment is optional but not the default tested shared-lab path.
- Background jobs are mostly synchronous/status-tracked, not true worker queues.
- Observability lacks a production metrics stack.
- Audit retention/integrity is not fully hardened.
- Secrets management is local `.env`, not a real secret manager.
- CI currently focuses backend release gate; frontend CI should be included if GitHub minutes/environment allow.
- Deployment, TLS, backup/restore, and rollback require stricter productization.

### Dashboard Product UX

The dashboard is functional, but SaaS polish remains:

- Better role-aware navigation and permission surfaces.
- Cleaner admin/IAM onboarding flow.
- Better assistant handoff UX.
- More consistent product design system.
- Less historical/version clutter in main pages.

## What Should Be Copied Or Adapted

Adapt these template patterns into ATDR, in FastAPI/React terms:

- MFU IAM SDK/token introspection flow as a Python service adapter.
- Permission path/action matrix as future RBAC v2.
- Google/MFU Mail login UI idea as a React login flow when provider details are approved.
- OTP/2FA UI flow as a future React account-security workflow.
- Account invite/lifecycle pattern for User Admin.
- Audit-retention and audit-integrity ideas.
- IAM admin/group/permission status visibility, without exposing secrets.
- Process discipline: tasklist/progress board, T1-T20 docs, PRD/traceability updates.
- Professional page-shell and admin-table layout ideas, but not Vue code directly.
- Root/frontend template env naming can inform deployment documentation, but backend runtime settings must remain ATDR FastAPI settings.

## What Should Not Be Copied

Do not copy or migrate:

- Node.js backend runtime.
- Vue/Vuex frontend runtime.
- MongoDB as a replacement for SQLAlchemy/Alembic.
- Template `.env` secret values.
- Template `node_modules`.
- Template IDE/local artifacts.
- Template route paths as ATDR truth.
- Hard-coded Google client IDs or IAM secrets.
- The template's generic business modules that do not fit ATDR.
- Template backend `.env` secret values, even when local permission to inspect exists. Use private `.env` or a real secret manager only.

## In-Repo `NewSystem/` Finding

The repository contains `NewSystem/`. A file comparison against the official template path found:

- 526 tracked files under `NewSystem/`.
- Ignored local artifacts under `NewSystem/`, including `.env.*`, `.idea/`, `.DS_Store`, and `node_modules/`.
- The in-repo copy is not identical to the official template. The official template has ATDR-specific generated paths such as `mfuaidrivenlogbasedthreatdetectionandresponse`, while the in-repo copy still includes older `newSystem` naming in several files.

Recommendation:

1. Do not delete `NewSystem/` during Phase 1.
2. Treat `<MFU_SHELL_ROOT>` as the official reference.
3. In the cleanup phase, either:
   - move only the useful tracked docs/manifest from `NewSystem/` into `docs/reference/NewSystem/`, or
   - delete the tracked `NewSystem/` copy after confirming all ATDR docs point to the external official template path and useful reference material is preserved.
4. Remove ignored local artifacts separately if desired, but never stage `.env` or secrets.

Current decision: keep `NewSystem/` untouched until a dedicated cleanup task audits references and confirms the official external template path remains available. The in-repo copy is a cleanup liability, not runtime truth.

## Safe Cleanup Plan

Do not run this plan until the user approves a cleanup phase.

| Path / area | Classification | Proposed action |
| --- | --- | --- |
| `NewSystem/` tracked source | Move/delete candidate | Replace with concise `docs/reference/` material or document external official template path. Do not delete until references are audited. |
| `NewSystem/**/node_modules/` | Ignore/delete local artifact | Safe to remove locally after confirming no work depends on it. It is ignored and should never be committed. |
| `NewSystem/.env*`, `NewSystem/**/.env*` | Sensitive local artifact | Keep ignored. Do not print, copy, or commit. |
| `NewSystem/.idea/`, `.DS_Store` | Local artifact | Safe cleanup candidate. |
| `docs/FINAL_*`, many old v0-v3 docs | Keep/update candidate | Keep for evidence now; later create a docs archive/index instead of deleting. |
| `atdr/dashboard/streamlit_app.py` | Legacy continuity | Keep until React fully replaces all referenced demo flows. |
| `demo_exports/` | Ignored generated reports | Do not commit. Delete only with user approval if local disk cleanup is needed. |
| `ml_baseline_reviews/` | Ignored review work | Do not delete without explicit backup approval. |
| `atdr/models/` artifacts | Ignored model artifacts | Do not commit. Do not delete active local artifacts without backup/approval. |

## Productization Priority Recommendation

The next major productization sequence should be:

1. Finish or checkpoint the in-progress v3.66-v3.73 productization changes and decide what to commit.
2. Implement a live-safe MFU IAM validation harness using the supervisor token/introspection evidence, with all secrets read only from private `.env`.
3. Stabilize real LLM assistant mode, follow-up context, and provider failure fallback.
4. Improve supervised SOC queue model design and model registry clarity.
5. Finish cleanup planning and remove/reference-only template duplication safely.
6. Move shared-lab persistence toward PostgreSQL validation and backup/restore.
7. Improve dashboard product UX and permission surfaces.
8. Add observability, audit retention/integrity, and production deployment hardening.

## Requirements For Real IAM Completion

Even with the supervisor template, real IAM completion still needs:

- Approved live/preprod MFU IAM endpoint access.
- Client ID and secret in private `.env` or a secret manager.
- Approved audience/scope values.
- Exact token introspection response contract.
- Callback/login flow approval if using OAuth/Google SSO.
- Allowed domain policy, including `lamduan.mfu.ac.th`.
- Group-to-role mapping for `admin`, `analyst`, and future `viewer`.
- 2FA/OTP policy and account recovery rules.
- Audit/privacy requirements for external provider traffic.

ATDR already has compatible placeholder/config names for many of these items, but that is not the same as completed live IAM login. Real login should be considered unfinished until an authenticated school-email user can complete the flow in ATDR, a local ATDR user is provisioned or linked safely, role mapping is audited, and tests prove local login still works.

## Requirements For Real LLM Assistant Completion

Real LLM mode should require:

- Provider and model set in private `.env`.
- API key never printed or committed.
- Provider probe passing without raw logs.
- Raw log context disabled unless a formal privacy review approves it.
- IP redaction enabled by default.
- Tests proving no response actions, detection runs, label changes, model activation, user changes, or data deletion.
- Dashboard status that shows provider mode without exposing secrets.

## Phase 1 Decision

Keep ATDR on FastAPI + React + SQLAlchemy/Alembic. Use the supervisor template as a reference for IAM, permission matrix, account lifecycle, audit, deployment discipline, and university workflow evidence. Do not migrate to Node/Vue/MongoDB. Do not delete the in-repo `NewSystem/` until a dedicated cleanup phase is approved and references are updated.

## Phase 1 Completion Evidence

This audit now includes:

- Current ATDR runtime and source evidence.
- Official supervisor template docs and source families.
- Root, backend-node, and frontend-vue env key families by variable name only.
- In-repo `NewSystem/` status and cleanup recommendation.
- Explicit keep/adapt/do-not-copy decisions.
- Productization priority sequence after the current v3.73 checkpoint.

No code, database, IAM secret, external login behavior, model state, or response behavior was changed by this audit.
