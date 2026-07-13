# T1-T20 Change Document: v3.78 Template Shell Integration Plan

## T1 Change Title

v3.78 Supervisor Template Shell Integration Plan

## T2 Requirement

The supervisor template must become the outer application shell and school-email IAM gateway. ATDR should open as the protected SOC module after template/IAM login without blindly migrating ATDR to Node/Vue/MongoDB or duplicating account registration.

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| Supervisor IAM overview | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\backend-node\docs\IAM_SYSTEM_OVERVIEW.md` | Documents IAM service integration, Google/MFU login, permission matrix, B2B introspection, and audit behavior. |
| Supervisor IAM PRD | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\backend-node\docs\IAM_PRD.md` | Defines login, OTP/2FA, account lifecycle, permission matrix, invitation, and B2B requirements. |
| Supervisor IAM recommendations | `C:\Users\User\Downloads\mfu-ai-driven-log-based-threat-detection-and-response\backend-node\docs\IAM_RECOMMENDATIONS.md` | Warns that secrets must be moved/rotated and hardening is required before production use. |
| Supervisor IAM adapters | `backend-node/server/integrations/iam/*.js` in the supervisor template | Provides SDK adapter, B2B middleware, token introspection, profile, and admin API boundaries. |
| Supervisor frontend shell | `frontend-vue/src/projects/components/dialog/SignIn.vue`, `TwoFA.vue`, `frontend-vue/src/router/index.js` | Provides Google/MFU login entry, 2FA dialog, and route guard/permission loading pattern. |
| ATDR auth | `atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py` | ATDR already has disabled-by-default MFU IAM token-login, public status, authenticated status, local user mapping, and audit. |
| ATDR frontend login | `frontend/src/pages/LoginPage.tsx`, `frontend/src/lib/api.ts` | ATDR exposes local login plus MFU IAM token-login readiness and API client methods. |
| ATDR config | `atdr/app/core/config.py` | ATDR reads ATDR-native and supervisor-template IAM env aliases without exposing secrets. |

## T4 Current Behavior

ATDR can run independently with local JWT login. It has a disabled-by-default MFU IAM token-login harness and readiness visibility, but the supervisor template is not yet acting as the actual outer login shell that launches ATDR.

## T5 Impacted Areas / Agents

- Orchestrator
- Product Owner / Requirement Planner
- Backend / API
- Frontend / Dashboard
- Security / Response Safety
- QA/UAT
- Release/Ops / Lab Validation

## T6 Scope

In scope:

- Source-backed supervisor-template shell/IAM audit.
- ATDR-specific integration plan.
- Recommended handoff architecture.
- Documentation of required private provider values and remaining advisor/provider questions.

Out of scope:

- Runtime implementation of OAuth/OIDC/Google callback.
- Enabling real MFU IAM login.
- Copying template secrets or `.env` files.
- Migrating ATDR to Node/Vue/MongoDB.
- Schema changes.
- Response automation or real firewall blocking.

## T7 Functional Requirements

| ID | Requirement | Priority | Source |
| --- | --- | --- | --- |
| FR-V378-001 | Define how the supervisor template should launch ATDR after successful login. | Must | User goal objective |
| FR-V378-002 | Identify best handoff method and rejected alternatives. | Must | Supervisor template and ATDR auth source |
| FR-V378-003 | Identify required private IAM/provider values without printing secrets. | Must | Supervisor template env variable names |
| FR-V378-004 | Preserve ATDR FastAPI/React/SQLAlchemy architecture. | Must | User goal objective |
| FR-V378-005 | Keep response automation, real firewall blocking, and assistant action execution disabled. | Must | ATDR safety requirements |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-001 | `docs/ATDR_TEMPLATE_SHELL_INTEGRATION_PLAN.md` exists and explains local/preprod/prod flow. | File inspection |
| AC-002 | Plan names what is reused and what is not copied from the template. | File inspection |
| AC-003 | Plan avoids secret values and only references variable names. | Secret-pattern scan |
| AC-004 | Tasklist and traceability docs are updated. | Tasklist render/check |
| AC-005 | No runtime behavior is changed. | Git diff and no code/schema edits |

## T9 API Contract

No API contract changed in this documentation phase.

The recommended future API/UI flow reuses:

- `POST /api/auth/mfu-iam/token-login`
- `GET /api/auth/mfu-iam/public-status`
- `GET /api/auth/mfu-iam/status`

## T10 Data Model / Migration

No schema change and no Alembic migration.

## T11 Backend Plan / Changes

No backend code changed in this phase.

Future implementation should:

- preserve local login
- validate IAM/handoff tokens server-side
- map verified school identities to local ATDR users
- default new school users to analyst
- map admins only from explicit private configuration
- audit success/failure
- never expose secrets

## T12 Frontend Plan / Changes

No frontend code changed in this phase.

Future implementation should add a small ATDR login handoff receiver that:

- accepts handoff mode from the template shell
- calls `POST /api/auth/mfu-iam/token-login`
- clears token-like URL values after use
- falls back cleanly to local login on failure

## T13 Security / Response / AI Safety

- Response mode remains simulated.
- Automatic response remains disabled.
- Real firewall enforcement is not added.
- Chatbot remains read-only.
- External LLM keys are not read, printed, or committed.
- Template secret values are not copied.
- Individual school email addresses are not hard-coded as sole allowed users.

## T14 Test Plan

| Test | Command / Method | Required? | Notes |
| --- | --- | --- | --- |
| Tasklist render | `node scripts/render-tasklist-progress-html.js .` | yes | Regenerates progress board. |
| Tasklist check | `node scripts/check-tasklist-progress-standard.js .` | yes | Verifies supervisor-style board format. |
| Secret scan | `rg` against new docs | yes | Checks for obvious secret assignments. |
| Diff check | `git diff --check -- docs/...` | yes | Docs whitespace hygiene. |

## T15 Implementation Summary

| File | Change Summary |
| --- | --- |
| `docs/ATDR_TEMPLATE_SHELL_INTEGRATION_PLAN.md` | Added source-backed template-shell/IAM handoff plan. |
| `docs/changes/T1_T20_V3_78_TEMPLATE_SHELL_INTEGRATION_PLAN.md` | Added completed T1-T20 change record for this planning phase. |
| `docs/AI-DOCS-INDEX.md` | Linked the new plan in active security/IAM docs. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | Added traceability row for the supervisor template shell integration plan. |
| `docs/tasks/tasklist-progress.md` | Added v3.78 progress-board evidence and current blocker. |
| `docs/tasks/tasklist-progress.html` | Regenerated from the Markdown progress board. |

## T16 Tests Run / Evidence

| Command / Check | Result | Evidence |
| --- | --- | --- |
| `node scripts/render-tasklist-progress-html.js .` | pass | Progress board regenerated successfully. |
| `node scripts/check-tasklist-progress-standard.js .` | pass | Progress-board standard check returned `ok: true`. |
| Secret-pattern scan on v3.78 docs | pass | No API-key, client-secret, password, private-key, or token assignment values were found in the v3.78 docs. Variable names are documented without values. |
| `git diff --check -- docs/...` | pass | No whitespace errors; Git only reported normal line-ending normalization warnings for touched docs. |
| `git status --short --untracked-files=all` | pass | Only intended docs changed/new; no `.env`, DB, real logs, model artifacts, `ml_baseline_reviews/`, `demo_exports/`, processed logs, or generated reports appeared. |

## T17 PRD / Docs Updated

| Document | Updated? | Reason |
| --- | --- | --- |
| `docs/ATDR_TEMPLATE_SHELL_INTEGRATION_PLAN.md` | yes | New primary integration plan. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | yes | New traceability row. |
| `docs/AI-DOCS-INDEX.md` | yes | New doc link. |
| `docs/tasks/tasklist-progress.md` | yes | Progress-board compliance. |
| `docs/tasks/tasklist-progress.html` | yes | Generated view. |

## T18 Risks / Blockers / Assumptions / Decisions

### Risks

- The exact token type the template can hand to ATDR still needs confirmation.
- Template env files may contain secret-like values and should be treated as private/provider-managed.
- Iframe embedding would create avoidable auth and UX risk.

### Blockers

- Real school-email login cannot be called complete until token type, callback URLs, allowed domains, role mapping, and provider access are confirmed.

### Assumptions

- ATDR remains the SOC module.
- The supervisor template owns account lifecycle and school login.
- Local ATDR login remains a fallback during implementation.

### Decisions

- Prefer redirect/token handoff plus optional reverse proxy.
- Do not migrate ATDR to Node/Vue/MongoDB.
- Do not duplicate account registration in ATDR.

## T19 Release / Rollback

This phase is documentation only. Rollback is reverting the touched docs and regenerated progress-board HTML. No database, API, schema, or runtime rollback is required.

## T20 Final Handoff

Status: completed for Phase A planning after verification.

Next implementation prompt:

```text
Implement the v3.79 Template-to-ATDR Handoff Receiver. Keep MFU IAM disabled by default, preserve local login, add frontend handoff mode, use POST /api/auth/mfu-iam/token-login, clear token-like URL values after use, audit success/failure, hide secrets, add tests, and do not migrate ATDR stacks.
```
