# T1-T20 Change Document: v3.79 Template-to-ATDR Handoff Receiver

## T1 Change Title

v3.79 Template-to-ATDR Handoff Receiver

## T2 Requirement

ATDR needs a safe frontend receiver so the supervisor template shell can hand an authenticated school/IAM user into ATDR without duplicating account registration or migrating ATDR stacks.

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| Integration plan | `docs/ATDR_TEMPLATE_SHELL_INTEGRATION_PLAN.md` | Recommends template shell plus redirect/token handoff into ATDR. |
| ATDR login page | `frontend/src/pages/LoginPage.tsx` | Existing local login and manual MFU token login UI. |
| ATDR auth hook | `frontend/src/hooks/useAuth.tsx` | Exposes `loginWithMfuIamToken`. |
| ATDR API client | `frontend/src/lib/api.ts` | Calls `POST /api/auth/mfu-iam/token-login`. |
| Backend token-login | `atdr/app/routers/auth.py`, `atdr/app/services/mfu_iam_service.py` | Validates token, maps user, issues ATDR JWT, and audits success/failure. |

## T4 Current Behavior

Before v3.79, ATDR had a manual school IAM token form but no automatic template-shell handoff receiver. Users had to paste a token themselves even if launched from the outer shell.

## T5 Impacted Areas / Agents

- Frontend / Dashboard
- Backend / API, unchanged but reused
- Security / Response Safety
- QA/UAT
- Release/Ops / Lab Validation

## T6 Scope

In scope:

- Detect explicit handoff token/code URL parameters on `/login`.
- Clear token-like values from the address bar.
- Call existing `POST /api/auth/mfu-iam/token-login`.
- Fall back to local login if IAM is disabled or validation fails.
- Add frontend regression coverage.
- Update docs and tasklist.

Out of scope:

- Real OAuth/OIDC/Google callback implementation.
- New backend IAM provider implementation.
- Schema changes.
- Template runtime changes.
- Response automation.
- Real firewall blocking.

## T7 Functional Requirements

| ID | Requirement | Priority | Source |
| --- | --- | --- | --- |
| FR-V379-001 | Login page must detect explicit template handoff token/code parameters. | Must | v3.78 plan |
| FR-V379-002 | Login page must clear token-like URL values after detection. | Must | Security/privacy requirement |
| FR-V379-003 | Handoff must call the existing token-login endpoint only when public status says token login is ready. | Must | Backend auth contract |
| FR-V379-004 | Local login must remain available after failed/disabled handoff. | Must | User goal |
| FR-V379-005 | Unsafe redirect targets must be ignored. | Must | Security requirement |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-001 | Successful handoff stores a session and navigates to the requested safe path. | Playwright |
| AC-002 | Handoff token/code does not remain in the URL. | Playwright |
| AC-003 | Disabled IAM handoff does not call token-login. | Playwright |
| AC-004 | Local login remains visible on disabled/failed handoff. | Playwright |
| AC-005 | No secrets are exposed in docs or UI text. | Review and secret scan |

## T9 API Contract

No backend API contract changed.

The frontend reuses:

```text
GET /api/auth/mfu-iam/public-status
POST /api/auth/mfu-iam/token-login
```

## T10 Data Model / Migration

No schema changes and no Alembic migration.

## T11 Backend Plan / Changes

No backend code changed. Existing backend behavior is reused:

- validates token through MFU IAM service when enabled
- supports explicit local mock mode only when configured
- maps verified external users to local ATDR users
- defaults external users to analyst unless configured otherwise
- audits success/failure
- hides secrets

## T12 Frontend Plan / Changes

`frontend/src/pages/LoginPage.tsx` now:

- parses query/fragment handoff parameters
- accepts token-like and code-like values as opaque handoff material
- clears URL values with `history.replaceState`
- checks public IAM readiness
- calls `loginWithMfuIamToken`
- navigates only to safe same-app paths
- shows concise success/failure/fallback status

## T13 Security / Response / AI Safety

- Handoff token/code is not displayed.
- Handoff URL is cleaned.
- Local login fallback remains.
- No secrets are committed.
- No response actions are created.
- No detection runs are started.
- No labels or model state are changed.
- No automatic response or firewall blocking is enabled.

## T14 Test Plan

| Test | Command / Method | Required? | Notes |
| --- | --- | --- | --- |
| Frontend lint | `cd frontend; npm.cmd run lint` | yes | TypeScript/ESLint check. |
| Frontend build | `cd frontend; npm.cmd run build` | yes | Ensures route compiles. |
| Playwright | `cd frontend; npm.cmd run test:e2e` | yes | Includes handoff success/fallback tests. |
| Tasklist render/check | `node scripts/render-tasklist-progress-html.js .`; `node scripts/check-tasklist-progress-standard.js .` | yes | Docs process gate. |

## T15 Implementation Summary

| File | Change Summary |
| --- | --- |
| `frontend/src/pages/LoginPage.tsx` | Added shell handoff parser, URL cleanup, readiness check, token-login flow, safe redirect, and handoff status UI. |
| `frontend/tests/smoke.spec.ts` | Added Playwright coverage for successful handoff and disabled-IAM fallback. |
| `docs/V3_79_TEMPLATE_TO_ATDR_HANDOFF_RECEIVER.md` | Added status and manual testing doc. |
| `docs/changes/T1_T20_V3_79_TEMPLATE_TO_ATDR_HANDOFF_RECEIVER.md` | Added completed change record. |
| `docs/AI-DOCS-INDEX.md` | Added v3.79 runbook link. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | Added v3.79 traceability row. |
| `docs/tasks/tasklist-progress.md` | Added v3.79 task/progress/verification/risk evidence. |
| `docs/tasks/tasklist-progress.html` | Regenerated board. |

## T16 Tests Run / Evidence

| Command / Check | Result | Evidence |
| --- | --- | --- |
| `cd frontend; npm.cmd run lint` | pass | ESLint passed for React source after the login handoff change. |
| `cd frontend; npm.cmd run build` | pass | TypeScript and Vite production build passed. |
| `cd frontend; npm.cmd run test:e2e -- smoke.spec.ts -g "template IAM handoff\|login page loads"` | pass | Targeted Playwright set passed: 3 passed. |
| `cd frontend; npm.cmd run test:e2e` | pass | Full Playwright suite passed: 19 passed, 1 skipped. |
| `node scripts/render-tasklist-progress-html.js .` | pass | Progress board regenerated successfully. |
| `node scripts/check-tasklist-progress-standard.js .` | pass | Progress-board standard check returned `ok: true`. |
| `.\.venv\Scripts\ruff.exe check .` | pass | Repository-wide Ruff check passed. |
| `.\.venv\Scripts\python.exe -m compileall -q atdr migrations` | pass | Python compile gate passed. |
| `.\.venv\Scripts\alembic.exe check` | pass | No new upgrade operations detected. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.config_doctor --pretty` | pass | Local SQLite profile is healthy; MFU IAM remains disabled/local-login-only; secrets exposed `false`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.test_mfu_iam_provider --pretty` | pass | MFU IAM status checked without provider call; mode `local_login_only`, token login not ready, secrets exposed `false`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_llm_provider --pretty` | pass | Gemini provider configured in private `.env`, LLM enabled, no provider call executed, raw logs disabled, redaction enabled, secrets exposed `false`. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` | pass | Release gate returned `ok: true`; backend tests passed inside release gate. |

## T17 PRD / Docs Updated

| Document | Updated? | Reason |
| --- | --- | --- |
| `docs/V3_79_TEMPLATE_TO_ATDR_HANDOFF_RECEIVER.md` | yes | New implementation doc. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | yes | New traceability row. |
| `docs/AI-DOCS-INDEX.md` | yes | New doc link. |
| `docs/tasks/tasklist-progress.md` | yes | Progress-board compliance. |
| `docs/tasks/tasklist-progress.html` | yes | Generated view. |

## T18 Risks / Blockers / Assumptions / Decisions

### Risks

- Live provider validation still depends on private `.env` and provider availability.
- If the supervisor shell can only provide a server-side session, a backend code-exchange bridge will still be needed.

### Blockers

- Exact production callback URLs, token type, and role mapping still require advisor/provider confirmation.

### Assumptions

- The shell can provide either an introspectable IAM token or a short-lived handoff code/token.
- ATDR remains a SOC module and local login remains fallback.

### Decisions

- Reuse the existing token-login endpoint.
- Do not add a new backend API until the exact template token/code contract is confirmed.

## T19 Release / Rollback

Rollback is frontend/docs only. Revert `LoginPage.tsx`, the Playwright tests, and docs if needed. No database rollback is required.

## T20 Final Handoff

Manual test:

```powershell
cd C:\Users\User\Desktop\ATDR
.\.venv\Scripts\python.exe -m atdr.scripts.config_doctor --pretty
cd frontend
npm.cmd run dev
```

Then open a local handoff URL after configuring private mock/live IAM:

```text
http://127.0.0.1:5173/login?mfu_token=mock:student@lamduan.mfu.ac.th&next=/assistant&source=template-shell
```
