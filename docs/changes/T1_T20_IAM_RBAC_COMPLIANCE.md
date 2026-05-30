# T1-T20 Change Document: IAM/RBAC Compliance

## T1 Change Title

- Title: ATDR IAM/RBAC compliance audit, permission matrix, and traceability closure
- Date: 2026-05-30
- Owner / acting agent: Codex
- Related version or sprint: v0.3 university-template compliance phase

## T2 Requirement

- User request: Adapt the university IAM requirement to ATDR without adding enterprise IAM, verify current authentication/authorization, document the permission model, add access-control tests, and update governance traceability.
- Business / lab goal: Make ATDR defensible for university review by showing who can access what, how permissions are enforced, and which IAM gaps remain.
- Success outcome: Admin/analyst RBAC is source-backed, tested, documented, and linked from ATDR governance docs.
- Explicit non-goals:
  - No OAuth, SSO, SAML, LDAP, or external identity provider.
  - No database reset or data deletion.
  - No real firewall blocking.
  - No automatic response.
  - No production-readiness claim.

## T3 Source Evidence

| Source | Path | Evidence / Finding |
| --- | --- | --- |
| Product docs | `README.md` | ATDR is a defensive lab prototype with local startup commands, React dashboard, simulated response, and governance docs. |
| Workflow | `docs/ATDR_AI_WORKFLOW.md` | Requires no guessing, source evidence, safety constraints, PRD/docs update gate, and T1-T20 handoff. |
| PRD | `docs/prd/PRD-ATDR.md` | Defines ATDR as lab-ready prototype; ML is decision support; response is simulated. |
| Backend route truth | `atdr/app/main.py`, `atdr/app/routers/*.py` | FastAPI routes use dependency-based protection. |
| Auth dependencies | `atdr/app/core/security.py` | `get_current_user`, `require_admin`, and `require_analyst_or_admin` enforce JWT and role checks. |
| User routes | `atdr/app/routers/users.py` | User management is admin-only. |
| Source routes | `atdr/app/routers/sources.py` | Source list/detail/health is analyst/admin; source create/update is admin-only. |
| ML routes | `atdr/app/routers/ml.py` | Label review workflows are analyst/admin; model training/scoring is admin-only. |
| Response service | `atdr/app/routers/response.py`, `atdr/app/services/response_service.py` | Simulated block/unblock is admin-only, requires justification, denies protected IPs, and audits denied attempts. |
| Data model | `atdr/app/db/models.py` | `User.role`, `AuditLog`, `ResponseAction`, `MLLabel`, and source models support current RBAC/audit workflows. |
| Frontend route truth | `frontend/src/App.tsx` | Admin-only routes are wrapped with `AdminRoute`. |
| Frontend guards/nav | `frontend/src/components/AdminRoute.tsx`, `frontend/src/components/AppShell.tsx` | Non-admin users see access denied and admin-only nav items are hidden. |
| Tests/scripts | `atdr/tests/test_api.py`, `atdr/tests/test_response_safety.py`, `frontend/package.json` | Existing tests covered auth, alert workflow, response safety, and frontend smoke checks. |
| Current runbooks/status | `docs/LAB_RUNBOOK.md`, `docs/V0_3_STATUS.md` | Current workflow remains local SQLite/FastAPI/React with simulated response and lab-source validation. |

## T4 Current Behavior

- Current backend behavior: Protected endpoints require JWT. Admin-only endpoints use `require_admin`; analyst/admin endpoints use `require_analyst_or_admin`.
- Current frontend behavior: React redirects unauthenticated users, hides admin nav items from analysts, and shows access denied for direct admin-route access.
- Current data model behavior: Users have a `role` string; audit, response, source, label, and run-history records are relational SQLAlchemy models.
- Current AI/ML behavior: ML Governance and prediction/report views are analyst/admin; model training and scoring are admin-only; ML remains decision support.
- Current response/audit behavior: Simulated block/unblock is admin-only, justification is required, protected IPs are denied, and denied attempts are audited.
- Current known limitation: No viewer role and no external IAM provider.

## T5 Impacted Areas / Agents

| Area / Agent | Impacted? | Reason |
| --- | --- | --- |
| Orchestrator | yes | Ensured source-evidence workflow and final handoff. |
| Product Owner / Requirement Planner | yes | Clarified ATDR-specific IAM scope and remaining gaps. |
| Data Model / Database | no | No schema change was required. |
| Backend / API | yes | Audited route dependencies and added RBAC regression tests. |
| Frontend / Dashboard | yes | Audited admin route guard, role-aware navigation, and disabled response controls. |
| AI/ML Governance | yes | Documented model-training permissions and decision-support boundary. |
| Security / Response Safety | yes | Verified response permissions, protected-IP denial, and audit behavior. |
| QA/UAT | yes | Added IAM/RBAC tests and ran verification gates. |
| Release/Ops / Lab Validation | yes | Confirmed no startup workflow change and documented limitations. |

## T6 Scope

### In Scope

- Inspect current auth/RBAC implementation.
- Create IAM/RBAC matrix.
- Create requirement traceability document.
- Update governance docs with ATDR-specific IAM adaptation.
- Add focused backend/static frontend RBAC tests.
- Run verification.

### Out Of Scope

- No OAuth, SSO, SAML, LDAP, or external IAM.
- No viewer/read-only role implementation.
- No real firewall blocking.
- No automatic response.
- No production-readiness claim.
- No reset/delete of current data.

## T7 Functional Requirements

| ID | Requirement | Priority | Source |
| --- | --- | --- | --- |
| FR-ATDR-IAM-001 | Document admin and analyst permissions with source evidence | Must | User request, `atdr/app/core/security.py` |
| FR-ATDR-IAM-002 | Verify protected endpoints reject unauthenticated requests | Must | User request, `atdr/app/core/security.py` |
| FR-ATDR-IAM-003 | Verify admin-only endpoints deny analyst users | Must | User request, `atdr/app/routers/users.py`, `atdr/app/routers/sources.py` |
| FR-ATDR-IAM-004 | Verify analysts can access intended investigation workflows | Must | User request, `atdr/app/routers/alerts.py`, `atdr/app/routers/logs.py` |
| FR-ATDR-IAM-005 | Verify simulated response safety permissions | Must | User request, `atdr/app/services/response_service.py` |
| FR-ATDR-IAM-006 | Keep enterprise IAM out of scope | Must | User request |

## T8 Acceptance Criteria

| ID | Acceptance Criteria | Verification |
| --- | --- | --- |
| AC-001 | IAM/RBAC matrix exists and maps admin/analyst/future viewer permissions | `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| AC-002 | Requirement traceability exists and includes IAM/RBAC | `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |
| AC-003 | Governance docs link IAM/RBAC adaptation | `docs/ATDR_AI_WORKFLOW.md`, `docs/prd/PRD-ATDR.md`, `docs/agents/ATDR_AGENT_OPERATING_MODEL.md` |
| AC-004 | Backend permission tests pass | `.\.venv\Scripts\python.exe -m pytest atdr\tests -q` |
| AC-005 | Frontend admin guard/navigation remains covered | `atdr/tests/test_iam_rbac.py`, `npm.cmd run test:e2e` |
| AC-006 | No OAuth/SSO/SAML/LDAP added | Source/doc review |
| AC-007 | Release gate passes | `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` |

## T9 API Contract

- New endpoints: none.
- Changed endpoints: none.
- Unchanged endpoints: all current API contracts remain backward compatible.
- Auth/RBAC: documented current route dependencies; no runtime behavior change required.
- Request examples: unchanged.
- Response examples: unchanged.
- Backward compatibility: preserved.

## T10 Data Model / Migration

- Schema changes: none.
- Alembic migration: none.
- Index changes: none.
- Existing data compatibility: unchanged.
- Rollback strategy: remove documentation/test additions if needed.
- No migration needed because this was an audit/documentation/test pass.

## T11 Backend Plan / Changes

- Routers: inspected auth, users, logs, alerts, sources, detection, ML, response, audit, suppressions, and watchlists.
- Schemas: inspected response/source/ML schemas where needed.
- Services: inspected user and response services.
- Scripts: no runtime script changes.
- Error handling: no behavior change.
- Audit behavior: verified denied response attempts are audited.
- Tests: added `atdr/tests/test_iam_rbac.py`.

## T12 Frontend Plan / Changes

- Routes/pages: inspected `frontend/src/App.tsx`.
- Components: inspected `AdminRoute`, `ProtectedRoute`, `AccessDenied`, and `AppShell`.
- API client/hooks: no changes.
- Loading/error/empty states: no changes.
- Role visibility: documented and statically tested admin-only nav/route guard.
- Accessibility/responsive notes: no UI behavior changes.
- Playwright/manual checks: Playwright smoke/regression suite passed with Node 20.

## T13 Security / Response / AI Safety

- Response mode remains simulation: yes.
- Automatic response remains disabled: yes.
- Real firewall enforcement added: no.
- Protected IP handling: verified in service and tests.
- Audit impact: denied response attempts are audited.
- ML decision-support status: unchanged; no automatic response path from ML/detection.
- Weak/reviewed label wording: unchanged.
- Data privacy/repo hygiene: no sensitive tracked files found in hygiene check.
- Security reviewer decision: pass with known IAM limitations.

## T14 Test Plan

| Test | Command / Method | Required? | Notes |
| --- | --- | --- | --- |
| Ruff | `.\.venv\Scripts\ruff.exe check atdr` | yes | Python lint. |
| Python compile | `.\.venv\Scripts\python.exe -m compileall -q atdr migrations` | yes | Syntax/import compile. |
| Backend tests | `.\.venv\Scripts\python.exe -m pytest atdr\tests -q` | yes | Includes IAM/RBAC tests. |
| Alembic drift | `.\.venv\Scripts\alembic.exe check` | yes | No schema drift expected. |
| Frontend lint | `cd frontend; npm.cmd run lint` | yes | Node 20 used. |
| Frontend build | `cd frontend; npm.cmd run build` | yes | Node 20 used. |
| Playwright | `cd frontend; npm.cmd run test:e2e` | yes | Existing smoke/regression suite. |
| Replay dry-run | `.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty` | yes | Confirms safe replay behavior. |
| Performance smoke | `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty` | yes | Documents current large SQLite performance warning. |
| Release gate | `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` | yes | Final backend release gate. |

## T15 Implementation Summary

| File | Change Summary |
| --- | --- |
| `docs/security/ATDR_IAM_RBAC_MATRIX.md` | Added admin/analyst/future-viewer permission matrix, backend/frontend enforcement summary, response safety permissions, and IAM limitations. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | Added source-backed traceability matrix for major ATDR requirements. |
| `atdr/tests/test_iam_rbac.py` | Added focused RBAC and response-safety regression tests. |
| `docs/ATDR_AI_WORKFLOW.md` | Added ATDR IAM/RBAC adaptation and source links. |
| `docs/prd/PRD-ATDR.md` | Added IAM/RBAC constraints and functional requirement. |
| `docs/agents/ATDR_AGENT_OPERATING_MODEL.md` | Expanded Security / Response Safety role for IAM/RBAC responsibilities. |
| `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md` | Added IAM/RBAC and traceability compliance entries and remaining gaps. |
| `README.md` | Linked IAM/RBAC matrix and requirement traceability docs. |

## T16 Tests Run / Evidence

| Command / Check | Result | Evidence |
| --- | --- | --- |
| `.\.venv\Scripts\ruff.exe check atdr` | Passed | `All checks passed!` |
| `.\.venv\Scripts\python.exe -m compileall -q atdr migrations` | Passed | Exit code 0 |
| `.\.venv\Scripts\python.exe -m pytest atdr\tests -q` | Passed | `120 passed, 1 skipped` |
| `.\.venv\Scripts\alembic.exe check` | Passed | `No new upgrade operations detected.` |
| `cd frontend; npm.cmd run lint` | Passed | ESLint completed with exit code 0 using Node 20.11.1. |
| `cd frontend; npm.cmd run build` | Passed | Vite build completed successfully using Node 20.11.1. |
| `cd frontend; npm.cmd run test:e2e` | Passed | `11 passed, 1 skipped` |
| `.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty` | Passed | Dry-run parsed safe sample and wrote no DB rows. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty` | Passed | Current rerun had no warnings: Overview 0.415s, ML Governance lightweight 1.3791s. A previous run showed transient large-SQLite budget warnings and remains documented for monitoring. |
| `.\.venv\Scripts\python.exe -m atdr.scripts.verify_release` | Passed | `ok: true`, no failed required checks. |

Skipped checks:

- Check: none.
- Reason: not applicable.
- Risk: no current performance warning, but a previous large-SQLite smoke run showed transient budget warnings and should be monitored.

## T17 PRD / Docs Updated

| Document | Updated? | Reason |
| --- | --- | --- |
| `docs/prd/PRD-ATDR.md` | yes | Added IAM/RBAC constraints, role limitations, and functional requirement. |
| `docs/ATDR_AI_WORKFLOW.md` | yes | Added ATDR IAM/RBAC adaptation and matrix/traceability links. |
| `docs/LAB_RUNBOOK.md` | no | No lab run command behavior changed. |
| `docs/V0_3_STATUS.md` | no for IAM pass | No v0.3 runtime behavior changed during the IAM pass. |
| README | yes | Added links to IAM/RBAC and traceability docs. |

## T18 Risks / Blockers / Assumptions / Decisions

### Risks

- Current IAM is local JWT RBAC only; it is not enterprise IAM.
- No viewer/read-only role exists yet.
- Demo JWT secret must be replaced before shared lab or real deployment.
- A previous large SQLite DB performance smoke showed budget warnings; the current rerun is healthy.

### Blockers

- None for the IAM/RBAC documentation and test pass.

### Assumptions

- Admin/analyst roles are sufficient for the current lab prototype.
- External IAM is future work and should not be added until explicitly requested.
- Backend dependency enforcement remains the authority over frontend visibility.

### Decisions

- Do not add OAuth/SSO/SAML/LDAP.
- Do not change current startup commands.
- Do not change DB schema.
- Do not enable real response enforcement.

## T19 Release / Rollback

- Release impact: process/docs/test improvement only; no runtime API or schema change.
- Deployment notes: no deployment change required.
- Local workflow impact: unchanged.
- Rollback plan: revert the added docs/tests if needed.
- Data rollback: not applicable; no data mutation.
- Monitoring/checks after release: continue using release gate, replay dry-run, and performance smoke.

## T20 Final Handoff

- Status: completed.
- Files changed: IAM/RBAC docs, traceability docs, compliance docs, README, and RBAC tests.
- Behavior changed: no runtime behavior change.
- Verification result: release gate passed; frontend lint/build/Playwright passed with Node 20.
- Remaining risks: external IAM, viewer role, demo JWT secret replacement, real device validation, production security hardening, and possible recurrence of large SQLite performance warnings.
- Exact next command for user:

```powershell
git status --short
```
