# T1-T20: NewSystem Template Alignment For ATDR

## T1 Change Title

ATDR NewSystem university-template alignment pass.

## T2 Requirement

Adapt the university `NewSystem` template expectations into ATDR without changing ATDR's working FastAPI + React + SQLAlchemy/Alembic architecture.

## T3 Source Evidence

| Evidence | Source |
| --- | --- |
| NewSystem setup and permission path pattern | `NewSystem/TEMPLATE.md` |
| NewSystem manifest/environment/permission expectations | `NewSystem/template.manifest.json` |
| NewSystem IAM PRD concepts | `NewSystem/backend-node/docs/IAM_PRD.md` |
| NewSystem IAM architecture concepts | `NewSystem/backend-node/docs/IAM_SYSTEM_OVERVIEW.md` |
| NewSystem OWASP-style review pattern | `NewSystem/backend-node/docs/OWASP_TOP10_REPORT.md` |
| ATDR route mounting | `atdr/app/main.py` |
| ATDR JWT/RBAC dependencies | `atdr/app/core/security.py` |
| ATDR protected routers | `atdr/app/routers/*.py` |
| ATDR React route/navigation truth | `frontend/src/App.tsx`, `frontend/src/components/AppShell.tsx` |
| Existing ATDR workflow and PRD | `docs/ATDR_AI_WORKFLOW.md`, `docs/prd/PRD-ATDR.md` |
| Existing ATDR RBAC matrix | `docs/security/ATDR_IAM_RBAC_MATRIX.md` |

## T4 Current Behavior

ATDR already had ATDR-specific workflow, PRD, agent operating model, IAM/RBAC matrix, requirement traceability, and release gate documentation. The remaining gap was making the relationship between ATDR and the tracked `NewSystem/` university template explicit, including a NewSystem-style manifest, permission path registry, and security review baseline.

## T5 Impacted Areas / Agents

| Area | Impact |
| --- | --- |
| Orchestrator | Clarifies active ATDR workflow vs reference NewSystem template. |
| Product Owner | Updates PRD and requirement traceability. |
| Security / Response Safety | Adds permission path registry and OWASP lab security review. |
| Release/Ops | Adds manifest and validation command inventory. |
| QA/UAT | Provides documentation evidence for university-template compliance. |

## T6 Scope

In scope:

- ATDR-specific template alignment document.
- ATDR template manifest.
- ATDR permission path registry.
- ATDR OWASP lab security review baseline.
- README, PRD, workflow, compliance, and traceability links.

Out of scope:

- No external IAM/OAuth/SSO/SAML/LDAP.
- No Node/Vue/Mongo migration.
- No database reset.
- No response automation.
- No real firewall blocking.

## T7 Functional Requirements

- Document how ATDR maps NewSystem template controls to ATDR implementation.
- Document which NewSystem parts are intentionally not copied.
- Provide a machine-readable ATDR manifest.
- Provide a permission path registry comparable to the NewSystem permission path pattern.
- Provide a lab security review baseline following the NewSystem security-review discipline.

## T8 Acceptance Criteria

| ID | Criterion | Status |
| --- | --- | --- |
| AC-001 | ATDR has a NewSystem alignment document with source evidence | Done |
| AC-002 | ATDR has a template manifest listing env keys, permission paths, validation commands, and safety constraints | Done |
| AC-003 | ATDR has a permission path registry tied to backend/frontend sources | Done |
| AC-004 | ATDR has an OWASP-style lab security review baseline | Done |
| AC-005 | README/PRD/workflow/compliance/traceability link the new docs | Done |
| AC-006 | No runtime behavior or database data is changed | Done |

## T9 API Contract

No API contract changes.

## T10 Data Model / Migration

No data model or Alembic migration changes.

## T11 Backend Plan / Changes

No backend code changes. Backend source files were read as evidence for current route and RBAC behavior.

## T12 Frontend Plan / Changes

No frontend code changes. React route/navigation files were read as evidence for current page and role behavior.

## T13 Security / Response / AI Safety

- Response remains simulated.
- ML remains decision support only.
- No real firewall blocking.
- No automatic response.
- No external IAM integration was added.
- New OWASP lab review explicitly states current lab controls and remaining security gaps.

## T14 Test Plan

Because this is documentation/process work, use lightweight validation:

- Verify new docs exist.
- Search active docs for stale template wording.
- Confirm no sensitive/generated files are tracked.
- Run `git diff --check`.

Full release gate is not required unless code changes are introduced.

## T15 Implementation Summary

Created:

- `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md`
- `docs/ATDR_TEMPLATE_MANIFEST.json`
- `docs/security/ATDR_PERMISSION_PATHS.md`
- `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md`
- `docs/changes/T1_T20_NEWSYSTEM_TEMPLATE_ALIGNMENT.md`

Updated:

- `README.md`
- `docs/ATDR_AI_WORKFLOW.md`
- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`

## T16 Tests Run / Evidence

| Check | Result |
| --- | --- |
| `Test-Path docs\ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md` | Pass |
| `Test-Path docs\ATDR_TEMPLATE_MANIFEST.json` | Pass |
| `Test-Path docs\security\ATDR_PERMISSION_PATHS.md` | Pass |
| `Test-Path docs\security\ATDR_OWASP_LAB_SECURITY_REVIEW.md` | Pass |
| `Test-Path docs\changes\T1_T20_NEWSYSTEM_TEMPLATE_ALIGNMENT.md` | Pass |
| `.\.venv\Scripts\python.exe -c "import json; json.load(open('docs/ATDR_TEMPLATE_MANIFEST.json', encoding='utf-8'))"` | Pass |
| `git diff --check` | Pass; only normal Windows LF/CRLF warnings were printed. |
| `git ls-files \| rg "(^|/)(ml_baseline_reviews|demo_exports)/|\\.env$|\\.sqlite3?$|atdr\\.db|\\.joblib$|paloalto-firewall|data/private|real_logs|\\.csv$"` | Pass; no tracked sensitive/generated matches. |
| Stale wording search over active ATDR docs | Pass with intentional references only: NewSystem is described as a reference template, and Node/Vue/Mongo/IAM items are explicitly marked as not copied or future work. |

## T17 PRD / Docs Updated

PRD update required and completed because the change affects university-template compliance, IAM/RBAC documentation, and security review documentation.

Updated:

- `docs/prd/PRD-ATDR.md`
- `docs/ATDR_AI_WORKFLOW.md`
- `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `README.md`

## T18 Risks / Blockers / Assumptions / Decisions

| Type | Item | Decision |
| --- | --- | --- |
| Risk | NewSystem reference docs may confuse readers | Active ATDR docs now point to ATDR-specific alignment and manifest. |
| Assumption | University template expectations can be satisfied by adaptation | Accepted; framework migration is not required. |
| Decision | Do not add external IAM now | ATDR local JWT/RBAC remains current scope. |
| Decision | Do not migrate to MongoDB/Node/Vue | ATDR stack remains FastAPI/React/SQLAlchemy. |

## T19 Release / Rollback

Release impact is documentation-only.

Rollback:

- Revert the added docs and link updates.
- No database or runtime rollback is needed.

## T20 Final Handoff

ATDR now has a clear, source-backed mapping from the university NewSystem template to ATDR's actual architecture. The project remains lab-ready, React-first, FastAPI-backed, SQLite-local, simulated-response-only, and ML decision-support-only.
