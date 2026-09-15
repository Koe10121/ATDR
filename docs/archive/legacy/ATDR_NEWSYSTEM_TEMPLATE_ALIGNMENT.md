# ATDR Alignment With The NewSystem University Template

This document explains how ATDR follows useful university `NewSystem` control
patterns while staying true to ATDR's FastAPI + React architecture. Selected
reference files are archived under `docs/reference/NewSystem/`; the unrelated
tracked Node/Vue/Mongo runtime copy has been removed from the proposed v4.8.1
tree.

`NewSystem` is a Node.js + Vue + MongoDB + IAM reference project. ATDR is a FastAPI + React + SQLAlchemy/Alembic defensive SOC prototype. Therefore, this alignment copies the workflow standards and control ideas, not the framework-specific implementation.

## Source Evidence Read

| Template / ATDR Area | Source |
| --- | --- |
| NewSystem template setup and required permission paths | `docs/reference/NewSystem/TEMPLATE.md` |
| NewSystem manifest and environment/permission standards | `docs/reference/NewSystem/template.manifest.json` |
| NewSystem workflow/change standard | `docs/reference/NewSystem/workflow/AI-WORKFLOW.md`, `docs/reference/NewSystem/workflow/T1-T20-change-document.md`, `docs/reference/NewSystem/workflow/agents/sprint-task-template.md` |
| ATDR tasklist/progress-board adaptation | `docs/tasks/README.md`, `docs/tasks/tasklist-progress.md`, `scripts/render-tasklist-progress-html.js`, `scripts/check-tasklist-progress-standard.js` |
| NewSystem IAM PRD concepts | `docs/reference/NewSystem/backend-node/docs/IAM_PRD.md` |
| NewSystem IAM architecture concepts | `docs/reference/NewSystem/backend-node/docs/IAM_SYSTEM_OVERVIEW.md` |
| NewSystem security review pattern | `docs/reference/NewSystem/backend-node/docs/OWASP_TOP10_REPORT.md` |
| ATDR active PRD | `docs/prd/PRD-ATDR.md` |
| ATDR active workflow | `docs/ATDR_AI_WORKFLOW.md` |
| ATDR IAM/RBAC matrix | `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| ATDR routes and auth enforcement | `atdr/app/main.py`, `atdr/app/core/security.py`, `atdr/app/routers/*.py` |
| ATDR React route/navigation truth | `frontend/src/App.tsx`, `frontend/src/components/AppShell.tsx` |

## What Was Adapted

| NewSystem Template Concept | ATDR Equivalent | Status |
| --- | --- | --- |
| Project manifest | `docs/ATDR_TEMPLATE_MANIFEST.json` | Added for ATDR v0.3 governance. |
| Permission paths | `docs/security/ATDR_PERMISSION_PATHS.md` and `docs/security/ATDR_IAM_RBAC_MATRIX.md` | Added as ATDR route/action registry. |
| IAM authentication | Local JWT recovery plus v3.91 MFU outer-shell opaque-code handoff | Implemented in source; real provider acceptance pending. |
| Role/permission checks | FastAPI dependencies: `require_admin`, `require_analyst_or_admin` | Implemented. |
| Account administration | Admin user management in `atdr/app/routers/users.py` | Implemented for local lab users. |
| Audit logging | `AuditLog` model, audit route, response/action audit writes | Implemented. |
| Environment discipline | `.env.example`, `.env.lab.example`, `.env.production.example` | Implemented. |
| PRD update gate | `docs/prd/PRD-ATDR.md` and `docs/ATDR_AI_WORKFLOW.md` | Implemented. |
| T1-T20 change handoff | `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` | Implemented. |
| Tasklist/progress board | `docs/tasks/tasklist-progress.md`, `docs/tasks/tasklist-progress.html`, and progress scripts under `scripts/` | Implemented as ATDR process evidence. |
| Docs index | `docs/AI-DOCS-INDEX.md` | Implemented to separate active ATDR docs from reference-only NewSystem docs. |
| Release checks | `atdr/scripts/verify_release.py` plus backend/frontend/smoke checks | Implemented. |
| Security review discipline | `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md` | Added as lab security review baseline. |

## What Was Not Copied

The following NewSystem items are not copied into ATDR because they are framework-specific, out of scope, or risky for the current lab prototype:

| NewSystem Item | ATDR Decision |
| --- | --- |
| Node.js backend structure | Not copied. ATDR remains FastAPI. |
| Vue/Vuex/CoreUI frontend structure | Not copied. ATDR remains React-first. |
| MongoDB data model | Not copied. ATDR remains SQLAlchemy/Alembic with SQLite locally and optional PostgreSQL later. |
| NewSystem IAM SDK runtime | Not copied. ATDR consumes the approved outer-shell handoff contract instead. |
| Direct ATDR-owned OAuth/SSO/SAML/LDAP | Not implemented; the MFU outer shell owns school sign-in. |
| Provider-managed Google/MFU SSO and 2FA lifecycle | Source handoff exists; live provider, group, recovery, and deprovisioning acceptance remain external. |
| Real production deployment assumptions | Not copied. ATDR is lab-ready, not production-certified. |
| Real enforcement/containment automation | Not copied. ATDR response remains simulated and analyst-approved. |

## ATDR Permission Path Model

NewSystem uses path + action permissions such as `view`, `edit`, `delete`, `action`, and `logs`.

ATDR adapts this to a simpler lab role model:

- `admin`: full local lab operator role.
- `analyst`: SOC analyst role for investigation, detection, label review, AI Governance viewing, and audit viewing.
- `viewer`: future read-only role, not implemented.

ATDR permission paths are documented in `docs/security/ATDR_PERMISSION_PATHS.md`. Backend route dependencies are the enforcement source of truth; frontend route hiding is only a usability layer.

## Compliance Decision

ATDR should follow the university template at the process and control level:

- source evidence before changes
- PRD and traceability updates
- tasklist/progress-board updates
- permission matrix
- auditability
- testing gate
- release gate
- security review
- clear limitations

ATDR should not be converted into NewSystem's Node/Vue/Mongo architecture. The
approved MFU companion shell remains a separately distributed identity boundary,
not an ATDR stack migration. See `docs/reference/NewSystem/REFERENCE_SCOPE.md`.
