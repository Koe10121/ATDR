# ATDR AI Docs Index

This index defines the active ATDR documentation set for AI/Codex-assisted work. It adapts the university template documentation pattern to ATDR without making NewSystem, Node, Vue, MongoDB, or full external IAM implementation truth.

## Active Control Documents

| Document | Purpose |
| --- | --- |
| `docs/ATDR_AI_WORKFLOW.md` | Active no-guessing, source-evidence, testing, PRD, tasklist, safety, and handoff workflow. |
| `docs/prd/PRD-ATDR.md` | Active ATDR product requirements and safety constraints. |
| `docs/tasks/README.md` | ATDR tasklist/progress-board rules. |
| `docs/tasks/tasklist-progress.md` | Canonical editable system progress board. |
| `docs/tasks/tasklist-progress.html` | Generated progress board view. |
| `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` | ATDR T1-T20 change/handoff template. |
| `docs/templates/PROJECT-TASKLIST-TEMPLATE.md` | ATDR feature/change tasklist template. |
| `docs/templates/PROJECT-SYSTEM-PROGRESS-TEMPLATE.md` | ATDR system progress template. |
| `docs/agents/ATDR_AGENT_OPERATING_MODEL.md` | ATDR agent roles, responsibilities, and verification responsibilities. |
| `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | Requirement-to-source/test/docs/gap traceability. |
| `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md` | University process compliance status and remaining gaps. |

## Security And IAM Documents

| Document | Purpose |
| --- | --- |
| `docs/security/ATDR_IAM_RBAC_MATRIX.md` | Current admin/analyst role matrix and access-control evidence. |
| `docs/security/ATDR_PERMISSION_PATHS.md` | NewSystem-style ATDR permission path registry for future IAM mapping. |
| `docs/security/ATDR_EXTERNAL_IAM_PLAN.md` | Disabled-by-default generic OIDC/school-email IAM plan. |
| `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md` | Lab security review baseline and production-hardening gaps. |

## Runbooks And Readiness Documents

| Document | Purpose |
| --- | --- |
| `README.md` | Short project overview, startup commands, verification commands, and doc map. |
| `docs/QUICKSTART_FOR_TEAM.md` | Windows setup for teammates using clone or zip download. |
| `docs/LAB_RUNBOOK.md` | Local/lab operations, replay, syslog, sources, scenarios, and troubleshooting. |
| `docs/ACCEPTANCE_TEST_CHECKLIST.md` | Manual acceptance workflow. |
| `docs/FINAL_SYSTEM_STATUS.md` | Current final controlled academic status. |
| `docs/V3_0_PRODUCTION_READINESS_TRACK.md` and related v3 docs | Future production-readiness planning without production claim. |

## Reference-Only Documents

The repository may include NewSystem template documents for traceability. They are reference-only unless an ATDR-specific document explicitly adopts a rule.

| Reference | Rule |
| --- | --- |
| `NewSystem/` | University process/style/reference material only. Not ATDR runtime code. |
| `docs/AI-WORKFLOW.md` | Original NewSystem-oriented workflow reference. Active workflow is `docs/ATDR_AI_WORKFLOW.md`. |
| `docs/prd/PRD-NewSystem.md` | NewSystem PRD reference. Active PRD is `docs/prd/PRD-ATDR.md`. |
| `docs/agents/agent-*.md` when NewSystem-specific | Reference roles only; active ATDR model is `docs/agents/ATDR_AGENT_OPERATING_MODEL.md`. |

## Change Rules

- Source code and mounted routes beat docs when they conflict.
- Use ATDR source paths in new work: `atdr/app/main.py`, `atdr/app/routers/*.py`, `atdr/app/db/models.py`, `frontend/src/App.tsx`, `frontend/src/lib/api.ts`, and tests.
- Update `docs/tasks/tasklist-progress.md` and regenerate `docs/tasks/tasklist-progress.html` when system progress, blockers, verification, or readiness changes.
- Use a T1-T20 change record for non-trivial work.
- Update `docs/prd/PRD-ATDR.md` and `docs/ATDR_REQUIREMENT_TRACEABILITY.md` when behavior, API, UI, data model, permission, safety, ML, or release expectations change.
- Do not claim production readiness, automatic response, real firewall blocking, or full external IAM unless future source evidence proves it.

