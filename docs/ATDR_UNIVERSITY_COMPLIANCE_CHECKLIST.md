# ATDR University Compliance Checklist

This checklist maps the university AI/project workflow rules to ATDR-specific evidence and remaining gaps.

## Source Evidence

| Evidence | Repository Source |
| --- | --- |
| ATDR workflow adaptation | `docs/ATDR_AI_WORKFLOW.md` |
| ATDR PRD | `docs/prd/PRD-ATDR.md` |
| Agent operating model | `docs/agents/ATDR_AGENT_OPERATING_MODEL.md` |
| Change template | `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` |
| IAM/RBAC permission matrix | `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| Requirement traceability | `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |
| Current product/run commands | `README.md` |
| Release gate | `atdr/scripts/verify_release.py` |
| Current status | `docs/V0_3_STATUS.md` |
| Repo hygiene | `.gitignore` |

## Compliance Matrix

| University Rule / Expectation | ATDR Current Satisfaction | Evidence | Gap / Next Action | Owner |
| --- | --- | --- | --- | --- |
| No guessing; inspect source first | Satisfied for future work through source discovery rule and T3 evidence requirement | `docs/ATDR_AI_WORKFLOW.md`, `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` | Enforce in every future change handoff | Orchestrator |
| Source evidence required | Satisfied by ATDR workflow and T1-T20 T3 section | `docs/ATDR_AI_WORKFLOW.md`, `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` | Future change docs must cite paths and findings | All agents |
| Source truth order defined | Satisfied with ATDR-specific truth order | `docs/ATDR_AI_WORKFLOW.md` | Keep updated if architecture changes | Orchestrator |
| T1-T20 change document required | Satisfied by ATDR template | `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` | Store completed change docs under `docs/changes/` for major work | Orchestrator |
| PRD update gate | Satisfied by ATDR PRD and workflow update rule | `docs/prd/PRD-ATDR.md`, `docs/ATDR_AI_WORKFLOW.md` | PRD must be updated when behavior/API/UI/data/ML/safety changes | Product Owner |
| Testing gate | Satisfied by release gate and documented test commands | `atdr/scripts/verify_release.py`, `frontend/package.json`, `atdr/tests/*` | Full verification remains required for code-risk changes | QA/UAT |
| Backend route truth | Satisfied by FastAPI route source order | `atdr/app/main.py`, `atdr/app/routers/*.py` | Keep README API highlights aligned with mounted routes | Backend/API |
| Frontend route truth | Satisfied by React route source order | `frontend/src/App.tsx`, `frontend/src/pages/*` | Keep dashboard docs aligned when routes change | Frontend |
| Data model/migration control | Satisfied by SQLAlchemy/Alembic source truth | `atdr/app/db/models.py`, `migrations/versions/*` | Add Alembic migration for future schema changes | Data Model |
| AI safety | Satisfied: ML is decision support only; weak labels are not production ground truth | `docs/prd/PRD-ATDR.md`, `docs/AI_TRAINING_RUNBOOK.md`, `docs/V0_3_STATUS.md` | Continue reviewed-label expansion before stronger claims | AI/ML Governance |
| Response safety | Satisfied: response remains simulated, approval/audit required | `docs/prd/PRD-ATDR.md`, `atdr/app/routers/response.py`, `atdr/tests/test_response_safety.py` | Real blocking remains future approved work only | Security / Response Safety |
| Repo hygiene | Satisfied by `.gitignore` and workflow rules | `.gitignore`, `docs/ATDR_AI_WORKFLOW.md` | Check `git status --short` before handoff | Release/Ops |
| Lab readiness documentation | Satisfied for current local workflow and source scenarios | `docs/LAB_RUNBOOK.md`, `docs/V0_3_STATUS.md`, `README.md` | Real device syslog forwarding still needs controlled lab hardware validation | Release/Ops |
| Production claim control | Satisfied: docs state lab-ready prototype, not certified production | `README.md`, `docs/V0_3_STATUS.md`, `docs/prd/PRD-ATDR.md` | Keep wording honest in future presentation/docs | Product Owner |
| Docker/PostgreSQL validation | Partially satisfied: optional docs/config exist, but local Docker validation is not required | `docker-compose.yml`, `docs/LAB_RUNBOOK.md`, `docs/DEPLOYMENT_GUIDE.md` | Validate on Docker-capable lab host later | Release/Ops |
| Real device validation | Partially satisfied: local replay/syslog and source scenarios exist | `docs/LAB_RUNBOOK.md`, `atdr/scripts/run_source_scenario.py`, `data/samples/scenarios/*` | Test with actual firewall/router forwarding in controlled lab | Release/Ops |
| IAM/RBAC adaptation | Satisfied for local lab roles: JWT auth, admin/analyst RBAC, frontend guards, response permission checks, and audit requirements are documented | `docs/security/ATDR_IAM_RBAC_MATRIX.md`, `atdr/app/core/security.py`, `frontend/src/components/AdminRoute.tsx` | External IAM provider and viewer role are future work, not current ATDR scope | Security / Response Safety |
| Requirement traceability | Satisfied for major v0.3 capabilities | `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | Keep updated when routes, data model, UI, ML, response, or source workflows change | Orchestrator |

## Current Compliance Status

ATDR now has ATDR-specific workflow governance, PRD, agent operating model, change template, and compliance checklist. The old template-style university docs can remain as historical references, but future ATDR work should use the ATDR-specific documents listed above.

## Remaining Gaps

- Real device syslog forwarding validation is not complete.
- External IAM provider integration is not implemented. ATDR currently uses local JWT auth and admin/analyst RBAC.
- Viewer/read-only role is not implemented.
- Demo JWT secrets must be replaced before shared lab or real deployment.
- Real firewall/router validation is pending.
- Real response enforcement is not implemented.
- Docker/PostgreSQL lab deployment validation is still optional/future on a Docker-capable host.
- Production security hardening is pending.
- Final report/slides are not finalized.
- Future non-trivial changes should create completed T1-T20 change records, not only use the template.
- More human-reviewed suspicious/malicious labels are needed before stronger ML claims.

## Required Pre-Handoff Checks For Future Work

```powershell
git status --short
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release
```

For docs-only changes, at minimum verify the docs exist, links are correct, and ATDR docs do not introduce stale template-specific commands or production claims.
