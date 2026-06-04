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
| External IAM groundwork plan | `docs/security/ATDR_EXTERNAL_IAM_PLAN.md` |
| NewSystem template alignment | `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md` |
| ATDR template manifest | `docs/ATDR_TEMPLATE_MANIFEST.json` |
| ATDR permission path registry | `docs/security/ATDR_PERMISSION_PATHS.md` |
| ATDR OWASP lab security review | `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md` |
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
| IAM/RBAC adaptation | Satisfied for local lab roles: JWT auth, admin/analyst RBAC, school-email account metadata, frontend guards, response permission checks, and audit requirements are documented | `docs/security/ATDR_IAM_RBAC_MATRIX.md`, `atdr/app/core/security.py`, `frontend/src/components/AdminRoute.tsx` | Full external login provider, SMTP invite email, and viewer role are future work; OIDC status/config groundwork is now documented | Security / Response Safety |
| NewSystem template adaptation | Satisfied: ATDR maps template concepts to FastAPI/React/SQLAlchemy equivalents and documents what was intentionally not copied | `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md`, `docs/ATDR_TEMPLATE_MANIFEST.json` | Keep this updated if external IAM, PostgreSQL/Docker, or real response connectors become approved scope | Orchestrator |
| Permission path registry | Satisfied: ATDR has a NewSystem-style permission path registry backed by current FastAPI and React sources | `docs/security/ATDR_PERMISSION_PATHS.md`, `docs/security/ATDR_IAM_RBAC_MATRIX.md` | Future external IAM can register these paths if approved | Security / Response Safety |
| OWASP/security review discipline | Satisfied for lab baseline: security posture, controls, and gaps are documented without production claim | `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md` | Add dependency scanning and stronger auth hardening before shared lab/production | Security / Response Safety |
| Requirement traceability | Satisfied for major v0.3 capabilities | `docs/ATDR_REQUIREMENT_TRACEABILITY.md` | Keep updated when routes, data model, UI, ML, response, or source workflows change | Orchestrator |

## Current Compliance Status

ATDR now has ATDR-specific workflow governance, PRD, agent operating model, change template, completed change example, IAM/RBAC matrix, requirement traceability, and release evidence. The old template-style university docs can remain as historical references, but future ATDR work should use the ATDR-specific documents listed above.

| Compliance Item | Current Status | Evidence |
| --- | --- | --- |
| No-guessing/source evidence rule | Satisfied | `docs/ATDR_AI_WORKFLOW.md`, T3 in `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` |
| ATDR PRD exists | Satisfied | `docs/prd/PRD-ATDR.md` |
| Agent operating model exists | Satisfied | `docs/agents/ATDR_AGENT_OPERATING_MODEL.md` |
| T1-T20 template exists | Satisfied | `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` |
| Completed T1-T20 example exists | Satisfied | `docs/changes/T1_T20_IAM_RBAC_COMPLIANCE.md` |
| IAM/RBAC matrix exists | Satisfied | `docs/security/ATDR_IAM_RBAC_MATRIX.md` |
| NewSystem template alignment exists | Satisfied | `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md` |
| ATDR template manifest exists | Satisfied | `docs/ATDR_TEMPLATE_MANIFEST.json` |
| Permission path registry exists | Satisfied | `docs/security/ATDR_PERMISSION_PATHS.md` |
| OWASP lab security review exists | Satisfied | `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md` |
| Requirement traceability exists | Satisfied | `docs/ATDR_REQUIREMENT_TRACEABILITY.md` |
| Release gate exists | Satisfied | `atdr/scripts/verify_release.py` |
| Acceptance checklist exists | Satisfied | `docs/ACCEPTANCE_TEST_CHECKLIST.md` |
| Lab runbook exists | Satisfied | `docs/LAB_RUNBOOK.md` |
| AI safety documented | Satisfied | `docs/prd/PRD-ATDR.md`, `docs/AI_TRAINING_RUNBOOK.md`, `docs/V0_3_STATUS.md` |
| Response safety documented | Satisfied | `docs/prd/PRD-ATDR.md`, `docs/security/ATDR_IAM_RBAC_MATRIX.md`, `atdr/tests/test_response_safety.py` |
| Repo hygiene documented | Satisfied | `.gitignore`, `docs/ATDR_AI_WORKFLOW.md`, `docs/QUICKSTART_FOR_TEAM.md` |
| Remaining gaps documented | Satisfied | Remaining Gaps section below |

## Large SQLite Performance Monitoring Note

During compliance closure, one large local SQLite performance smoke run showed budget warnings, but the final rerun completed within budget. Keep this note as a monitoring item because local SQLite timing can vary with concurrent backend/dashboard activity and DB lock contention.

| Metric | Previous Warning Run | Final Rerun | Local Budget |
| --- | ---: | ---: |
| Overview / ingestion summary | 10.7997s | 0.415s | 1.0s for Overview, 2.0s for ingestion summary |
| ML Governance lightweight summary | 2.8009s | 1.3791s | 2.0s |

Do not reset or delete data to hide performance issues. If warnings recur, recommended next action is to profile the Overview/ingestion summary query path on the current large SQLite DB and consider a targeted cache/query/index improvement or PostgreSQL lab validation later.

## Remaining Gaps

- Real device syslog forwarding validation is not complete.
- Full external IAM provider login is not implemented. ATDR currently uses local JWT auth and admin/analyst RBAC; v0.4 adds disabled OIDC config/status groundwork only.
- Viewer/read-only role is not implemented.
- Demo JWT secrets must be replaced before shared lab or real deployment.
- Real firewall/router validation is pending.
- Real response enforcement is not implemented.
- Docker/PostgreSQL lab deployment validation is still optional/future on a Docker-capable host.
- Production security hardening is pending.
- Final report/slides are not finalized.
- Future non-trivial changes should create completed T1-T20 change records like `docs/changes/T1_T20_IAM_RBAC_COMPLIANCE.md`.
- More human-reviewed suspicious/malicious labels are needed before stronger ML claims.
- Large local SQLite DB performance should be monitored; investigate if the Overview/ML Governance warnings recur.

## Required Pre-Handoff Checks For Future Work

```powershell
git status --short
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release
```

For docs-only changes, at minimum verify the docs exist, links are correct, and ATDR docs do not introduce stale template-specific commands or production claims.
