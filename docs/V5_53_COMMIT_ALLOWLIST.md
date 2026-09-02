# v5.53 Commit Allowlist

Date: 2026-09-01

This is the exact cumulative tracked-path boundary for v5.53 MFU IAM And
Shared Deployment Readiness. It authorizes no staging, commit, push, merge, or
deployment operation. A separate explicit approval is required.

## Exact Paths

1. `.env.example`
2. `.env.lab.example`
3. `.env.production.example`
4. `.env.shell.example`
5. `.github/workflows/ci.yml`
6. `.github/workflows/codeql.yml`
7. `atdr/app/core/config.py`
8. `atdr/app/main.py`
9. `atdr/app/routers/observability.py`
10. `atdr/app/schemas/operations.py`
11. `atdr/app/services/repository_security_service.py`
12. `atdr/app/services/v553_release_readiness_service.py`
13. `atdr/scripts/run_v553_release_readiness.py`
14. `atdr/scripts/run_v553_security_acceptance.py`
15. `atdr/scripts/run_v553_team_runtime_acceptance.py`
16. `atdr/tests/test_v553_release_readiness.py`
17. `deploy/systemd/atdr.env.example`
18. `docs/AI-DOCS-INDEX.md`
19. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
20. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
21. `docs/changes/T1_T20_V5_53_MFU_IAM_AND_SHARED_DEPLOYMENT_READINESS.md`
22. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
23. `docs/CURRENT_SYSTEM_STATE_LOCK.md`
24. `docs/DEPLOYMENT_GUIDE.md`
25. `docs/LAB_RUNBOOK.md`
26. `docs/OPERATIONS_RUNBOOK.md`
27. `docs/prd/PRD-ATDR.md`
28. `docs/QUICKSTART_FOR_TEAM.md`
29. `docs/security/ATDR_MFU_IAM_PREPROD_VALIDATION.md`
30. `docs/security/V5_53_EXTERNAL_ACCEPTANCE_MANIFESTS.md`
31. `docs/tasks/tasklist-progress.html`
32. `docs/tasks/tasklist-progress.md`
33. `docs/TEAM_ONE_COMMAND_START.md`
34. `docs/V5_53_COMMIT_ALLOWLIST.md`
35. `docs/V5_53_MFU_IAM_AND_SHARED_DEPLOYMENT_READINESS.md`
36. `frontend/src/hooks/useApiQueries.ts`
37. `frontend/src/lib/api.ts`
38. `frontend/src/pages/MLGovernance.tsx`
39. `frontend/src/pages/UserAdmin.tsx`
40. `frontend/src/types/api.ts`
41. `frontend/tests/smoke.spec.ts`
42. `README.md`
43. `requirements.lock.txt`
44. `requirements.txt`

## Mandatory Exclusions

Do not stage private `.env` files, databases, raw/private logs, labels, review
outputs, model artifacts, provider payloads, acceptance manifests, generated
reports, SBOM output, `ml_baseline_reviews/`, `demo_exports/`, processed
evidence, tokens, credentials, keys, or secrets.

## Pre-Commit Reconciliation

- Changed-path set must equal these 44 paths exactly.
- Staging must be empty until separate explicit approval.
- `git diff --check` must pass.
- Private/ignored evidence and generated outputs must remain untracked.
- Repository secret/path scan and dependency audits must pass.
- No commit or push is authorized by this file.
