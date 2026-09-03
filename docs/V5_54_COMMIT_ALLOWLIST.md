# v5.54 Commit Allowlist

Date: 2026-09-03

This is the exact tracked-path review boundary for v5.54 Release Candidate
Truth Lock And Operator Handoff. It authorizes no staging, commit, push, merge,
deployment, model activation, or external acceptance. Separate explicit user
approval is required for any Git publication.

## Exact Paths

1. `README.md`
2. `atdr/app/schemas/operations.py`
3. `atdr/app/services/v553_release_readiness_service.py`
4. `atdr/scripts/run_v553_team_runtime_acceptance.py`
5. `atdr/tests/test_v553_release_readiness.py`
6. `docs/AI-DOCS-INDEX.md`
7. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
8. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
9. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
10. `docs/CURRENT_SYSTEM_STATE_LOCK.md`
11. `docs/DEPLOYMENT_GUIDE.md`
12. `docs/LAB_RUNBOOK.md`
13. `docs/OPERATIONS_RUNBOOK.md`
14. `docs/QUICKSTART_FOR_TEAM.md`
15. `docs/TEAM_ONE_COMMAND_START.md`
16. `docs/V5_54_COMMIT_ALLOWLIST.md`
17. `docs/V5_54_EXTERNAL_OWNER_ACCEPTANCE.md`
18. `docs/V5_54_OPERATOR_HANDOFF.md`
19. `docs/V5_54_RELEASE_CANDIDATE_TRUTH_LOCK.md`
20. `docs/changes/T1_T20_V5_54_RELEASE_CANDIDATE_TRUTH_LOCK.md`
21. `docs/prd/PRD-ATDR.md`
22. `docs/tasks/tasklist-progress.html`
23. `docs/tasks/tasklist-progress.md`
24. `frontend/src/components/Badge.tsx`
25. `frontend/src/pages/UserAdmin.tsx`
26. `frontend/src/types/api.ts`
27. `frontend/tests/smoke.spec.ts`

## Mandatory Exclusions

Do not stage private `.env` files, databases, raw/private logs, labels,
protected reviews, model artifacts, provider payloads, acceptance manifests,
generated reports, SBOM output, `ml_baseline_reviews/`, `demo_exports/`,
processed evidence, temporary databases, tokens, credentials, keys, or
secrets.

## Pre-Commit Reconciliation

- Changed-path set must equal these 27 paths exactly.
- Staging must remain empty until separate explicit approval.
- `git diff --check` must pass.
- Repository security scan and dependency audits must pass.
- Private/ignored evidence must remain untracked.
- Protected v5.49b evidence must remain unopened and unmodified.
- No commit or push is authorized by this file.
