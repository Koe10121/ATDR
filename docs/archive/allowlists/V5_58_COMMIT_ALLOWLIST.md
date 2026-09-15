# v5.58 Commit Allowlist

Date: 2026-09-05

This is the exact tracked-path review boundary for v5.58 Governed Hybrid
Detection Runtime Closure. It authorizes no staging, commit, push, merge,
deployment, model activation, provider approval, or external acceptance.
Separate explicit user approval is required for any Git publication.

## Exact Paths

1. `README.md`
2. `atdr/app/detection/explanations.py`
3. `atdr/app/detection/runtime_contract.py`
4. `atdr/app/detection/supervised_detector.py`
5. `atdr/app/detection/supervised_workflow.py`
6. `atdr/app/detection/v51_supervised_lifecycle.py`
7. `atdr/app/routers/ml.py`
8. `atdr/app/services/assistant_service.py`
9. `atdr/app/services/detection_service.py`
10. `atdr/scripts/run_v558_governed_hybrid_runtime.py`
11. `atdr/tests/test_api.py`
12. `atdr/tests/test_supervised_ml.py`
13. `atdr/tests/test_v558_governed_hybrid_runtime.py`
14. `docs/AI-DOCS-INDEX.md`
15. `docs/AI_TRAINING_RUNBOOK.md`
16. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
17. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
18. `docs/changes/T1_T20_V5_58_GOVERNED_HYBRID_DETECTION_RUNTIME.md`
19. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
20. `docs/CURRENT_SYSTEM_STATE_LOCK.md`
21. `docs/prd/PRD-ATDR.md`
22. `docs/tasks/tasklist-progress.html`
23. `docs/tasks/tasklist-progress.md`
24. `docs/V5_58_COMMIT_ALLOWLIST.md`
25. `docs/V5_58_GOVERNED_HYBRID_DETECTION_RUNTIME.md`
26. `docs/V5_59_REPOSITORY_CONSOLIDATION_PLAN.md`
27. `frontend/src/components/MetricCard.tsx`
28. `frontend/src/hooks/useApiQueries.ts`
29. `frontend/src/lib/api.ts`
30. `frontend/src/pages/AlertsTriage.tsx`
31. `frontend/src/pages/ExecutiveOverview.tsx`
32. `frontend/src/pages/MLGovernance.tsx`
33. `frontend/src/types/api.ts`
34. `frontend/tests/smoke.spec.ts`

## Mandatory Exclusions

Do not stage private `.env` files, databases, raw or private logs, labels,
protected reviews, model artifacts, generated reports, provider prompts or
responses, provider payloads, SBOM output, `ml_baseline_reviews/`,
`demo_exports/`, processed evidence, temporary databases, acceptance
manifests, tokens, credentials, keys, or secrets.

## Pre-Commit Reconciliation

- Changed-path set must equal these 34 paths exactly.
- Staging must remain empty until separate explicit approval.
- `git diff --check` must pass.
- Repository security scan and complete verification matrix must pass.
- Private and generated evidence must remain ignored and untracked.
- Consumed v5.49b evidence must remain unopened and unmodified.
- No model activation, automatic response, or real blocking is authorized.
- No commit or push is authorized by this file.
