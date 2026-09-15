# v5.38 Exact Commit Allowlist

This file does not authorize a commit or push. A repository owner must provide
separate explicit approval before staging these exact 20 paths:

1. `atdr/app/services/v538_product_reliability_service.py`
2. `atdr/scripts/run_v538_product_reliability_acceptance.py`
3. `atdr/tests/test_v538_product_reliability.py`
4. `scripts/system_common.ps1`
5. `scripts/start_system.ps1`
6. `frontend/src/components/ErrorBanner.tsx`
7. `frontend/src/pages/ExecutiveOverview.tsx`
8. `frontend/src/pages/MLGovernance.tsx`
9. `frontend/src/pages/ResponseCenter.tsx`
10. `frontend/tests/smoke.spec.ts`
11. `docs/V5_38_PRODUCT_RELIABILITY_AND_FAILURE_MODE_LOCK.md`
12. `docs/changes/T1_T20_V5_38_PRODUCT_RELIABILITY_LOCK.md`
13. `docs/V5_38_COMMIT_ALLOWLIST.md`
14. `docs/QUICKSTART_FOR_TEAM.md`
15. `docs/LAB_RUNBOOK.md`
16. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
17. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
18. `docs/prd/PRD-ATDR.md`
19. `docs/tasks/tasklist-progress.md`
20. `docs/tasks/tasklist-progress.html`

Explicitly excluded: `.env` files, databases, private logs, raw evidence,
labels, review outputs, model artifacts, `ml_baseline_reviews/`,
`demo_exports/`, processed evidence, generated reports, provider payloads,
API keys, and every path not listed above.
