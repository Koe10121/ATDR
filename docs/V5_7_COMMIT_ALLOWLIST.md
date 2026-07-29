# v5.7 Exact Commit Allowlist

Date: 2026-07-26

This document defines the exact tracked change boundary for v5.7 Independent
Evidence Readiness and Blind Shadow Revalidation. It is not authorization to
stage, commit, or push.

## Allowed Paths

1. `atdr/app/detection/v51_supervised_lifecycle.py`
2. `atdr/app/detection/v57_independent_shadow_revalidation.py`
3. `atdr/scripts/run_v57_independent_shadow_revalidation.py`
4. `atdr/tests/test_v57_independent_shadow_revalidation.py`
5. `data/samples/benchmarks/v57_independent_evidence_manifest.template.json`
6. `frontend/src/components/Badge.tsx`
7. `frontend/src/pages/MLGovernance.tsx`
8. `frontend/src/types/api.ts`
9. `frontend/tests/smoke.spec.ts`
10. `docs/detection/V5_7_INDEPENDENT_EVIDENCE_ACQUISITION.md`
11. `docs/V5_7_INDEPENDENT_EVIDENCE_READINESS_AND_BLIND_REVALIDATION.md`
12. `docs/changes/T1_T20_V5_7_INDEPENDENT_EVIDENCE_READINESS_AND_BLIND_REVALIDATION.md`
13. `docs/prd/PRD-ATDR.md`
14. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
15. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
16. `docs/AI_TRAINING_RUNBOOK.md`
17. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
18. `docs/AI-DOCS-INDEX.md`
19. `docs/tasks/tasklist-progress.md`
20. `docs/tasks/tasklist-progress.html`
21. `docs/V5_7_COMMIT_ALLOWLIST.md`

## Explicit Exclusions

- `.env` files and secrets;
- database files;
- private or real logs and their paths;
- `ml_baseline_reviews/`;
- `demo_exports/`;
- `atdr/data/processed/`;
- trained model artifacts;
- prediction freezes, review packs, lock audits, and generated reports; and
- every cumulative v4.9-v5.6 worktree path not listed above.

Before any separately authorized commit, compare the staged path set exactly
against these 21 paths and stop on any difference. Do not force-push.
