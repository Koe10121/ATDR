# v5.4 Exact Commit Allowlist

This file defines only the v5.4 Temporal Evidence Curation and Shadow Drift
Monitoring phase. It does not authorize staging, committing, or pushing.

## Exact v5.4 Paths

1. `atdr/app/detection/v54_temporal_evidence.py`
2. `atdr/scripts/run_v54_temporal_evidence_preparation.py`
3. `atdr/tests/test_v54_temporal_evidence.py`
4. `data/samples/benchmarks/v53_temporal_evidence_lock.json`
5. `atdr/app/detection/v51_supervised_lifecycle.py`
6. `frontend/src/types/api.ts`
7. `frontend/src/pages/MLGovernance.tsx`
8. `frontend/tests/smoke.spec.ts`
9. `docs/V5_4_TEMPORAL_EVIDENCE_AND_SHADOW_DRIFT.md`
10. `docs/changes/T1_T20_V5_4_TEMPORAL_EVIDENCE_AND_SHADOW_DRIFT.md`
11. `docs/V5_4_COMMIT_ALLOWLIST.md`
12. `docs/prd/PRD-ATDR.md`
13. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
14. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
15. `docs/AI_TRAINING_RUNBOOK.md`
16. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
17. `docs/AI-DOCS-INDEX.md`
18. `docs/tasks/tasklist-progress.md`
19. `docs/tasks/tasklist-progress.html`

## Explicitly Excluded

- `.env*` private configuration and secrets;
- databases, logs, processed evidence, and private PAN-OS files;
- `ml_baseline_reviews/` reports, manifests, or review packs;
- `demo_exports/` and generated JSON/CSV/HTML/PDF evidence;
- model binaries and active/candidate artifact directories; and
- any cumulative path not listed above.

Before any separately approved commit, compare the staged path set exactly with
this list, run `git diff --check`, and repeat protected-artifact and secret
hygiene checks. Never force-push.
