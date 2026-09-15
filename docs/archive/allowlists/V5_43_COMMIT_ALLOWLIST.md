# v5.43 Exact Commit Allowlist

No commit or push is authorized by this document. A separate explicit user
approval is required.

The exact v5.43 tracked path set is:

1. `atdr/app/detection/v543_temporal_stability_repair.py`
2. `atdr/app/routers/evidence_review.py`
3. `atdr/app/schemas/evidence_review.py`
4. `atdr/scripts/apply_template_atdr_launcher.py`
5. `atdr/scripts/run_v543_temporal_stability_repair.py`
6. `atdr/tests/test_v537_evidence_review_workspace.py`
7. `atdr/tests/test_v543_temporal_stability_repair.py`
8. `docs/AI_TRAINING_RUNBOOK.md`
9. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
10. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
11. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
12. `docs/V5_43_COMMIT_ALLOWLIST.md`
13. `docs/V5_43_DEVELOPMENT_TEMPORAL_STABILITY_REPAIR.md`
14. `docs/changes/T1_T20_V5_43_DEVELOPMENT_TEMPORAL_STABILITY_REPAIR.md`
15. `docs/prd/PRD-ATDR.md`
16. `docs/tasks/tasklist-progress.html`
17. `docs/tasks/tasklist-progress.md`
18. `frontend/src/hooks/useApiQueries.ts`
19. `frontend/src/lib/api.ts`
20. `frontend/src/pages/MLGovernance.tsx`
21. `frontend/src/types/api.ts`
22. `frontend/tests/smoke.spec.ts`

Explicitly excluded are `.env` files, credentials, databases, private logs,
raw evidence, labels/reviews, model artifacts, generated reports,
`ml_baseline_reviews/`, `demo_exports/`, processed evidence, caches, paths,
fingerprints, source identities, predictions, IP addresses, and secrets.

The allowlist does not authorize a commit, push, model freeze, activation,
promotion, alert-authority change, automatic response, or real firewall action.
