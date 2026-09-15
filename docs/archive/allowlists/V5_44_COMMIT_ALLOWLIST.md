# v5.44 Exact Commit Allowlist

No commit or push is authorized by this document. A separate explicit user
approval is required.

Because v5.43 remains uncommitted, the exact cumulative v5.43-v5.44 tracked
path set is:

1. `atdr/app/detection/v541_governed_blind_evidence.py`
2. `atdr/app/detection/v543_temporal_stability_repair.py`
3. `atdr/app/detection/v544_chronological_evidence.py`
4. `atdr/app/detection/v56_private_panos_model_repair.py`
5. `atdr/app/routers/evidence_review.py`
6. `atdr/app/schemas/evidence_review.py`
7. `atdr/scripts/apply_template_atdr_launcher.py`
8. `atdr/scripts/run_v543_temporal_stability_repair.py`
9. `atdr/scripts/run_v544_chronological_evidence_expansion.py`
10. `atdr/tests/test_v537_evidence_review_workspace.py`
11. `atdr/tests/test_v541_governed_blind_evidence.py`
12. `atdr/tests/test_v543_temporal_stability_repair.py`
13. `atdr/tests/test_v544_chronological_evidence.py`
14. `docs/AI_TRAINING_RUNBOOK.md`
15. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
16. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
17. `docs/changes/T1_T20_V5_43_DEVELOPMENT_TEMPORAL_STABILITY_REPAIR.md`
18. `docs/changes/T1_T20_V5_44_CHRONOLOGICAL_EVIDENCE_EXPANSION.md`
19. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
20. `docs/prd/PRD-ATDR.md`
21. `docs/tasks/tasklist-progress.html`
22. `docs/tasks/tasklist-progress.md`
23. `docs/V5_43_COMMIT_ALLOWLIST.md`
24. `docs/V5_43_DEVELOPMENT_TEMPORAL_STABILITY_REPAIR.md`
25. `docs/V5_44_CHRONOLOGICAL_EVIDENCE_EXPANSION.md`
26. `docs/V5_44_COMMIT_ALLOWLIST.md`
27. `frontend/src/hooks/useApiQueries.ts`
28. `frontend/src/lib/api.ts`
29. `frontend/src/pages/MLGovernance.tsx`
30. `frontend/src/types/api.ts`
31. `frontend/tests/smoke.spec.ts`

Explicitly excluded are `.env` files, credentials, databases, private logs,
raw evidence, labels/reviews, model artifacts, generated reports,
`ml_baseline_reviews/`, `demo_exports/`, processed evidence, caches, private
paths, fingerprints, source identities, predictions, IP addresses, and
secrets.

The allowlist does not authorize a commit, push, model freeze, activation,
promotion, alert-authority change, automatic response, or real firewall
action.
