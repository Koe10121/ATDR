# v5.46 Exact Commit Allowlist

No commit or push is authorized by this document. A separate explicit user
approval is required.

Because v5.43-v5.45 remain uncommitted, the exact cumulative v5.43-v5.46
tracked path set is 44 paths:

1. `.gitignore`
2. `atdr/app/detection/v541_governed_blind_evidence.py`
3. `atdr/app/detection/v543_temporal_stability_repair.py`
4. `atdr/app/detection/v544_chronological_evidence.py`
5. `atdr/app/detection/v545_development_model_repair.py`
6. `atdr/app/detection/v546_manual_anchor_transfer_repair.py`
7. `atdr/app/detection/v56_private_panos_model_repair.py`
8. `atdr/app/routers/evidence_review.py`
9. `atdr/app/schemas/evidence_review.py`
10. `atdr/scripts/apply_template_atdr_launcher.py`
11. `atdr/scripts/run_v543_temporal_stability_repair.py`
12. `atdr/scripts/run_v544_chronological_evidence_expansion.py`
13. `atdr/scripts/run_v545_development_model_repair.py`
14. `atdr/scripts/run_v546_manual_anchor_transfer_repair.py`
15. `atdr/tests/test_v537_evidence_review_workspace.py`
16. `atdr/tests/test_v541_governed_blind_evidence.py`
17. `atdr/tests/test_v543_temporal_stability_repair.py`
18. `atdr/tests/test_v544_chronological_evidence.py`
19. `atdr/tests/test_v545_development_model_repair.py`
20. `atdr/tests/test_v546_manual_anchor_transfer_repair.py`
21. `docs/AI_TRAINING_RUNBOOK.md`
22. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
23. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
24. `docs/changes/T1_T20_V5_43_DEVELOPMENT_TEMPORAL_STABILITY_REPAIR.md`
25. `docs/changes/T1_T20_V5_44_CHRONOLOGICAL_EVIDENCE_EXPANSION.md`
26. `docs/changes/T1_T20_V5_45_DEVELOPMENT_ONLY_SUPERVISED_MODEL_REPAIR.md`
27. `docs/changes/T1_T20_V5_46_MANUAL_ANCHOR_TRANSFER_AND_CALIBRATION_REPAIR.md`
28. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
29. `docs/prd/PRD-ATDR.md`
30. `docs/tasks/tasklist-progress.html`
31. `docs/tasks/tasklist-progress.md`
32. `docs/V5_43_COMMIT_ALLOWLIST.md`
33. `docs/V5_43_DEVELOPMENT_TEMPORAL_STABILITY_REPAIR.md`
34. `docs/V5_44_CHRONOLOGICAL_EVIDENCE_EXPANSION.md`
35. `docs/V5_44_COMMIT_ALLOWLIST.md`
36. `docs/V5_45_COMMIT_ALLOWLIST.md`
37. `docs/V5_45_DEVELOPMENT_ONLY_SUPERVISED_MODEL_REPAIR.md`
38. `docs/V5_46_COMMIT_ALLOWLIST.md`
39. `docs/V5_46_MANUAL_ANCHOR_TRANSFER_AND_CALIBRATION_REPAIR.md`
40. `frontend/src/hooks/useApiQueries.ts`
41. `frontend/src/lib/api.ts`
42. `frontend/src/pages/MLGovernance.tsx`
43. `frontend/src/types/api.ts`
44. `frontend/tests/smoke.spec.ts`

Explicitly excluded are `.env` files, credentials, databases, private logs,
raw evidence, labels/reviews, model artifacts, generated reports,
`ml_baseline_reviews/`, `demo_exports/`, processed evidence, test outputs,
private paths, fingerprints, source identities, predictions, IP addresses,
provider payloads, and secrets.

This allowlist does not authorize a commit, push, recipe/model freeze,
activation, promotion, alert-authority change, automatic response, or real
firewall action.
