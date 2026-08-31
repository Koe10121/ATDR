# v5.47 Exact Commit Allowlist

No commit or push is authorized by this document. A separate explicit user
approval is required.

Because v5.43-v5.46 remain uncommitted, the exact cumulative v5.43-v5.47
tracked path set is 50 paths:

1. `.gitignore`
2. `atdr/app/detection/v541_governed_blind_evidence.py`
3. `atdr/app/detection/v543_temporal_stability_repair.py`
4. `atdr/app/detection/v544_chronological_evidence.py`
5. `atdr/app/detection/v545_development_model_repair.py`
6. `atdr/app/detection/v546_manual_anchor_transfer_repair.py`
7. `atdr/app/detection/v547_manual_anchor_acquisition.py`
8. `atdr/app/detection/v56_private_panos_model_repair.py`
9. `atdr/app/routers/evidence_review.py`
10. `atdr/app/schemas/evidence_review.py`
11. `atdr/scripts/apply_template_atdr_launcher.py`
12. `atdr/scripts/run_v543_temporal_stability_repair.py`
13. `atdr/scripts/run_v544_chronological_evidence_expansion.py`
14. `atdr/scripts/run_v545_development_model_repair.py`
15. `atdr/scripts/run_v546_manual_anchor_transfer_repair.py`
16. `atdr/scripts/run_v547_manual_anchor_acquisition.py`
17. `atdr/tests/test_v537_evidence_review_workspace.py`
18. `atdr/tests/test_v541_governed_blind_evidence.py`
19. `atdr/tests/test_v543_temporal_stability_repair.py`
20. `atdr/tests/test_v544_chronological_evidence.py`
21. `atdr/tests/test_v545_development_model_repair.py`
22. `atdr/tests/test_v546_manual_anchor_transfer_repair.py`
23. `atdr/tests/test_v547_manual_anchor_acquisition.py`
24. `docs/AI_TRAINING_RUNBOOK.md`
25. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
26. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
27. `docs/changes/T1_T20_V5_43_DEVELOPMENT_TEMPORAL_STABILITY_REPAIR.md`
28. `docs/changes/T1_T20_V5_44_CHRONOLOGICAL_EVIDENCE_EXPANSION.md`
29. `docs/changes/T1_T20_V5_45_DEVELOPMENT_ONLY_SUPERVISED_MODEL_REPAIR.md`
30. `docs/changes/T1_T20_V5_46_MANUAL_ANCHOR_TRANSFER_AND_CALIBRATION_REPAIR.md`
31. `docs/changes/T1_T20_V5_47_PREDICTION_BLIND_MANUAL_ANCHOR_ACQUISITION.md`
32. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
33. `docs/prd/PRD-ATDR.md`
34. `docs/tasks/tasklist-progress.html`
35. `docs/tasks/tasklist-progress.md`
36. `docs/V5_43_COMMIT_ALLOWLIST.md`
37. `docs/V5_43_DEVELOPMENT_TEMPORAL_STABILITY_REPAIR.md`
38. `docs/V5_44_CHRONOLOGICAL_EVIDENCE_EXPANSION.md`
39. `docs/V5_44_COMMIT_ALLOWLIST.md`
40. `docs/V5_45_COMMIT_ALLOWLIST.md`
41. `docs/V5_45_DEVELOPMENT_ONLY_SUPERVISED_MODEL_REPAIR.md`
42. `docs/V5_46_COMMIT_ALLOWLIST.md`
43. `docs/V5_46_MANUAL_ANCHOR_TRANSFER_AND_CALIBRATION_REPAIR.md`
44. `docs/V5_47_COMMIT_ALLOWLIST.md`
45. `docs/V5_47_PREDICTION_BLIND_MANUAL_ANCHOR_ACQUISITION.md`
46. `frontend/src/hooks/useApiQueries.ts`
47. `frontend/src/lib/api.ts`
48. `frontend/src/pages/MLGovernance.tsx`
49. `frontend/src/types/api.ts`
50. `frontend/tests/smoke.spec.ts`

Explicitly excluded are `.env` files, credentials, databases, private logs,
raw evidence, labels/reviews, sealed/working review packs, model artifacts,
generated reports, `ml_baseline_reviews/`, `demo_exports/`, processed
evidence, test outputs, private paths, fingerprints, source identities,
predictions, IP addresses, provider payloads, and secrets.

This allowlist does not authorize a commit, push, human-label import, training,
candidate freeze, model activation or promotion, alert-authority change,
automatic response, or real firewall action.
