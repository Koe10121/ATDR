# v5.49 Exact Cumulative Commit Allowlist

No commit or push is authorized by this document. A separate explicit user
approval is required.

Because v5.43-v5.48 remain uncommitted, the exact cumulative v5.43-v5.49
tracked path set is 64 paths:

1. `.gitignore`
2. `atdr/app/detection/v541_governed_blind_evidence.py`
3. `atdr/app/detection/v543_temporal_stability_repair.py`
4. `atdr/app/detection/v544_chronological_evidence.py`
5. `atdr/app/detection/v545_development_model_repair.py`
6. `atdr/app/detection/v546_manual_anchor_transfer_repair.py`
7. `atdr/app/detection/v547_manual_anchor_acquisition.py`
8. `atdr/app/detection/v548_manual_anchor_fixed_revalidation.py`
9. `atdr/app/detection/v549_fixed_revalidation_decision.py`
10. `atdr/app/detection/v56_private_panos_model_repair.py`
11. `atdr/app/routers/evidence_review.py`
12. `atdr/app/schemas/evidence_review.py`
13. `atdr/app/services/v548_manual_anchor_review_service.py`
14. `atdr/scripts/apply_template_atdr_launcher.py`
15. `atdr/scripts/run_v543_temporal_stability_repair.py`
16. `atdr/scripts/run_v544_chronological_evidence_expansion.py`
17. `atdr/scripts/run_v545_development_model_repair.py`
18. `atdr/scripts/run_v546_manual_anchor_transfer_repair.py`
19. `atdr/scripts/run_v547_manual_anchor_acquisition.py`
20. `atdr/scripts/run_v548_manual_anchor_fixed_revalidation.py`
21. `atdr/scripts/run_v549_fixed_revalidation_decision.py`
22. `atdr/tests/test_v537_evidence_review_workspace.py`
23. `atdr/tests/test_v541_governed_blind_evidence.py`
24. `atdr/tests/test_v543_temporal_stability_repair.py`
25. `atdr/tests/test_v544_chronological_evidence.py`
26. `atdr/tests/test_v545_development_model_repair.py`
27. `atdr/tests/test_v546_manual_anchor_transfer_repair.py`
28. `atdr/tests/test_v547_manual_anchor_acquisition.py`
29. `atdr/tests/test_v548_manual_anchor_review.py`
30. `atdr/tests/test_v549_fixed_revalidation_decision.py`
31. `docs/AI_TRAINING_RUNBOOK.md`
32. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
33. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
34. `docs/changes/T1_T20_V5_43_DEVELOPMENT_TEMPORAL_STABILITY_REPAIR.md`
35. `docs/changes/T1_T20_V5_44_CHRONOLOGICAL_EVIDENCE_EXPANSION.md`
36. `docs/changes/T1_T20_V5_45_DEVELOPMENT_ONLY_SUPERVISED_MODEL_REPAIR.md`
37. `docs/changes/T1_T20_V5_46_MANUAL_ANCHOR_TRANSFER_AND_CALIBRATION_REPAIR.md`
38. `docs/changes/T1_T20_V5_47_PREDICTION_BLIND_MANUAL_ANCHOR_ACQUISITION.md`
39. `docs/changes/T1_T20_V5_48_PROTECTED_MANUAL_ANCHOR_REVIEW_AND_FIXED_REVALIDATION.md`
40. `docs/changes/T1_T20_V5_49_FIXED_DEVELOPMENT_REVALIDATION_AND_CANDIDATE_DECISION.md`
41. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
42. `docs/prd/PRD-ATDR.md`
43. `docs/tasks/tasklist-progress.html`
44. `docs/tasks/tasklist-progress.md`
45. `docs/V5_43_COMMIT_ALLOWLIST.md`
46. `docs/V5_43_DEVELOPMENT_TEMPORAL_STABILITY_REPAIR.md`
47. `docs/V5_44_CHRONOLOGICAL_EVIDENCE_EXPANSION.md`
48. `docs/V5_44_COMMIT_ALLOWLIST.md`
49. `docs/V5_45_COMMIT_ALLOWLIST.md`
50. `docs/V5_45_DEVELOPMENT_ONLY_SUPERVISED_MODEL_REPAIR.md`
51. `docs/V5_46_COMMIT_ALLOWLIST.md`
52. `docs/V5_46_MANUAL_ANCHOR_TRANSFER_AND_CALIBRATION_REPAIR.md`
53. `docs/V5_47_COMMIT_ALLOWLIST.md`
54. `docs/V5_47_PREDICTION_BLIND_MANUAL_ANCHOR_ACQUISITION.md`
55. `docs/V5_48_COMMIT_ALLOWLIST.md`
56. `docs/V5_48_PROTECTED_MANUAL_ANCHOR_REVIEW_AND_FIXED_REVALIDATION.md`
57. `docs/V5_49_COMMIT_ALLOWLIST.md`
58. `docs/V5_49_FIXED_DEVELOPMENT_REVALIDATION_AND_CANDIDATE_DECISION.md`
59. `frontend/src/hooks/useApiQueries.ts`
60. `frontend/src/lib/api.ts`
61. `frontend/src/pages/EvidenceReviewPage.tsx`
62. `frontend/src/pages/MLGovernance.tsx`
63. `frontend/src/types/api.ts`
64. `frontend/tests/smoke.spec.ts`

Explicitly excluded are `.env` files, credentials, databases, private logs,
raw evidence, labels/reviews, sealed/working review packs, review state,
protocol/claim/result files, model artifacts, generated reports,
`ml_baseline_reviews/`, `demo_exports/`, processed evidence, test outputs,
private paths, fingerprints, source identities, predictions, IP addresses,
provider payloads, and secrets.

This allowlist does not authorize a commit, push, human-label import, training,
candidate freeze, model activation or promotion, alert-authority change,
automatic response, or real firewall action.
