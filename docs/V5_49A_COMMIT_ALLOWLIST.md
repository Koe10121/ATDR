# v5.49a Exact Cumulative Commit Allowlist

No commit or push is authorized by this document. A separate explicit user
approval is required.

Because v5.43-v5.49 remain uncommitted, the exact cumulative v5.43-v5.49a
tracked path set is 72 paths:

1. `.gitignore`
2. `atdr/app/detection/v541_governed_blind_evidence.py`
3. `atdr/app/detection/v543_temporal_stability_repair.py`
4. `atdr/app/detection/v544_chronological_evidence.py`
5. `atdr/app/detection/v545_development_model_repair.py`
6. `atdr/app/detection/v546_manual_anchor_transfer_repair.py`
7. `atdr/app/detection/v547_manual_anchor_acquisition.py`
8. `atdr/app/detection/v548_manual_anchor_fixed_revalidation.py`
9. `atdr/app/detection/v549_fixed_revalidation_decision.py`
10. `atdr/app/detection/v549a_supplemental_threat_anchor_acquisition.py`
11. `atdr/app/detection/v56_private_panos_model_repair.py`
12. `atdr/app/routers/evidence_review.py`
13. `atdr/app/schemas/evidence_review.py`
14. `atdr/app/services/v548_manual_anchor_review_service.py`
15. `atdr/app/services/v549a_supplemental_threat_anchor_review_service.py`
16. `atdr/scripts/apply_template_atdr_launcher.py`
17. `atdr/scripts/run_v543_temporal_stability_repair.py`
18. `atdr/scripts/run_v544_chronological_evidence_expansion.py`
19. `atdr/scripts/run_v545_development_model_repair.py`
20. `atdr/scripts/run_v546_manual_anchor_transfer_repair.py`
21. `atdr/scripts/run_v547_manual_anchor_acquisition.py`
22. `atdr/scripts/run_v548_manual_anchor_fixed_revalidation.py`
23. `atdr/scripts/run_v549_fixed_revalidation_decision.py`
24. `atdr/scripts/run_v549a_supplemental_threat_anchor_acquisition.py`
25. `atdr/tests/test_v537_evidence_review_workspace.py`
26. `atdr/tests/test_v541_governed_blind_evidence.py`
27. `atdr/tests/test_v543_temporal_stability_repair.py`
28. `atdr/tests/test_v544_chronological_evidence.py`
29. `atdr/tests/test_v545_development_model_repair.py`
30. `atdr/tests/test_v546_manual_anchor_transfer_repair.py`
31. `atdr/tests/test_v547_manual_anchor_acquisition.py`
32. `atdr/tests/test_v548_manual_anchor_review.py`
33. `atdr/tests/test_v549_fixed_revalidation_decision.py`
34. `atdr/tests/test_v549a_supplemental_threat_anchor_recovery.py`
35. `docs/AI_TRAINING_RUNBOOK.md`
36. `docs/ATDR_PRODUCT_FINISH_LINE.md`
37. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
38. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
39. `docs/changes/T1_T20_V5_43_DEVELOPMENT_TEMPORAL_STABILITY_REPAIR.md`
40. `docs/changes/T1_T20_V5_44_CHRONOLOGICAL_EVIDENCE_EXPANSION.md`
41. `docs/changes/T1_T20_V5_45_DEVELOPMENT_ONLY_SUPERVISED_MODEL_REPAIR.md`
42. `docs/changes/T1_T20_V5_46_MANUAL_ANCHOR_TRANSFER_AND_CALIBRATION_REPAIR.md`
43. `docs/changes/T1_T20_V5_47_PREDICTION_BLIND_MANUAL_ANCHOR_ACQUISITION.md`
44. `docs/changes/T1_T20_V5_48_PROTECTED_MANUAL_ANCHOR_REVIEW_AND_FIXED_REVALIDATION.md`
45. `docs/changes/T1_T20_V5_49_FIXED_DEVELOPMENT_REVALIDATION_AND_CANDIDATE_DECISION.md`
46. `docs/changes/T1_T20_V5_49A_SUPPLEMENTAL_THREAT_ANCHOR_RECOVERY.md`
47. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
48. `docs/prd/PRD-ATDR.md`
49. `docs/tasks/tasklist-progress.html`
50. `docs/tasks/tasklist-progress.md`
51. `docs/V5_43_COMMIT_ALLOWLIST.md`
52. `docs/V5_43_DEVELOPMENT_TEMPORAL_STABILITY_REPAIR.md`
53. `docs/V5_44_CHRONOLOGICAL_EVIDENCE_EXPANSION.md`
54. `docs/V5_44_COMMIT_ALLOWLIST.md`
55. `docs/V5_45_COMMIT_ALLOWLIST.md`
56. `docs/V5_45_DEVELOPMENT_ONLY_SUPERVISED_MODEL_REPAIR.md`
57. `docs/V5_46_COMMIT_ALLOWLIST.md`
58. `docs/V5_46_MANUAL_ANCHOR_TRANSFER_AND_CALIBRATION_REPAIR.md`
59. `docs/V5_47_COMMIT_ALLOWLIST.md`
60. `docs/V5_47_PREDICTION_BLIND_MANUAL_ANCHOR_ACQUISITION.md`
61. `docs/V5_48_COMMIT_ALLOWLIST.md`
62. `docs/V5_48_PROTECTED_MANUAL_ANCHOR_REVIEW_AND_FIXED_REVALIDATION.md`
63. `docs/V5_49_COMMIT_ALLOWLIST.md`
64. `docs/V5_49_FIXED_DEVELOPMENT_REVALIDATION_AND_CANDIDATE_DECISION.md`
65. `docs/V5_49A_COMMIT_ALLOWLIST.md`
66. `docs/V5_49A_SUPPLEMENTAL_THREAT_ANCHOR_RECOVERY.md`
67. `frontend/src/hooks/useApiQueries.ts`
68. `frontend/src/lib/api.ts`
69. `frontend/src/pages/EvidenceReviewPage.tsx`
70. `frontend/src/pages/MLGovernance.tsx`
71. `frontend/src/types/api.ts`
72. `frontend/tests/smoke.spec.ts`

Explicitly excluded are `.env` files, credentials, databases, private logs,
raw evidence, labels/reviews, sealed or working review packs, review state,
protocol proposals, execution claims/results, model artifacts, generated
reports, `ml_baseline_reviews/`, `demo_exports/`, processed evidence, test
outputs, private paths, fingerprints, source identities, predictions, IP
addresses, provider payloads, and secrets.

This allowlist does not authorize a commit, push, human-label import, model
evaluation, training, candidate freeze, activation, promotion, alert-authority
change, automatic response, or real firewall action.
