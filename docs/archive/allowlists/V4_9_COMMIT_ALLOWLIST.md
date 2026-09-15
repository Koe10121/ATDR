# v4.9 Exact Commit Allowlist

No commit or push is authorized by this file.

Any future v4.9 closure commit must stage exactly these 45 paths and nothing else:

1. `README.md`
2. `atdr/app/detection/attack_mapping.py`
3. `atdr/app/detection/explanations.py`
4. `atdr/app/detection/rule_catalog.py`
5. `atdr/app/detection/rules.py`
6. `atdr/app/detection/v398_independent_holdout_validation.py`
7. `atdr/app/detection/v49_detection_ml_reliability.py`
8. `atdr/app/ml/features.py`
9. `atdr/app/parsers/paloalto_parser.py`
10. `atdr/app/services/alert_service.py`
11. `atdr/scripts/generate_detection_variants.py`
12. `atdr/scripts/performance_smoke.py`
13. `atdr/scripts/run_v49_detection_ml_reliability.py`
14. `atdr/scripts/send_sample_syslog.py`
15. `atdr/scripts/validate_rule_pack_contract.py`
16. `atdr/tests/test_api.py`
17. `atdr/tests/test_detection_validation_suite.py`
18. `atdr/tests/test_ml_baseline_review.py`
19. `atdr/tests/test_parser.py`
20. `atdr/tests/test_rule_pack_contract.py`
21. `atdr/tests/test_supervised_ml.py`
22. `atdr/tests/test_syslog_sender.py`
23. `atdr/tests/test_v46_mfu_shell_distribution.py`
24. `atdr/tests/test_v49_detection_ml_reliability.py`
25. `data/samples/benchmarks/cse_cic_ids2018_v49_manifest.json`
26. `data/samples/paloalto-demo.txt`
27. `data/samples/scenarios/scenario_expectations.json`
28. `docs/AI-DOCS-INDEX.md`
29. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
30. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
31. `docs/CURRENT_AI_ML_PRODUCT_STATUS.md`
32. `docs/V4_9_COMMIT_ALLOWLIST.md`
33. `docs/V4_9_DETECTION_ML_RELIABILITY_LOCK.md`
34. `docs/changes/T1_T20_V4_9_DETECTION_ML_RELIABILITY_LOCK.md`
35. `docs/detection/ATDR_DETECTION_TAXONOMY.md`
36. `docs/detection/ATDR_RULE_PACK_CONTRACT.md`
37. `docs/detection/ATDR_SCENARIO_CORPUS_CONTRACT.md`
38. `docs/prd/PRD-ATDR.md`
39. `docs/security/ATDR_DETECTION_LABELING_POLICY.md`
40. `docs/security/ATDR_DETECTION_RULE_STANDARD.md`
41. `docs/tasks/tasklist-progress.html`
42. `docs/tasks/tasklist-progress.md`
43. `frontend/src/components/Badge.tsx`
44. `frontend/src/pages/MLGovernance.tsx`
45. `frontend/tests/smoke.spec.ts`

Explicitly excluded: `.env` files, secrets, databases, private/real logs, raw or processed evidence, label/review exports, model artifacts, generated CSV/JSON/HTML/PDF reports, downloaded benchmark data, `ml_baseline_reviews/`, `demo_exports/`, frontend build/test output, temporary pytest/runtime files, and every path not listed above.
