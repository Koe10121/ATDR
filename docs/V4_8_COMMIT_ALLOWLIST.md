# v4.8 Exact Cumulative Commit Allowlist

No commit or push is authorized by this file.

v4.7 remains uncommitted in the current worktree, and the shared documentation files now contain both v4.7 and v4.8 updates. Therefore, any future single closure commit must stage exactly this cumulative 17-path boundary and nothing else:

1. `atdr/app/services/dashboard_service.py`
2. `atdr/scripts/profile_dashboard_summary.py`
3. `atdr/tests/test_v47_overview_performance.py`
4. `docs/V4_7_LARGE_SQLITE_PERFORMANCE_STABILIZATION.md`
5. `docs/V4_7_COMMIT_ALLOWLIST.md`
6. `docs/changes/T1_T20_V4_7_LARGE_SQLITE_PERFORMANCE.md`
7. `atdr/scripts/run_v48_product_acceptance.py`
8. `atdr/tests/test_v48_product_acceptance.py`
9. `docs/V4_8_END_TO_END_PRODUCT_ACCEPTANCE.md`
10. `docs/V4_8_COMMIT_ALLOWLIST.md`
11. `docs/changes/T1_T20_V4_8_PRODUCT_ACCEPTANCE.md`
12. `docs/LAB_RUNBOOK.md`
13. `docs/prd/PRD-ATDR.md`
14. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
15. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
16. `docs/tasks/tasklist-progress.md`
17. `docs/tasks/tasklist-progress.html`

Explicitly excluded: `.env`, databases, logs, raw evidence, model artifacts, review data, generated reports, benchmark snapshots, `ml_baseline_reviews/`, `demo_exports/`, processed data, temporary/pytest/runtime files, and every path not listed above.
