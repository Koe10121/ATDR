# v4.7 Exact Commit Allowlist

No commit or push is authorized by this file. After final verification, a repository owner may explicitly approve staging exactly these paths and no others:

1. `atdr/app/services/dashboard_service.py`
2. `atdr/scripts/profile_dashboard_summary.py`
3. `atdr/tests/test_v47_overview_performance.py`
4. `docs/V4_7_LARGE_SQLITE_PERFORMANCE_STABILIZATION.md`
5. `docs/V4_7_COMMIT_ALLOWLIST.md`
6. `docs/changes/T1_T20_V4_7_LARGE_SQLITE_PERFORMANCE.md`
7. `docs/LAB_RUNBOOK.md`
8. `docs/prd/PRD-ATDR.md`
9. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
10. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
11. `docs/tasks/tasklist-progress.md`
12. `docs/tasks/tasklist-progress.html`

Explicitly excluded: `.env`, databases, logs, raw evidence, model artifacts, review data, benchmark snapshots, generated reports, `ml_baseline_reviews/`, `demo_exports/`, processed data, pytest/runtime files, and every path not listed above.
