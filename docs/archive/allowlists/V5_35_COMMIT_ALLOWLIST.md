# v5.35 Exact Commit Allowlist

This file does not authorize a commit or push. A repository owner must provide
separate explicit approval before staging these exact paths:

1. `atdr/app/db/models.py`
2. `atdr/scripts/performance_smoke.py`
3. `atdr/scripts/profile_dashboard_summary.py`
4. `atdr/tests/test_v47_overview_performance.py`
5. `atdr/tests/test_v535_overview_stabilization.py`
6. `migrations/versions/f8a9b0c1d2e3_add_overview_source_volume_covering_indexes.py`
7. `migrations/versions/b9c0d1e2f3a4_add_ml_governance_distribution_indexes.py`
8. `docs/V5_35_LARGE_SQLITE_OVERVIEW_STABILIZATION.md`
9. `docs/changes/T1_T20_V5_35_LARGE_SQLITE_OVERVIEW_STABILIZATION.md`
10. `docs/V5_35_COMMIT_ALLOWLIST.md`
11. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
12. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
13. `docs/prd/PRD-ATDR.md`
14. `docs/LAB_RUNBOOK.md`
15. `docs/tasks/tasklist-progress.md`
16. `docs/tasks/tasklist-progress.html`

Explicitly excluded: `.env` files, databases, private logs, labels/reviews,
model artifacts, `ml_baseline_reviews/`, `demo_exports/`, processed evidence,
temporary profiles, generated reports, and every path not listed above.
