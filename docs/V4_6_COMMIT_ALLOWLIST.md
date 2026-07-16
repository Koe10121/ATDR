# v4.6 Exact Commit Allowlist

No commit or push is authorized by this file. After verification, a repository owner may explicitly approve staging exactly these paths and no others:

1. `.gitignore`
2. `README.md`
3. `config/mfu-shell-contract.json`
4. `scripts/check_system.ps1`
5. `scripts/setup_team.ps1`
6. `scripts/start_system.ps1`
7. `scripts/system_common.ps1`
8. `atdr/app/services/mfu_shell_package_service.py`
9. `atdr/scripts/mfu_shell_package.py`
10. `atdr/tests/test_v46_mfu_shell_distribution.py`
11. `docs/V4_6_VERSIONED_MFU_SHELL_DISTRIBUTION.md`
12. `docs/V4_6_REPO_HYGIENE_REPORT.md`
13. `docs/V4_6_COMMIT_ALLOWLIST.md`
14. `docs/changes/T1_T20_V4_6_VERSIONED_MFU_SHELL_DISTRIBUTION.md`
15. `docs/TEAM_ONE_COMMAND_START.md`
16. `docs/QUICKSTART_FOR_TEAM.md`
17. `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
18. `docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md`
19. `docs/prd/PRD-ATDR.md`
20. `docs/AI-DOCS-INDEX.md`
21. `docs/tasks/tasklist-progress.md`
22. `docs/tasks/tasklist-progress.html`

Explicitly excluded: the ZIP archive, `.atdr_runtime/`, clean-room files, private shell configuration, `.env`, databases, logs, uploads, dependencies, model artifacts, review/evidence directories, generated reports, and any path not listed above.
