# v4.6 Repository Hygiene Report

Date: 2026-07-16

## Scope

The v4.6 change introduces source code, tests, documentation, and a non-secret package contract. The built MFU shell archive and all clean-room evidence remain ignored runtime artifacts.

## Package Audit

- Archive: `mfu-atdr-shell-1.4.0-atdr.1.zip`
- Files: 454
- Private configuration included: no
- Secrets exposed: no
- Unsafe archive paths: none
- Environment files: none
- Database/log/model/upload/backup artifacts: none
- Archive SHA-256: locked in `config/mfu-shell-contract.json`
- Source fingerprint: locked in `config/mfu-shell-contract.json`

The source template contained private environment files and generated/dependency content. Those inputs were not copied into the package or repository.

## Git Boundary

The exact v4.6 commit boundary is listed in `docs/V4_6_COMMIT_ALLOWLIST.md`. It excludes:

- `.env` and private shell environment files;
- `atdr.db`, SQLite/PostgreSQL data, and backups;
- real/private logs and uploads;
- model artifacts and provider benchmark files;
- `ml_baseline_reviews/`, `demo_exports/`, processed logs, and generated reports;
- `.atdr_runtime/`, clean-room clones, installed shell source, dependencies, and package archives.

No commit or push is authorized by this document. A repository owner must review and explicitly approve the exact allowlist first.

## Final Audit Result

- Git status paths: 22
- Allowlisted paths: 22
- Extra paths: 0
- Missing paths: 0
- Staged paths: 0
- Tracked paths inspected: 1,483
- Forbidden tracked private environment/DB/log/model/review/export artifacts: 0
- Package archive: ignored and retained only under local `.atdr_runtime/`
- Disposable clean-room clone: removed after acceptance
- `git diff --check`: passed; only the repository's normal Windows LF-to-CRLF notices were emitted
