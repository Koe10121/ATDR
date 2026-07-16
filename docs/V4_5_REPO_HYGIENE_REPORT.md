# v4.5 Repository Hygiene Report

## Result

The v4.5 source boundary contains application code, tests, migrations, safe synthetic samples, deployment references, and documentation only. No commit or push has been performed. The exact proposed source allowlist is recorded in `docs/V4_5_COMMIT_ALLOWLIST.md` and requires explicit approval before staging.

## Protected Local Material

The following remain ignored and must not be staged:

- `.env` and private frontend/shell environment files;
- `atdr.db`, SQLite backups, and any PostgreSQL dumps;
- real/private firewall or syslog files;
- model artifacts (`.joblib`, `.pkl`, `.onnx`, and similar);
- `ml_baseline_reviews/`, `demo_exports/`, processed logs, generated reports, and benchmark snapshots;
- `.venv/`, `node_modules/`, build output, Playwright output, caches, and `.atdr_runtime/`;
- the separately supplied MFU shell and its credentials.

## External Template Material

`NewSystem/` remains tracked historical university-template reference material. It is not part of ATDR runtime and is not the approved external MFU shell used by the launcher. It was not deleted in v4.5 because removal deserves a separate reviewed cleanup decision.

The approved MFU shell is supplied outside versioned ATDR source. `config/mfu-shell-contract.json` validates its expected structure without storing a private path or secret. A companion repository/release checksum is still missing.

## Hygiene Checks

- The candidate boundary contains exactly 175 modified or untracked source paths. It matches `docs/V4_5_COMMIT_ALLOWLIST.md`. The increase from the initial audit is the deliberate normalization of already-tracked personal paths in 44 historical/reference files plus the final shared SOC page-header, ML operating-policy, and assistant answer-renderer refactors.
- The 1,414 currently tracked paths contain no database or backup file and no model artifact. Environment-like tracked paths are examples only; the only protected output path is `atdr/data/processed/.gitkeep`.
- Candidate scans found zero Google/OpenAI/GitHub/Slack token patterns and zero private-key headers.
- Full tracked-source scans found zero Windows, macOS, or Linux user-specific absolute paths after normalizing historical references to `<ATDR_ROOT>`, `<MFU_SHELL_ROOT>`, `<USER_HOME>`, and `<UNIVERSITY_TEMPLATE_ROOT>`.
- Test-only credential placeholders remain synthetic fixtures. No private value was copied from the configured environment or external shell.
- `.atdr_runtime/`, local clean-room copies, Playwright output, builds, dependencies, databases, model artifacts, generated evidence, and private shell configuration remain ignored and outside the allowlist.
- The release gate returned `ok: true` with no failed required checks.

Any path outside the exact allowlist blocks staging.
