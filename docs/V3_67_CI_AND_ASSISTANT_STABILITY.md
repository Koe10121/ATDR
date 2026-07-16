# v3.67 CI And Assistant Stability

## Summary

v3.67 hardens the GitHub CI workflow and records the post-v3.66 SOC Assistant verification state.

The local release gate already passed after the assistant context repair. A CI-style clean-copy check was then run without the private `.env` file to make sure the backend does not depend on local secrets or local database state.

## What Changed

- The backend CI job now uses explicit safe defaults:
  - `DATABASE_URL=sqlite:///./atdr_ci.db`
  - `RESPONSE_SIMULATION=true`
  - `ASSISTANT_LLM_ENABLED=false`
  - `ASSISTANT_ALLOW_RAW_LOG_CONTEXT=false`
- Pytest in CI now writes cache and temporary files under `.tmp/` inside the workspace.
- CI now includes a separate React dashboard job:
  - Node.js 20
  - `npm ci`
  - Playwright Chromium install
  - `npm run lint`
  - `npm run build`
  - `npm run test:e2e`

No application runtime commands changed.

## Findings

The no-private-`.env` clean-copy backend sequence passed when pytest was given a writable base temp directory. The earlier local failure was a Windows temp-folder permission issue while pytest tried to scan `<USER_HOME>\AppData\Local\Temp\pytest-of-User`; it was not an ATDR logic failure.

## Verification Evidence

- Clean-copy `config_doctor`: passed without `.env`.
- Clean-copy backend tests with explicit basetemp: `431 passed, 1 skipped`.
- Clean-copy Alembic upgrade/check: passed.
- Clean-copy Ruff: passed.
- Local v3.66 verification:
  - `ruff check .`: passed.
  - `compileall`: passed.
  - `atdr/tests/test_assistant.py`: `29 passed`.
  - Frontend lint/build/e2e: `15 passed, 1 skipped`.
  - release gate: `ok: true`.

## Safety

- No `.env` values, API keys, client secrets, database files, real logs, model artifacts, `ml_baseline_reviews/`, `demo_exports/`, or generated reports were committed.
- Assistant remains read-only.
- External LLM remains disabled in CI.
- Raw log context remains disabled in CI.
- Response automation and real firewall blocking remain disabled.
- No ML model was activated or promoted.

## Remaining Notes

The React dashboard job makes CI closer to the actual release gate. The CI workflow still does not run large local performance smoke or real external LLM provider calls because those depend on local data volume and private configuration.
