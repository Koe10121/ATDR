# ATDR Final Acceptance Checklist

Record the test date, tester, result, and evidence for each item.

## Startup

- [ ] Backend starts with:

  ```powershell
  .\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
  ```

- [ ] `http://127.0.0.1:8000/health` reports healthy service/database checks.
- [ ] Frontend starts with:

  ```powershell
  cd frontend
  npm.cmd run dev
  ```

- [ ] React dashboard opens at `http://127.0.0.1:5173`.
- [ ] Admin and analyst local login work as intended.

## Ingestion And Sources

- [ ] Safe sample or scenario ingestion creates raw log rows.
- [ ] Raw evidence is preserved.
- [ ] Normalized logs are created for valid rows.
- [ ] Parse failures are counted without crashing ingestion.
- [ ] Source last-seen and log counters update.
- [ ] Source health and parser warnings are understandable.
- [ ] Ingestion run history records counts and status.

## Detection And Investigation

- [ ] Final scenario source `final-demo-firewall-live` is healthy.
- [ ] Final scenario shows 10 logs received, 10 normalized, 10 parsed, and 0 parse failures.
- [ ] Rule detection runs successfully.
- [ ] Detection run history records evaluated logs and results.
- [ ] Final scenario detection run reports `port_scan (1)` and no unrelated historical attack counts.
- [ ] Expected scenario alerts appear.
- [ ] Final scenario creates one critical port-scan alert and one case.
- [ ] Final scenario alert shows 10 occurrences and 10 related logs.
- [ ] Repeated alerts update occurrence/related-log counts where applicable.
- [ ] Alert detail opens.
- [ ] `Why flagged?` shows evidence and analyst guidance.
- [ ] ATT&CK-style mapping appears where supported.
- [ ] Related logs can be opened or filtered.
- [ ] Lightweight cases group related activity.
- [ ] Log Explorer and Alerts source filters work.
- [ ] Dropdowns close and do not block later clicks.

## AI Governance

- [ ] Candidate is `independent_fpr_stabilized`.
- [ ] Fresh blind holdout shows 700 rows, 7 sources, and 16 scenarios.
- [ ] Readiness v8 shows 22/22.
- [ ] Status shows `Final Controlled Validation Candidate`.
- [ ] `Decision Support Only` is visible.
- [ ] `Not Production Promoted` is visible.
- [ ] `Response Automation Disabled` is visible.
- [ ] Label review import/export controls remain available.
- [ ] Metrics are not described as production accuracy.

## Response And Audit

- [ ] Simulated block requires confirmation.
- [ ] A justification note is required.
- [ ] Response is denied when alert evidence is missing.
- [ ] Protected internal/management IP action is denied.
- [ ] Denied response attempt is audited.
- [ ] Approved response remains simulated.
- [ ] Audit record includes actor, action, target, result, and time.
- [ ] No ML output creates an automatic response.
- [ ] Final scenario response actions remain 0 before/after.
- [ ] No real firewall change occurs.

## Performance And Quality

- [ ] Overview summary is responsive for the local dataset.
- [ ] AI Governance lightweight summary loads without blocking navigation.
- [ ] Alerts and cases load within acceptable lab timing.
- [ ] Dashboard has no horizontal overflow.
- [ ] Loading, empty, and error states are readable.
- [ ] Performance smoke reports no warning:

  ```powershell
  .\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke
  ```

## Final Verification

- [ ] Ruff passes.
- [ ] Compileall passes.
- [ ] Backend tests pass.
- [ ] Alembic reports no drift.
- [ ] React lint passes.
- [ ] React build passes.
- [ ] Playwright passes.
- [ ] Replay dry-run passes.
- [ ] Controlled source validation passes.
- [ ] v2.0 fresh blind revalidation passes without tuning.
- [ ] Release gate passes:

  ```powershell
  .\.venv\Scripts\python.exe -m atdr.scripts.verify_release
  ```

## Repository Hygiene

- [ ] No real/private logs are staged or tracked.
- [ ] No `.env` file is staged or tracked.
- [ ] No SQLite/DB file is staged or tracked.
- [ ] No model artifact is staged or tracked.
- [ ] No generated CSV/report or benchmark snapshot is staged or tracked.
- [ ] `ml_baseline_reviews/`, `demo_exports/`, and processed logs remain ignored.

## Final Sign-Off

- [ ] Validated scope is described as controlled lab decision support.
- [ ] Production promotion remains false.
- [ ] Model activation remains false.
- [ ] Response automation remains disabled.
- [ ] Real firewall blocking remains disabled.
- [ ] Remaining limitations are disclosed.
