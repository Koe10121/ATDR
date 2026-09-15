# ATDR Final Acceptance Checklist

Record the test date, tester, result, and evidence for each item.

## Startup

- [ ] Integrated MFU-shell startup succeeds with:

  ```powershell
  .\scripts\start_system.cmd
  .\scripts\check_system.cmd
  ```

- [ ] The shell login opens at `http://localhost:8080/#/pages/login` and a
  successful handoff reaches the ATDR React dashboard.

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

- [ ] Supervised lifecycle shows `shadow_observation`.
- [ ] Schema-incompatible evidence abstains before supervised inference.
- [ ] v5.22 shadow candidate limitations remain visible: independent human
  labels, suspicious recall, source diversity, and calibration are open.
- [ ] No model is shown as activated or production-promoted.
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
- [ ] Detection/scenario execution creates no automatic response action.
- [ ] A response record appears only after explicit analyst confirmation and
  remains simulated.
- [ ] No real firewall change occurs.

## Performance And Quality

- [x] Overview summary is responsive for the local dataset.
- [x] AI Governance lightweight summary loads without blocking navigation.
- [x] Alerts and cases load within acceptable lab timing.
- [x] Dashboard has no horizontal overflow.
- [x] Loading, empty, and error states are readable.
- [x] Performance smoke reports no warning:

  ```powershell
  .\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke
  ```

## Final Verification

- [x] Ruff passes.
- [x] Compileall passes.
- [x] Backend tests pass.
- [x] Alembic reports no drift.
- [x] React lint passes.
- [x] React build passes.
- [x] Playwright passes.
- [x] Replay dry-run passes.
- [x] Controlled source validation passes.
- [x] v5.25 integrated acceptance passes `14/14` using disposable storage and
  fresh or validated locked Gemini evidence.
- [x] Release gate passes:

  ```powershell
  .\.venv\Scripts\python.exe -m atdr.scripts.verify_release
  ```

## Repository Hygiene

- [x] No real/private logs are staged or tracked.
- [x] No `.env` file is staged or tracked.
- [x] No SQLite/DB file is staged or tracked.
- [x] No model artifact is staged or tracked.
- [x] No generated CSV/report or benchmark snapshot is staged or tracked.
- [x] `ml_baseline_reviews/`, `demo_exports/`, and processed logs remain ignored.

## Final Sign-Off

- [x] Validated scope is described as controlled lab decision support.
- [x] Production promotion remains false.
- [x] Model activation remains false.
- [x] Response automation remains disabled.
- [x] Real firewall blocking remains disabled.
- [x] Remaining limitations are disclosed.
- [x] Non-loopback transport, real firewall/router, independent native human
  labels, MFU preproduction, approved host, and Gemini deployment governance
  remain listed as external gates unless separately evidenced.
