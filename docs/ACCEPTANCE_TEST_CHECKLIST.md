# ATDR v0.1 Acceptance Test Checklist

Use this checklist before calling a build lab-ready. Do not reset or delete existing local data unless a test explicitly says to use a temporary database.

## Startup

- [ ] Backend starts:
  ```powershell
  .\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
  ```
- [ ] Frontend starts:
  ```powershell
  cd frontend
  npm.cmd run dev
  ```
- [ ] React dashboard opens at `http://127.0.0.1:5173`.
- [ ] Health endpoint returns `ok`:
  ```powershell
  Invoke-RestMethod http://127.0.0.1:8000/health
  ```

## Authentication And Navigation

- [ ] Admin login works.
- [ ] Analyst login works.
- [ ] Overview page loads.
- [ ] Alerts page loads.
- [ ] Investigation / Log Explorer loads.
- [ ] AI Governance loads.
- [ ] Response & Audit loads.
- [ ] Admin / Settings is visible to admin users.
- [ ] Admin / Settings is hidden or access-denied for analyst users.

## Alert Workflow

- [ ] Alert table loads without API errors.
- [ ] Alert detail drawer opens.
- [ ] Detail shows severity, risk score, attack type, detection source, why flagged, evidence logs, ATT&CK-style mapping, recommended action, response history, and audit timeline.
- [ ] Status can move through:
  - [ ] New (`open`)
  - [ ] Investigating
  - [ ] Needs More Context
  - [ ] Contained
  - [ ] Resolved
  - [ ] False Positive
- [ ] Analyst notes can be added.
- [ ] Timeline records status changes and notes.

## Investigation / Log Explorer

- [ ] Log table loads.
- [ ] Search works.
- [ ] Common filters work.
- [ ] Advanced filters expand/collapse.
- [ ] Sorting dropdowns work.
- [ ] Dropdowns do not freeze or block page clicks after selection.
- [ ] Log detail opens and shows raw evidence plus normalized fields.

## AI Governance

- [ ] AI Governance page loads.
- [ ] Model status clearly says analyst-review eligible or candidate-only, not production-promoted.
- [ ] "Decision support only" wording is visible near model output.
- [ ] Weak labels and reviewed labels are clearly separated.
- [ ] Label export control is visible.
- [ ] Label import control is visible.
- [ ] Human review sample export is visible.
- [ ] Model report download is visible.

## Response And Audit

- [ ] Response mode shows simulation.
- [ ] Simulated block requires confirmation.
- [ ] Simulated unblock requires confirmation.
- [ ] Justification note is required.
- [ ] Protected internal/management IP block is denied.
- [ ] Denied response attempt is recorded in Audit Trail.
- [ ] Successful simulated response is recorded in Audit Trail.
- [ ] No real firewall enforcement occurs.

## Lab Scenario And Syslog

- [ ] Lab scenario dry-run works:
  ```powershell
  .\.venv\Scripts\python.exe -m atdr.scripts.run_lab_scenario --dry-run --use-sample-data --pretty
  ```
- [ ] Optional sample scenario works without reset:
  ```powershell
  .\.venv\Scripts\python.exe -m atdr.scripts.run_lab_scenario --use-sample-data --pretty
  ```
- [ ] Syslog receiver is documented:
  ```powershell
  .\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
  ```
- [ ] Sample syslog sender works or is clearly documented:
  ```powershell
  .\.venv\Scripts\python.exe -m atdr.scripts.send_sample_syslog --host 127.0.0.1 --port 5514 --count 3
  ```

## Repo Hygiene

- [ ] `git status --short` does not show real logs.
- [ ] No generated CSV exports are staged.
- [ ] No database files are staged.
- [ ] No model artifacts are staged.
- [ ] No `.env` files are staged.
- [ ] `ml_baseline_reviews/` and `demo_exports/` are ignored.

## Release Gate

- [ ] Ruff passes.
- [ ] Compileall passes.
- [ ] Backend tests pass.
- [ ] Alembic check reports no drift.
- [ ] React lint passes.
- [ ] React build passes.
- [ ] Playwright smoke tests pass.
- [ ] Release gate passes:
  ```powershell
  .\.venv\Scripts\python.exe -m atdr.scripts.verify_release
  ```
