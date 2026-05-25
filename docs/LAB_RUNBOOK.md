# ATDR Lab Runbook

This runbook keeps the normal local workflow intact while adding optional lab-readiness checks. SQLite remains valid for local testing. Docker and PostgreSQL are optional lab-pilot targets, not required for daily development.

## Normal Local Workflow

Start the backend:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Start the React dashboard:

```powershell
cd frontend
npm.cmd run dev
```

Open:

```text
http://127.0.0.1:5173
```

This workflow must continue to support log import, detection, alert triage, ML Governance, reviewed CSV import, model retraining, simulated response actions, and audit review.

## Health Check

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected result: status `ok`, database `ok`, and response mode `simulation`.

## Safe Lab Scenario Runner

Dry run first:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_lab_scenario --dry-run --use-sample-data --pretty
```

Run against the safe sample file without resetting current data:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_lab_scenario --use-sample-data --no-ml --pretty
```

Run against an explicit private log path only when intended:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_lab_scenario --sample-path "C:/Users/User/Downloads/paloalto-firewall(1).log" --limit 5000 --pretty
```

Optional destructive demo reset is explicit:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_lab_scenario --reset-demo --use-sample-data --pretty
```

The runner never resets data unless `--reset-demo` is passed. It never imports private logs unless `--sample-path` is passed. Simulated response is skipped unless `--simulate-response` is passed.

The output includes import timing, detection timing, ML scoring timing when enabled, feature-generation timing, dashboard summary timing, top attack types, top source IPs, and audit presence.

## Import Logs Manually

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.import_logs "C:/Users/User/Downloads/paloalto-firewall(1).log" --limit 5000
```

Real or large logs should stay outside Git. Do not place private logs in the repository root.

## Run Detection

Through API after login, or from the dashboard Demo Controls. For CLI-style local validation, use the optional lab scenario runner. Detection remains rule-first, and ML remains assistive.

## Live Syslog Local Test

Terminal 1:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

Terminal 2:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.send_sample_syslog --host 127.0.0.1 --port 5514 --count 3
```

Verify:

- Raw logs increased.
- Normalized logs increased.
- AI Governance Data Quality shows latest ingestion time.
- Investigation page can find the new rows.
- Detection can be run after ingestion.

The UDP receiver is local/lab only. Do not bind it to `0.0.0.0` unless host firewall rules and network scope are approved.

## Triage And Simulated Response

1. Open Alerts.
2. Select an alert.
3. Review why flagged, evidence logs, ATT&CK-style mapping, and behavior-window evidence.
4. Assign to yourself or mark `Investigating`.
5. Add an analyst note.
6. Use simulated block only when evidence exists and the target is not protected internal infrastructure.
7. Confirm the action.
8. Open Response & Audit or Audit Trail and verify actor, action, target, and reason.

Response actions remain simulated. ATDR records denied response attempts too.

## Optional PostgreSQL/Docker Lab Workflow

Use this only on a Docker-capable host:

```powershell
Copy-Item .env.lab.example .env
.\.venv\Scripts\python.exe -m atdr.scripts.config_doctor --pretty
docker compose --profile postgres up -d postgres
docker compose --profile postgres run --rm migrate
docker compose --profile postgres up --build api dashboard
.\.venv\Scripts\python.exe -m atdr.scripts.lab_smoke_check
```

Docker/PostgreSQL is not required for normal local testing.

## Optional Reset And Seed

Do not reset the current local database unless you intend to clear demo data.

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.reset_demo --yes --path data/samples/paloalto-demo.txt --limit 5000
```

Use `--yes` only when you understand it clears local demo data.

## Troubleshooting

- API health check failed: confirm uvicorn is running on port `8000`.
- React shows failed fetch: confirm `VITE_API_BASE_URL` points to `http://127.0.0.1:8000`.
- Login fails: run `python -m atdr.scripts.seed_users`.
- Config Doctor warns about demo JWT secret: expected in local demo, unsafe for lab/prod.
- Config Doctor warns about missing sample path: set `DEMO_SAMPLE_LOG_PATH` in private `.env` or use `data/samples/paloalto-demo.txt`.
- Syslog test receives nothing: confirm receiver is running before sender and that both use the same host/port.

## Safety Rules

- Do not enable automatic response.
- Do not claim certified production readiness.
- Do not commit real logs, DB files, model artifacts, generated CSV/reports, `.env`, `ml_baseline_reviews/`, or `demo_exports/`.
