# MFU AI-Driven Log-Based Threat Detection and Response System

ATDR is a defensive senior-project prototype for importing Palo Alto firewall syslog CSV logs, preserving raw evidence, normalizing key fields, generating explainable alerts, and simulating response actions with audit trails.

## What Is Included

- FastAPI backend with log import, log explorer, alerts, detection, response, audit, and dashboard-summary endpoints.
- Robust Palo Alto parser using `csv.reader` after splitting only the syslog timestamp and hostname.
- SQLite by default, with SQLAlchemy models matching the prototype tables.
- Rule-based detection plus optional IsolationForest anomaly scoring and supervised analyst-label decision support.
- Incident-style alert grouping reduces per-log alert noise while preserving evidence log links.
- Log source management tracks file import, replay, syslog, router, firewall, and sample sources with health/status counters.
- Streamlit dashboard with Executive Demo, Overview, Log Explorer, Alerts, Detection Tuning, ML Governance, Threat Controls, Response Center, Audit Log, and admin Demo Controls pages.
- SOC Command Center dashboard styling with Plotly charts, triage queues, readiness panels, and evidence-focused incident views.
- SOC workflow support for alert assignment, analyst notes, status changes, timelines, and audited response actions.
- Alert suppression rules with review state, watchlist indicators, escalation metadata, computed SLA signals, and exportable JSON/CSV/HTML/PDF incident reports.
- Production-style tuning view for alert pressure, noisy rules, false-positive learning, suppression candidates, ML baseline health, and ownership gaps.
- Production-style reliability basics: structured JSON logs, request IDs, richer health checks, and migration support.
- Security hardening basics: configurable CORS origins and browser security headers.
- Demo, architecture, operations, presentation, and production-readiness documentation in `docs/`.
- Lab-pilot deployment guide with SQLite, PostgreSQL, and safe syslog receiver modes.
- CLI scripts for import, demo seeding, safe synthetic ML labels, ML training, anomaly scoring, release verification, lab smoke checks, backups, and export cleanup.
- Unit and API tests for parsing, rules, auth, workflow, demo controls, and severity scoring.

## Project Layout

```text
atdr/
  app/
    main.py
    core/
    db/
    parsers/
    detection/
    routers/
    services/
    schemas/
  dashboard/
    streamlit_app.py
  data/
  models/
  scripts/
  tests/
frontend/
  src/
    React production dashboard migration
migrations/
```

Keep real or large Palo Alto log files outside Git, for example in `Downloads`, `data/private/`, or `real_logs/`. Set `DEMO_SAMPLE_LOG_PATH` in `.env` to the absolute path when you want the demo scripts to use a private local log file.

## Local Setup

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python -m atdr.scripts.config_doctor --pretty
```

If your system uses `python` instead of the Windows launcher, replace `py -3.11` with `python`.

## Run The Backend

```powershell
uvicorn atdr.app.main:app --reload
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

The health response includes database connectivity, ML model artifact readiness, response mode, environment, and service version.
Every API response includes an `X-Request-ID` header. If a client sends `X-Request-ID`, ATDR preserves it; otherwise the API generates one for troubleshooting.

## Demo Login

Create demo users:

```powershell
python -m atdr.scripts.seed_users
```

Default demo accounts from `.env.example`:

```text
admin / admin123
analyst / analyst123
```

The admin role can run simulated block/unblock response actions. Analysts can investigate and update alert status.
Alert workflow states are `open` (New), `investigating`, `needs_more_context`, `contained`, `resolved`, and `false_positive`.
Alerts can be assigned to analysts, annotated with investigation notes, and reviewed through a timeline view.

Most API endpoints now require a bearer token. Use `/api/auth/login` to receive a JWT and pass it as:

```text
Authorization: Bearer <access_token>
```

## Import Logs

The default import limit is `5000` rows so the first demo stays responsive with large firewall files. Change `DEFAULT_IMPORT_LIMIT` in `.env`, pass `--limit`, or use `--limit 0` to import the full file. Keep private logs outside Git and pass an absolute path when importing real data.

```powershell
python -m atdr.scripts.import_logs "C:/path/to/private/paloalto-firewall.log" --limit 5000
```

Run detection:

```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:8000/api/detection/run?limit=5000&use_ml=false"
```

Seed a quick demo from the provided sample:

```powershell
python -m atdr.scripts.seed_demo
```

Reset the local demo database and recreate grouped alerts:

```powershell
python -m atdr.scripts.reset_demo --yes --limit 5000
```

Grouped detection currently uses 5-minute buckets. Low-severity groups are suppressed unless at least 5 matching evidence logs are present.

## Run The Dashboard

Keep the FastAPI backend running, then start Streamlit:

```powershell
streamlit run atdr/dashboard/streamlit_app.py --server.headless true --browser.gatherUsageStats false
```

Open `http://127.0.0.1:8501`.

## Run The React Dashboard Preview

The production dashboard migration lives in `frontend/`. Streamlit remains available for continuity while React is the priority dashboard path. The React dashboard is organized around Overview, Alerts, Investigation, AI Governance, Response & Audit, and Admin / Settings.

After installing Node.js 20+ or the current LTS, run:

```powershell
cd frontend
Copy-Item .env.example .env
npm install
npm run dev
```

On Windows, if PowerShell blocks `npm.ps1`, use `npm.cmd install` and `npm.cmd run dev`.

Open `http://127.0.0.1:5173`. FastAPI must be running at `http://127.0.0.1:8000`.

Frontend verification after Node is available:

```powershell
npm run build
npm run lint
npm run test:e2e
```

## Live Syslog Lab Test

Run the localhost UDP receiver in one terminal:

```powershell
python -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

Then send harmless sample Palo Alto traffic lines from another terminal:

```powershell
python -m atdr.scripts.send_sample_syslog --host 127.0.0.1 --port 5514 --count 3
```

Verify ingestion through the Log Explorer, ML Governance data-quality panel, or `GET /api/logs`. Keep the receiver bound to localhost for lab testing unless the host firewall and network scope are explicitly approved.

## Optional Lab Scenario Runner

For a safe end-to-end lab check that does not reset data by default:

```powershell
python -m atdr.scripts.run_lab_scenario --dry-run --use-sample-data --pretty
python -m atdr.scripts.run_lab_scenario --use-sample-data --no-ml --pretty
```

Use `--reset-demo` only when you intentionally want to clear demo data. See `docs/LAB_RUNBOOK.md`.

For v0.1 acceptance testing and current lab-readiness status, see `docs/ACCEPTANCE_TEST_CHECKLIST.md` and `docs/V0_1_STATUS.md`.

For v0.2 replay ingestion and alert deduplication work, see `docs/V0_2_PLAN.md`.

For v0.3 live/lab source management work, see `docs/V0_3_PLAN.md`.

Safe replay dry-run:

```powershell
python -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty
```

Register a lab source and replay as that source:

```powershell
python -m atdr.scripts.register_log_source --name lab-firewall-1 --source-type firewall --parser-profile palo_alto --host 192.0.2.10 --port 514 --pretty
python -m atdr.scripts.replay_logs --send-to direct --source-name lab-firewall-1 --source-type firewall --source-host 192.0.2.10 --source-port 514 --limit 100 --rate 1 --pretty
```

## ML-Assisted Anomaly Detection

Train the optional IsolationForest after importing logs:

```powershell
python -m atdr.scripts.train_model --limit 20000
```

Score imported logs without creating alerts:

```powershell
python -m atdr.scripts.predict_anomaly --limit 5000
```

Then run detection with ML enabled:

```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:8000/api/detection/run?limit=5000&use_ml=true"
```

The ML output is treated as assistance only. Rule explanations remain the primary reason an alert is created.

The ML Governance dashboard and `/api/ml/*` endpoints record model training and scoring runs, including actor, training log count, feature columns, feature summary, model artifact hash, anomaly count, anomaly rate, run comparison, and baseline drift signals. The dataset profile also reports baseline candidate counts, high-risk traffic volume, deny/drop volume, unknown-app volume, and training recommendations. This keeps the AI layer explainable and auditable instead of treating the model as a black box.

For safer training, use baseline-only mode first. It trains on allowed traffic, caps app risk, excludes unknown/incomplete applications, and can exclude logs already flagged as anomalous.

The evaluation report compares recent scoring runs and summarizes top anomalous source IPs, apps, ports, protocols, sample logs, score statistics, and operator recommendations.

Analyst-reviewed labels can be stored in `ml_labels` through `/api/ml/labels` or the React Log Explorer labeling panel. The ML Governance page includes a prioritized Label Review Queue and CSV import/export for analyst review workflows. After enough reviewed rows exist, train the supervised decision-support classifier:

```powershell
python -m atdr.scripts.train_supervised_model --test-size 0.3
```

The supervised classifier uses the original single-log features plus 5-minute source/destination context such as deny rate, unique destination ports, total bytes, unknown app count, high-risk app count, hour of day, and after-hours signal. Its output is combined with rule score and IsolationForest anomaly support in a hybrid risk score, but it remains analyst decision support only.

For a safe synthetic training demo without private traffic:

```powershell
python -m atdr.scripts.seed_demo_labels
python -m atdr.scripts.train_supervised_model --test-size 0.3
```

For the complete end-to-end hybrid AI workflow, see `docs/AI_TRAINING_RUNBOOK.md`.

For lab-pilot tuning, export an analyst review package:

```powershell
python -m atdr.scripts.ml_baseline_review --anomaly-limit 200 --baseline-limit 200
```

This writes JSON/CSV/Markdown evidence to `ml_baseline_reviews/`, including anomaly rows with raw evidence excerpts and blank analyst review columns. See `docs/ML_BASELINE_TUNING.md`.

## API Highlights

- `GET /health`
- `POST /api/auth/login`
- `GET /api/auth/me`
- `POST /api/demo/reset`
- `POST /api/demo/import-sample`
- `POST /api/demo/run-detection`
- `POST /api/demo/train-ml`
- `POST /api/demo/apply-ml`
- `POST /api/demo/export-bundle`
- `GET /api/ml/status`
- `GET /api/ml/runs`
- `GET /api/ml/profile`
- `GET /api/ml/report`
- `GET /api/ml/labels`
- `POST /api/ml/labels`
- `PUT /api/ml/labels/{label_id}`
- `GET /api/ml/labels/export`
- `GET /api/ml/labels/template`
- `POST /api/ml/labels/import`
- `GET /api/ml/review-queue`
- `GET /api/ml/review-queue/export`
- `GET /api/ml/supervised/report`
- `GET /api/ml/supervised/report/export`
- `POST /api/ml/supervised/train`
- `GET /api/ml/supervised/predict/{log_id}`
- `POST /api/ml/train`
- `POST /api/ml/score`
- `POST /api/logs/import`
- `GET /api/logs`
- `GET /api/logs/{log_id}`
- `GET /api/sources`
- `GET /api/sources/{id}`
- `POST /api/sources`
- `PATCH /api/sources/{id}`
- `GET /api/sources/{id}/health`
- `GET /api/alerts`
- `POST /api/alerts/{alert_id}/resolve`
- `POST /api/alerts/{alert_id}/false-positive`
- `POST /api/alerts/{alert_id}/investigate`
- `POST /api/alerts/{alert_id}/contain`
- `POST /api/alerts/{alert_id}/status`
- `POST /api/alerts/{alert_id}/assign`
- `POST /api/alerts/{alert_id}/assign/me`
- `POST /api/alerts/{alert_id}/notes`
- `GET /api/alerts/{alert_id}/notes`
- `GET /api/alerts/{alert_id}/timeline`
- `POST /api/alerts/{alert_id}/escalate`
- `GET /api/alerts/{alert_id}/report`
- `GET /api/suppressions`
- `POST /api/suppressions`
- `POST /api/suppressions/{id}/disable`
- `POST /api/suppressions/{id}/review`
- `GET /api/watchlists`
- `POST /api/watchlists`
- `POST /api/watchlists/{id}/disable`
- `GET /api/users`
- `POST /api/users`
- `POST /api/users/{id}/disable`
- `POST /api/users/{id}/reset-password`
- `POST /api/users/{id}/role`
- `POST /api/auth/change-password`
- `POST /api/detection/run`
- `GET /api/detection/summary`
- `GET /api/detection/tuning`
- `POST /api/response/block-ip`
- `POST /api/response/unblock-ip`
- `GET /api/response/blocked-ips`
- `GET /api/audit`
- `GET /api/dashboard/summary`

## Tests

```powershell
pytest atdr/tests
```

Run the full local release gate before a demo or release candidate:

```powershell
python -m atdr.scripts.verify_release --pretty
```

If API and Streamlit are already running, include local smoke checks:

```powershell
python -m atdr.scripts.verify_release --include-smoke --pretty
```

Playwright browser smoke tests are optional. Run them only after installing browser dependencies and starting API plus Streamlit:

```powershell
$env:ATDR_RUN_PLAYWRIGHT="1"
pytest atdr/tests/test_dashboard_playwright_smoke.py -q
```

## Database Migrations

SQLite demo mode can still auto-create tables with `AUTO_CREATE_TABLES=true`.
For production-style environments, set:

```text
AUTO_CREATE_TABLES=false
```

Then run migrations explicitly:

```powershell
alembic upgrade head
```

Create future schema migrations after model changes:

```powershell
alembic revision --autogenerate -m "describe change"
```

If you already have a pre-Alembic local SQLite database with the current schema, back it up and mark it as migrated:

```powershell
alembic stamp head
```

## Docker

SQLite demo:

```powershell
docker compose up --build
```

PostgreSQL profile:

```powershell
docker compose --profile postgres up -d postgres
docker compose --profile postgres run --rm migrate
docker compose --profile postgres up --build api dashboard
```

For PostgreSQL, start from `.env.lab.example`:

```powershell
Copy-Item .env.lab.example .env
python -m atdr.scripts.config_doctor --pretty
```

Use `.env.example` for local demo, `.env.lab.example` for PostgreSQL lab pilot, and `.env.production.example` as a future hardened template. See `docs/ENVIRONMENT_GUIDE.md`, `docs/DEPLOYMENT_GUIDE.md`, `docs/OPERATIONS_RUNBOOK.md`, and `docs/PRODUCTION_READINESS.md` for lab-pilot deployment guidance, live syslog receiver usage, CORS/HTTPS/reverse-proxy guidance, backups, and retention policy.

CI runs the same core quality gate on push and pull request: Config Doctor, compileall, pytest, Alembic drift check, and conservative Ruff linting. Docker and Playwright checks remain optional because they depend on host tooling.

Run the local UDP syslog receiver in lab mode:

```powershell
python -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

Prove the live ingestion path locally without a firewall:

```powershell
python -m atdr.scripts.syslog_lab_smoke --count 5
```

See `docs/SMALL_OFFICE_LAB_PILOT.md` for the controlled small-office pilot path, including real syslog forwarding and safe response requirements.

## Clean Supervisor Demo Flow

Use `docs/DEMO_DAY_RUNBOOK.md` as the authoritative local Windows checklist for demo day. Quick start:

```powershell
python -m atdr.scripts.seed_users
python -m atdr.scripts.config_doctor --pretty
uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000
streamlit run atdr/dashboard/streamlit_app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true --browser.gatherUsageStats false
python -m atdr.scripts.demo_health_check
python -m atdr.scripts.lab_smoke_check --skip-docker
```

Then in the dashboard:

1. Log in as `admin`.
2. Keep **Presentation Mode** enabled in the sidebar.
3. Open **Demo Controls**.
4. Run **Reset Demo Data**.
5. Run **Run Detection** if needed.
6. Optionally run **Train ML Model** and **Apply ML Scoring**.
7. Run **Generate Demo Evidence Bundle**.
8. Present from **Executive Demo** first.

CLI export option:

```powershell
python -m atdr.scripts.export_demo_bundle --actor admin
```

Lab-pilot utility scripts:

```powershell
python -m atdr.scripts.lab_smoke_check
python -m atdr.scripts.backup_demo --dry-run
python -m atdr.scripts.backup_postgres --dry-run
python -m atdr.scripts.cleanup_exports --older-than-days 14
python -m atdr.scripts.verify_release --pretty
```

On this development machine, Docker Compose validation may need to be run elsewhere if Docker is not installed. The smoke check reports that blocker clearly.

## Assumptions

- Response actions are simulated by default. The system records block and unblock actions but does not modify real firewall devices. If `RESPONSE_SIMULATION=false` is set before an approved connector exists, actions are recorded as `pending_connector`, not falsely reported as executed.
- The parser focuses on Palo Alto TRAFFIC fields and safely normalizes useful THREAT fields. Full raw payload fields are stored in `parsed_json` for evidence and later mapping improvements.
- Alert creation groups related evidence logs by rule, source or internet-sweep pattern, and 5-minute time bucket. Low-severity singletons are suppressed to keep the analyst view usable.
- IsolationForest is an unsupervised assistive model. Train it on a representative baseline window and review anomaly-rate reports before using it to support real SOC decisions.
- The default SQLite database is intended for local demonstrations. PostgreSQL is included for a more realistic deployment path.

## Project Documentation

- `docs/ARCHITECTURE.md`: subsystem diagram and data trust model.
- `docs/DEMO_FLOW.md`: hands-on demo sequence.
- `docs/DEMO_DAY_RUNBOOK.md`: local Windows supervisor demo checklist.
- `docs/ENVIRONMENT_GUIDE.md`: demo, lab, and future production environment profiles.
- `docs/FINAL_DEMO_SCRIPT.md`: final supervisor walkthrough script.
- `docs/PRESENTATION_PACKAGE.md`: supervisor demo script and screenshot checklist.
- `docs/RELEASE_CHECKLIST.md`: local demo and lab-pilot release gate checklist.
- `docs/DASHBOARD_PRODUCTION_PATH.md`: honest path from Streamlit SOC console to enterprise frontend.
- `docs/SUPERVISOR_QA.md`: prepared answers for likely evaluation questions.
- `docs/SCREENSHOT_CHECKLIST.md`: exact screenshots to capture for slides/report.
- `docs/DEPLOYMENT_GUIDE.md`: SQLite, PostgreSQL, and syslog receiver setup.
- `docs/OPERATIONS_RUNBOOK.md`: HTTPS, backups, retention, and safe response procedure.
- `docs/V0_3_PLAN.md`: live/lab log source management and parser profile readiness.
- `docs/LIMITATIONS_AND_FUTURE_WORK.md`: honest production roadmap.
