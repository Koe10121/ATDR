# MFU AI-Driven Log-Based Threat Detection and Response System

ATDR is a defensive senior-project lab prototype for AI-assisted firewall log monitoring. It imports Palo Alto firewall/syslog logs, preserves raw evidence, normalizes investigation fields, generates explainable SOC-style alerts, supports analyst review, and records simulated analyst-approved response actions with audit trails.

ATDR is lab-ready for controlled small-office validation. It is not certified production software, does not perform real firewall blocking, and does not trigger automatic response actions.

## Current v0.3 Snapshot

- FastAPI backend with JWT auth, admin/analyst RBAC, SQLAlchemy/Alembic, and SQLite by default.
- Local account management supports username/password plus optional school-email fields, verified-email status, and email login for local users.
- React-first SOC dashboard with Overview, Alerts, Investigation / Log Explorer, AI Governance, Response & Audit, Threat Controls, Detection Tuning, User Admin, and Demo Controls.
- Palo Alto parser with raw evidence preservation, plus parser profiles for `palo_alto`, `generic_syslog`, and `raw_fallback`.
- Log source management with source health, source-level data quality, replay/syslog lab support, and source-scoped detection.
- Rule-based detection, alert deduplication, lightweight case grouping, ATT&CK-style mapping, and "Why flagged?" explanations.
- IsolationForest anomaly scoring and supervised ML decision support with AI Governance, labeling workflow, active learning, and model validation gates.
- Simulated response actions with confirmation, protected-IP safeguards, justification notes, and audit logs.
- External school-email IAM groundwork via disabled-by-default generic OIDC configuration/status. Local login remains the default, and SMTP/email invites are disabled future work.
- Safe synthetic scenario validation under `data/samples/scenarios/`.
- Release gate, performance smoke, onboarding docs, IAM/RBAC docs, PRD, traceability, and university workflow documentation.

## Safety And Scope

- Real or large firewall logs must stay outside Git, for example in `Downloads`, `data/private/`, or `real_logs/`.
- `.env`, DB files, model artifacts, generated CSVs/reports, `ml_baseline_reviews/`, and `demo_exports/` must not be committed.
- Response mode remains simulation unless a future approved connector is implemented.
- ML is analyst decision support only; weak-label metrics are not production accuracy.
- Docker/PostgreSQL is optional future/lab deployment work, not required for normal local testing.

## Quick Start

For a beginner-friendly Windows setup from a fresh clone or GitHub zip download, use:

- `docs/QUICKSTART_FOR_TEAM.md`

Minimum local flow:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\alembic.exe upgrade head
python -m atdr.scripts.seed_users
```

If your system uses `python` instead of the Windows launcher, replace `py -3.11` with `python`.

Default local demo users from `.env.example`:

```text
admin / admin123
analyst / analyst123
```

Replace demo secrets before shared lab or real deployment.

Environment templates:

- `.env.example` - normal local SQLite/demo setup.
- `.env.lab.example` - optional PostgreSQL/shared lab starting point.
- `.env.production.example` - future hardened deployment template, not a production guarantee.

## Start The Backend

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

## Start The React Dashboard

Install Node.js 20.x LTS or newer. Node 16 may fail with the current Vite, ESLint, and Playwright toolchain.

```powershell
cd frontend
Copy-Item .env.example .env
npm.cmd install
npm.cmd run dev
```

Open:

```text
http://127.0.0.1:5173
```

FastAPI must be running at:

```text
http://127.0.0.1:8000
```

Streamlit remains available only as legacy/demo continuity. React is the priority dashboard path. See `docs/DASHBOARD_PRODUCTION_PATH.md` for the historical dashboard migration context.

## Import Or Replay Logs

Keep private logs outside Git and pass an absolute path when importing real data:

```powershell
python -m atdr.scripts.import_logs "C:\Users\User\Downloads\paloalto-firewall.log" --limit 5000
```

Run detection:

```powershell
Invoke-RestMethod -Method Post "http://127.0.0.1:8000/api/detection/run?limit=5000&use_ml=false"
```

Safe replay dry-run:

```powershell
python -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty
```

Register a lab source and replay as that source:

```powershell
python -m atdr.scripts.register_log_source --name lab-firewall-1 --source-type firewall --parser-profile palo_alto --host 192.0.2.10 --port 514 --pretty
python -m atdr.scripts.replay_logs --send-to direct --source-name lab-firewall-1 --source-type firewall --source-host 192.0.2.10 --source-port 514 --limit 100 --rate 1 --pretty
```

## Controlled Threat Detection Validation

Synthetic scenario files live under `data/samples/scenarios/`. They validate normal traffic, negative controls, mixed small-subnet traffic, scanning-like traffic, brute-force-like service attempts, C2/beaconing-like activity, data exfiltration suspicion, connection flood behavior, deduplication, parser fallback, and policy/suspicious-app behavior without using private logs or offensive tooling.

Run the full v0.7 validation suite safely against a temporary database:

```powershell
python -m atdr.scripts.run_detection_validation_suite --all --pretty
```

The suite writes ignored JSON/Markdown reports plus a risk-calibration report under `demo_exports/detection_validation/`. The React Overview page shows a compact latest validation summary, but generated reports should not be committed.

Run a scenario against a temporary database:

```powershell
python -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --use-temp-db --run-detection --pretty
```

Run a scenario into the current dashboard intentionally:

```powershell
python -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name scenario-lab-firewall-1 --run-detection --pretty
```

Validate a controlled replay source and export advisor-friendly JSON/Markdown reports:

```powershell
python -m atdr.scripts.validate_live_source --source-name scenario-lab-firewall-1 --source-type firewall --parser-profile palo_alto --duration 0 --run-detection --pretty
python -m atdr.scripts.export_lab_validation_report --source-name scenario-lab-firewall-1 --format both --pretty
```

Real firewall/router hardware validation remains future work. ATDR is intended for controlled small-subnet/lab-scale validation, not production certification.

## ML And AI Governance

ATDR combines:

- rule-based detection as the primary explainable signal
- IsolationForest anomaly scoring as assistive unsupervised ML
- supervised classifier output trained from reviewed/assisted labels
- hybrid risk scoring for analyst triage

The model is analyst-review eligible, not production-promoted. Response automation remains disabled regardless of model output.

Useful commands:

```powershell
python -m atdr.scripts.generate_assisted_labels --dry-run --limit 1000 --pretty
python -m atdr.scripts.export_active_learning_review_sample --limit 200
python -m atdr.scripts.train_supervised_model --split time --test-size 0.3 --min-samples 6
```

See `docs/AI_TRAINING_RUNBOOK.md` and `docs/ML_BASELINE_TUNING.md`.

## Verification

Backend:

```powershell
.\.venv\Scripts\python.exe -m compileall -q atdr migrations
.\.venv\Scripts\python.exe -m pytest atdr\tests -q
.\.venv\Scripts\alembic.exe check
```

Frontend:

```powershell
cd frontend
npm.cmd run lint
npm.cmd run build
npm.cmd run test:e2e
```

Release checks:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release
```

Equivalent release-gate command from an activated virtual environment:

```powershell
python -m atdr.scripts.verify_release
```

Optional browser smoke flag for legacy Python-driven dashboard smoke checks:

```powershell
$env:ATDR_RUN_PLAYWRIGHT="1"
```

## Documentation Map

Start here:

- `docs/QUICKSTART_FOR_TEAM.md` - Windows setup for teammates using clone or zip download.
- `docs/LAB_RUNBOOK.md` - lab operations, replay, syslog, source validation, and troubleshooting.
- `docs/V0_6_THREAT_DETECTION_VALIDATION.md` - active controlled threat detection validation plan.
- `docs/V0_5_SIMULATION_DEMO_PLAN.md` - earlier controlled replay validation plan.
- `docs/V0_5_REAL_SOURCE_VALIDATION_PLAN.md` - future controlled hardware source validation plan.
- `docs/V0_3_RELEASE_CANDIDATE.md` - current release-candidate summary.
- `docs/V0_4_STATUS.md` - current dashboard/IAM/performance checkpoint.
- `docs/V0_3_STATUS.md` - detailed current v0.3 status.
- `docs/V0_3_PLAN.md` - v0.3 source-management and scenario-validation plan.

Governance and university workflow:

- `docs/ATDR_AI_WORKFLOW.md` - no-guessing, source-evidence, testing, PRD-update, safety, and handoff workflow.
- `docs/ATDR_NEWSYSTEM_TEMPLATE_ALIGNMENT.md` - how ATDR adapts the university NewSystem template without copying Node/Vue/Mongo implementation.
- `docs/ATDR_TEMPLATE_MANIFEST.json` - ATDR-specific template manifest with env keys, permission paths, validation commands, and safety constraints.
- `docs/prd/PRD-ATDR.md` - real ATDR PRD.
- `docs/security/ATDR_IAM_RBAC_MATRIX.md` - admin/analyst permission matrix and IAM limitations.
- `docs/security/ATDR_EXTERNAL_IAM_PLAN.md` - disabled-by-default OIDC groundwork for future school-email login.
- `docs/security/ATDR_PERMISSION_PATHS.md` - NewSystem-style ATDR permission path registry.
- `docs/security/ATDR_OWASP_LAB_SECURITY_REVIEW.md` - lab security review baseline and remaining hardening gaps.
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md` - source-backed mapping from requirements to code, tests, docs, and gaps.
- `docs/agents/ATDR_AGENT_OPERATING_MODEL.md` - ATDR agent roles and handoff responsibilities.
- `docs/templates/ATDR_T1_T20_CHANGE_DOCUMENT.md` - ATDR change document template.
- `docs/changes/T1_T20_IAM_RBAC_COMPLIANCE.md` - completed change-document example.

Other useful docs:

- `docs/ACCEPTANCE_TEST_CHECKLIST.md`
- `docs/ARCHITECTURE.md`
- `docs/DEMO_DAY_RUNBOOK.md`
- `docs/DASHBOARD_PRODUCTION_PATH.md`
- `docs/ENVIRONMENT_GUIDE.md`
- `docs/DEPLOYMENT_GUIDE.md`
- `docs/OPERATIONS_RUNBOOK.md`
- `docs/LIMITATIONS_AND_FUTURE_WORK.md`

## Project Layout

```text
atdr/
  app/
    main.py
    core/
    db/
    parsers/
    detection/
    ml/
    routers/
    services/
    schemas/
  dashboard/        legacy Streamlit continuity
  scripts/
  tests/
data/samples/       safe synthetic/demo samples only
frontend/           React SOC dashboard
migrations/         Alembic migrations
docs/               runbooks, PRD, governance, status, release docs
```

## Current Limitations

- Real firewall blocking is not implemented.
- Automatic response is not enabled.
- Real router/firewall syslog forwarding still needs controlled lab validation.
- SQLite is convenient for local use; PostgreSQL is recommended later for shared/larger lab deployment.
- Supervised ML still needs more reviewed labels and live validation before stronger claims.
- Case grouping is lightweight and not a full incident-management/ticketing platform.
