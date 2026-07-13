# ATDR Quickstart For Team Members

This guide is for teammates who want to download ATDR, run it locally, and open the React dashboard on Windows.

MongoDB is not used currently. The local development database is SQLite because it works with the current FastAPI + SQLAlchemy + Alembic backend and is easiest for a teammate laptop.

## What You Will Run

Backend:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Frontend:

```powershell
cd frontend
npm.cmd run dev
```

Dashboard:

```text
http://127.0.0.1:5173
```

## Requirements

Install these first:

- Python 3.11 or newer
- Node.js 20.19.0 or newer, preferably the current Node 20 LTS release, with npm
- Git, if cloning instead of downloading a zip
- VS Code, recommended

Node.js 20.19.0 or newer is recommended because the current Vite, ESLint, and Playwright toolchain requires newer Node APIs. Node 16 is unsupported, and older Node 20 releases may emit engine warnings or fail future installs.

## Option A: Clone From GitHub

```powershell
cd C:\Users\User\Desktop
git clone <your-atdr-repo-url> ATDR
cd ATDR
```

Replace `<your-atdr-repo-url>` with the actual GitHub repository URL.

## Option B: Zip Download Setup

1. Open the GitHub repository in your browser.
2. Click **Code**.
3. Click **Download ZIP**.
4. Extract the zip file.
5. Rename the extracted folder to `ATDR` if needed.
6. Open PowerShell in the extracted folder:

```powershell
cd C:\Users\User\Desktop\ATDR
```

Zip downloads do not include Git history, but the app can still run normally.

## Backend Setup

From the project root:

```powershell
cd C:\Users\User\Desktop\ATDR
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If `py -3.11` does not work, try:

```powershell
python -m venv .venv
```

Copy the local environment example:

```powershell
Copy-Item .env.example .env
```

Apply database migrations:

```powershell
.\.venv\Scripts\alembic.exe upgrade head
```

Create demo users:

```powershell
python -m atdr.scripts.seed_users
```

Default local demo users from `.env.example`:

```text
admin / admin123
analyst / analyst123
```

These are only for local demo use. Replace them before shared lab use.

## Validate Backend Setup

Run the environment checker:

```powershell
python -m atdr.scripts.check_dev_environment --pretty --no-api
```

This checks Python, backend dependencies, `.env`, SQLite database connection if the DB exists, Alembic drift, frontend files, Node/npm, and safe sample files. It does not reset the database and does not import real logs.

## Start Backend

From the project root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open another PowerShell window and check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

If the backend is running, the health response should show database status, ML model status, and response mode.

## Frontend Setup

Open a second PowerShell window. The frontend environment template is `frontend/.env.example`.

```powershell
cd C:\Users\User\Desktop\ATDR\frontend
Copy-Item .env.example .env
npm.cmd install
npm.cmd run dev
```

Open:

```text
http://127.0.0.1:5173
```

Login with:

```text
admin / admin123
```

## Run A Safe Scenario Test

From a PowerShell window in the project root with the virtual environment active:

```powershell
python -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --use-temp-db --run-detection --pretty
```

This uses a temporary database and safe synthetic logs. It does not modify your current local ATDR database.

To intentionally run a scenario into your local dashboard database:

```powershell
python -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name teammate-scenario-firewall --run-detection --pretty
```

Only do this when you want the scenario to appear in the dashboard.

## Run Replay Dry-Run

```powershell
python -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty
```

Dry-run shows what would be replayed but does not write logs to the database.

## Import Real Or Large Logs

Keep real logs outside Git, for example:

```text
C:\Users\User\Downloads\paloalto-firewall.log
```

Do not copy real or large firewall logs into the repository.

Example import:

```powershell
python -m atdr.scripts.import_logs "C:\Users\User\Downloads\paloalto-firewall.log" --limit 5000
```

For large imports, use smaller chunks. SQLite is convenient but slower for large datasets. PostgreSQL is recommended later for shared lab deployment.

## Database Choice

### SQLite For Local Development

ATDR currently uses SQLite by default:

```text
DATABASE_URL="sqlite:///./atdr.db"
```

SQLite is good for:

- One-person local setup.
- Class project demos.
- Small local tests.
- Easy zip/clone setup with no separate database server.

### PostgreSQL For Optional Lab Deployment

PostgreSQL is the recommended future/shared lab database because it handles larger data and concurrent access better than SQLite. Use `.env.lab.example` as the starting point only when a PostgreSQL or Docker-capable lab host is available.

If `.env` contains a PostgreSQL URL with host `postgres`, that host is a Docker Compose service name. It will not resolve on a normal Windows terminal unless the Docker/PostgreSQL lab stack is running.

For normal local dashboard testing, `.env` should use:

```env
DATABASE_URL="sqlite:///./atdr.db"
AUTO_CREATE_TABLES=true
ENVIRONMENT="development"
RESPONSE_SIMULATION=true
```

Preview a safe switch back to the local SQLite profile:

```powershell
python -m atdr.scripts.use_local_sqlite_config --dry-run --pretty
```

Write the local SQLite profile only when you intentionally want to update `.env`:

```powershell
python -m atdr.scripts.use_local_sqlite_config --write --pretty
```

The write mode preserves a backup under ignored `.tmp/env-backups/`.

### MongoDB Is Not Used Currently

Do not migrate ATDR to MongoDB for v0.3.

ATDR has relational workflow data that fits SQLAlchemy/Alembic well:

- users and roles
- raw logs and normalized logs
- alerts and alert evidence
- ML labels and model runs
- audit logs
- sources and run history
- simulated response actions

MongoDB could be future research for a raw log archive or external log lake, but it is not needed for the current ATDR backend.

## Common Problems

### Backend Not Reachable

Check that Uvicorn is running:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

If it fails, start the backend again from the project root.

### Port 8000 Already In Use

Another backend may already be running. Close the old terminal or inspect the port:

```powershell
netstat -ano | Select-String "127.0.0.1:8000"
```

### Frontend Cannot Connect To Backend

Check `frontend\.env`:

```text
VITE_API_BASE_URL=http://127.0.0.1:8000
```

Restart `npm.cmd run dev` after changing frontend env values.

### npm Install Error

Use `npm.cmd` on Windows PowerShell:

```powershell
npm.cmd install
```

If Node is missing, install Node.js 20.19.0 or a newer Node 20 LTS release and reopen PowerShell. Upgrade Node 16 or older Node 20 releases before relying on frontend build or Playwright checks.

### Alembic Migration Error

Make sure the virtual environment is active and backend requirements are installed:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
.\.venv\Scripts\alembic.exe upgrade head
```

### Missing `.env`

Copy the example:

```powershell
Copy-Item .env.example .env
```

Do not commit `.env`.

### Dashboard Login Issue

Create demo users:

```powershell
python -m atdr.scripts.seed_users
```

Then log in with `admin / admin123`.

If login returns `Database unavailable` or logs show `could not translate host name "postgres"`, your `.env` is probably using the optional PostgreSQL lab profile while Docker/PostgreSQL is not running. Run:

```powershell
python -m atdr.scripts.config_doctor --pretty
python -m atdr.scripts.use_local_sqlite_config --dry-run --pretty
```

For normal local testing, switch `.env` back to SQLite as shown in the Database Choice section.

### Email Verification / Dev Outbox

Email verification is disabled by default. The normal local dashboard does not send real email:

```env
EMAIL_NOTIFICATIONS_ENABLED=false
EMAIL_VERIFICATION_ENABLED=false
EMAIL_DELIVERY_MODE="disabled"
```

For local testing only, admins can use the dev outbox:

```env
EMAIL_NOTIFICATIONS_ENABLED=true
EMAIL_VERIFICATION_ENABLED=true
EMAIL_DELIVERY_MODE="dev_outbox"
```

Restart the backend after changing `.env`, then open Admin / User Admin. Verification codes appear only in the admin-only dev outbox. Do not commit `.env`, SMTP passwords, or real email-provider secrets.

### Safe Sample Only Has A Few Logs

The safe demo sample at `data/samples/paloalto-demo.txt` is intentionally tiny. If you request 1000 demo logs but the safe sample has only a few lines, ATDR can only import what exists in that sample. Use a larger private sample path outside Git when testing larger imports.

### Real Logs And Generated Files Must Stay Out Of Git

Do not commit:

- real firewall/router logs
- `atdr.db`
- `.env`
- model artifacts
- `ml_baseline_reviews/`
- `demo_exports/`
- generated reports

## Quick Verification Checklist

Run these after setup:

```powershell
python -m atdr.scripts.check_dev_environment --pretty
python -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty
```

Optional fuller local check:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release
```

## What Remains Simulated

- Response actions are simulated.
- No real firewall blocking is enabled.
- ML is decision support only.
- The system is lab-ready for controlled validation, not certified production software.
