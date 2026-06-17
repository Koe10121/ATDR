# ATDR v3.3 Docker/PostgreSQL Lab Runbook

Use this runbook only on a Docker/PostgreSQL-capable host. Normal local ATDR testing still uses SQLite and does not require Docker.

## 1. Prepare Environment

```powershell
Copy-Item .env.lab.example .env
```

Edit `.env`:

```env
DATABASE_URL=postgresql+psycopg2://atdr_user:change_me@127.0.0.1:5432/atdr_lab
AUTO_CREATE_TABLES=false
JWT_SECRET_KEY=<long-random-secret>
DEMO_ADMIN_PASSWORD=<non-default-password>
DEMO_ANALYST_PASSWORD=<non-default-password>
RESPONSE_SIMULATION=true
RESPONSE_PROVIDER=simulation
```

Do not commit `.env`.

## 2. Start PostgreSQL

If a Docker Compose PostgreSQL profile is available:

```powershell
docker compose --profile postgres up -d postgres
```

If the host uses a manually installed PostgreSQL server, create an `atdr_lab` database and user, then set `DATABASE_URL` accordingly.

## 3. Install Dependencies

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cd frontend
npm.cmd install
cd ..
```

## 4. Run Migrations

```powershell
.\.venv\Scripts\alembic.exe upgrade head
.\.venv\Scripts\alembic.exe check
```

## 5. Seed Users

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.seed_users
```

The seed command is idempotent and should not reset data.

## 6. Start ATDR

Backend:

```powershell
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Frontend:

```powershell
cd frontend
npm.cmd run dev
```

Open `http://127.0.0.1:5173`.

## 7. Validate PostgreSQL Lab Readiness

Read-only first:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.database_portability_audit --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --pretty
```

Then include safe sample ingest:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --include-smoke --include-sample-ingest --pretty
```

For a full backend release gate:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_postgres_lab_validation --include-release-gate --pretty
```

## 8. Run No-Hardware Source Pilot

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v32_no_hardware_source_pilot --pretty
```

Expected: safe synthetic rows, source health, source-linked detection, no automatic responses, and `production_ready=false`.

## 9. Performance and Evidence

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.verify_release
.\.venv\Scripts\python.exe -m atdr.scripts.backup_postgres --dry-run
```

Capture:

- validator output
- performance smoke timings
- release gate result
- backup dry-run result
- dashboard screenshots if needed, stored outside Git

## 10. Safe Shutdown

```powershell
docker compose --profile postgres down
```

Only remove volumes/databases if the lab owner explicitly approves it.

## Not Production Ready

This runbook validates a shared-lab path. It does not enable automatic response, real firewall blocking, model activation, or production readiness.
