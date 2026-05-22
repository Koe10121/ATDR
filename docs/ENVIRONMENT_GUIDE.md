# ATDR Environment Guide

ATDR has separate environment templates so demo, lab-pilot, and future production usage do not get mixed together.

## Which Env File Should I Use?

| Scenario | File | Database | Purpose |
| --- | --- | --- | --- |
| Local supervisor demo | `.env.example` | SQLite | Fast local demo on one Windows machine |
| PostgreSQL lab pilot | `.env.lab.example` | PostgreSQL | Docker/PostgreSQL lab host with safer deployment defaults |
| Future production | `.env.production.example` | PostgreSQL | Hardened template for reviewed deployment planning |

Copy the correct file to `.env` before starting services.

```powershell
Copy-Item .env.example .env
```

For lab pilot:

```powershell
Copy-Item .env.lab.example .env
```

## Validate Configuration

Run Config Doctor after editing `.env`:

```powershell
python -m atdr.scripts.config_doctor --pretty
```

Before a demo or lab-pilot handoff, run the release gate:

```powershell
python -m atdr.scripts.verify_release --pretty
```

It checks:

- unsafe default JWT secret
- production mode with SQLite
- production mode with `AUTO_CREATE_TABLES=true`
- wildcard CORS origins
- public syslog binding
- response simulation disabled
- missing sample log path
- ML model directory status

Config Doctor exits nonzero only when critical unsafe production settings are detected.

## Local Demo Profile

Use `.env.example` for supervisor demo:

```text
ENVIRONMENT=development
DATABASE_URL=sqlite:///./atdr.db
AUTO_CREATE_TABLES=true
RESPONSE_SIMULATION=true
CORS_ALLOWED_ORIGINS=http://127.0.0.1:8501,http://localhost:8501,http://127.0.0.1:5173,http://localhost:5173
SYSLOG_HOST=127.0.0.1
```

Demo credentials and the demo JWT secret are intentionally easy to use locally and must not be reused for shared lab or production deployment.

## Lab Pilot Profile

Use `.env.lab.example` on a Docker/PostgreSQL host:

```text
ENVIRONMENT=production
DATABASE_URL=postgresql+psycopg2://atdr:<strong-password>@postgres:5432/atdr
AUTO_CREATE_TABLES=false
RESPONSE_SIMULATION=true
```

Run:

```powershell
docker compose --profile postgres up -d postgres
docker compose --profile postgres run --rm migrate
docker compose --profile postgres up --build api dashboard
python -m atdr.scripts.lab_smoke_check
```

On the current Windows development machine, Docker CLI may be unavailable. In that case, run:

```powershell
python -m atdr.scripts.lab_smoke_check --skip-docker
```

and complete full Docker validation on a Docker-capable host.

## Future Production Profile

Use `.env.production.example` only as a reviewed deployment template. It still keeps:

```text
RESPONSE_SIMULATION=true
```

Real firewall enforcement is unsupported until an approved connector, allowlist, dry-run preview, rollback process, and change approval flow exist.
