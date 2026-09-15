# ATDR Environment Guide

ATDR has separate environment templates so normal shell-first use, authorized
recovery, shared-lab work, and future deployment planning do not get mixed.

## Which Env File Should I Use?

| Scenario | File | Database | Purpose |
| --- | --- | --- | --- |
| Normal MFU shell-first local | `.env.shell.example` | SQLite | Complete four-service Windows workflow |
| Explicit local recovery | `.env.example` | SQLite | Authorized component diagnosis only |
| PostgreSQL lab pilot | `.env.lab.example` | PostgreSQL | Docker/PostgreSQL lab host with safer deployment defaults |
| Future production | `.env.production.example` | PostgreSQL | Hardened template for reviewed deployment planning |

For normal use, do not manually copy an environment file. Run setup with the
approved shell package; it creates ignored configuration and generated local
secrets:

```powershell
.\scripts\setup_team.cmd `
  -ShellPackage "D:\Approved Artifacts\mfu-atdr-shell-1.4.0-atdr.1.zip" `
  -ShellPrivateConfigRoot "D:\Private MFU Configuration"
```

Use `.env.example` only when explicitly selecting the recovery/development
profile. For an optional lab pilot:

```powershell
Copy-Item .env.lab.example .env
```

## Validate Configuration

Run Config Doctor after editing `.env`:

```powershell
python -m atdr.scripts.config_doctor --pretty
```

For production-readiness planning, also run:

```powershell
python -m atdr.scripts.production_readiness_doctor --pretty
```

This stricter doctor reports blockers and warnings for shared lab and future production-like planning. It does not make ATDR production ready and does not mutate the database.

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

## Normal Local Profile

The setup launcher derives the normal private profile from
`.env.shell.example`. Its governing values include:

```text
ENVIRONMENT=development
DATABASE_URL=sqlite:///./atdr.db
AUTO_CREATE_TABLES=true
ATDR_AUTH_MODE=template_shell
RESPONSE_SIMULATION=true
RESPONSE_PROVIDER=simulation
ASSISTANT_ALLOW_RAW_LOG_CONTEXT=false
SYSLOG_HOST=127.0.0.1
```

The normal entry is the MFU shell. Generated bridge/JWT keys remain private,
and approved provider values are supplied separately. MongoDB stores only the
companion shell state; ATDR still uses SQLite.

The safe sample path points to `data/samples/`. Keep real Palo Alto files
outside Git and pass their private path only at runtime.

## Lab Pilot Profile

Use `.env.lab.example` on a Docker/PostgreSQL host:

```text
ENVIRONMENT=production
DATABASE_URL=postgresql+psycopg2://atdr:<strong-password>@postgres:5432/atdr
AUTO_CREATE_TABLES=false
RESPONSE_SIMULATION=true
RESPONSE_PROVIDER=simulation
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
RESPONSE_PROVIDER=simulation
```

Real firewall enforcement is unsupported until an approved connector, allowlist, dry-run preview, rollback process, and change approval flow exist. If simulation is disabled before a connector exists, ATDR records response actions as `pending_connector`.

## Validation References

- Local and live-source workflow: `docs/LAB_RUNBOOK.md`
- PostgreSQL/shared-host workflow: `docs/DEPLOYMENT_GUIDE.md`
- Health, monitoring, backup, and recovery: `docs/OPERATIONS_RUNBOOK.md`
- Model and drift governance: `docs/AI_TRAINING_RUNBOOK.md`

SQLite remains the normal local workflow. PostgreSQL validation is optional and
should run only on an approved PostgreSQL-capable lab or deployment host.
