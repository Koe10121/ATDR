# ATDR Release Checklist

Use this checklist for a controlled local release-candidate handoff. It does
not certify production readiness or close external acceptance.

## Repository And Configuration

- Working tree contains no unexpected or private files.
- Private `.env`, database, logs, labels, reviews, models, provider payloads,
  generated reports, and processed evidence remain ignored.
- `python -m atdr.scripts.config_doctor --pretty` passes for the selected
  profile without exposing values.
- `RESPONSE_SIMULATION=true` for any shared/production release; automatic
  (unattended) response is off in every profile. A local/lab profile may
  explicitly opt into the real, host-scoped Windows Firewall connector
  (`RESPONSE_PROVIDER=windows_firewall`) — confirm this is intentional before
  a release handoff, since it means Block actually changes host firewall
  state.
- Supervised runtime remains `unqualified`; no artifact was activated.

## Backend And Data

```powershell
node scripts/render-tasklist-progress-html.js .
node scripts/check-tasklist-progress-standard.js .
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m compileall -q atdr migrations
.\.venv\Scripts\python.exe -m pytest atdr/tests -q
.\.venv\Scripts\alembic.exe check
```

Do not reset the database to make a release check pass. Run destructive or
stateful drills only against disposable/test storage.

## Frontend

```powershell
Set-Location frontend
npm.cmd run lint
npm.cmd run build
npm.cmd run test:e2e
Set-Location ..
```

Confirm login, Overview, Alerts, Investigation, SOC Assistant, AI Governance,
Operations, Response & Audit, and User Admin behave at supported viewports.
Set `ATDR_RUN_PLAYWRIGHT=1` only when the release gate should run the browser
suite itself; the explicit `npm.cmd run test:e2e` command above remains the
normal verification path.

## Detection And Assistant

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --run-detection --use-temp-db --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_layered_detection_validation --all --variants 3 --no-report --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_assistant_qa --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v558_governed_hybrid_runtime --require-safe --pretty
```

Require rules authoritative, advisory layers non-authoritative, Assistant
read-only, and response simulation-only.

## Security And Release Gate

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v553_security_acceptance --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.audit_repository_surface --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.performance_smoke --pretty
python -m atdr.scripts.verify_release --pretty
```

Review GitHub Actions, dependency audits, and CodeQL after a separately
approved push.

## Shared-Host And Rollback Checks

For an approved PostgreSQL host, confirm Alembic is at head and run the
non-writing preflights:

```powershell
python -m atdr.scripts.backup_postgres --dry-run
python -m atdr.scripts.lab_smoke_check
```

Docker/PostgreSQL validation is an external acceptance gate and is not required
for ordinary local SQLite use. Before deployment, record a tested Rollback plan,
backup location, restore owner, and recovery evidence in the release handoff.

## External Acceptance

Production remains false until the owners listed in
`docs/EXTERNAL_ACCEPTANCE.md` provide real, current IAM, provider, host,
physical-device, teammate, and independent-evidence acceptance.

The superseded release checklist is retained at
`docs/archive/runbooks/RELEASE_CHECKLIST_THROUGH_V5_58.md`.
