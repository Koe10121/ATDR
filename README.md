# MFU AI-Driven Log-Based Threat Detection And Response

ATDR is a defensive SOC platform for collecting firewall/syslog records,
preserving and normalizing evidence, running explainable detection, presenting
analyst-ready alerts, and supporting investigations with a read-only AI
Assistant.

ATDR is a controlled release candidate, not certified production software.
Deterministic rules remain alert-authoritative. Supervised ML and anomaly
scores are advisory. Response is simulated and analyst-confirmed; automatic
response and real firewall blocking are disabled.

## Current Truth

The published baseline is:

- v5.53 implementation: `825e29dde7430cee191ab86068c05e7c5ae30bf5`;
- narrow CI repair: `b5761a953cf541e744fc437d4fb07be2adaec63f`;
- GitHub Actions run `33585630166`: green;
- CodeQL run `33585630219`: green.

The current v5.54 worktree is consolidating the local release candidate and
operator handoff. It is not committed or published. No external acceptance or
production claim follows from local configuration.

Current governed ML truth:

- the immutable v5.49b protocol consumed 180 genuine protected decisions once;
- all eight fixed strategies were evaluated;
- zero supervised candidates qualified;
- no artifact was activated or promoted;
- lifecycle remains `shadow_observation`;
- consumed protected evidence must never be rerun or tuned.

See [Current System State](docs/CURRENT_SYSTEM_STATE_LOCK.md), [Current AI/ML
Status](docs/CURRENT_AI_ML_PRODUCT_STATUS.md), and [v5.54 Operator
Handoff](docs/V5_54_OPERATOR_HANDOFF.md).

## What ATDR Does

1. **Collects logs:** file import, API import, durable large-file jobs, replay,
   and a lab UDP syslog receiver.
2. **Preserves evidence:** raw records are stored before parsing; malformed
   records remain available with parser warnings.
3. **Parses and normalizes:** PAN-OS TRAFFIC, THREAT, and SYSTEM layouts plus
   generic syslog and raw fallback produce consistent investigation fields.
4. **Detects threats:** a versioned deterministic rule catalog performs
   source/time correlation, grouping, scoring, and deduplication.
5. **Adds advisory AI/ML:** IsolationForest and governed supervised strategies
   can rank or enrich evidence but cannot create or suppress authoritative
   alerts.
6. **Explains findings:** alerts show why they were flagged, evidence strength,
   related logs, parser caveats, ATT&CK-style context, and recommended checks.
7. **Assists analysts:** deterministic retrieval and optional Gemini synthesis
   provide concise, cited, read-only answers over bounded ATDR context.
8. **Records decisions:** assignments, notes, labels, simulated response
   requests, and account/security events are audited.

## Architecture

| Surface | Technology | Role |
| --- | --- | --- |
| ATDR API | FastAPI / Python 3.11 | Auth, ingestion, detection, investigation, Assistant, operations |
| ATDR UI | React / TypeScript / Vite | SOC dashboard and analyst workflows |
| Persistence | SQLAlchemy / Alembic | SQLite locally; PostgreSQL for approved shared deployment |
| Detection | Python rule engine | Alert-authoritative explainable detection |
| ML | scikit-learn | Advisory anomaly and supervised evaluation |
| Authentication shell | Approved MFU Node/Vue companion | School sign-in and secure one-time handoff |

The companion shell uses MongoDB for its own state. ATDR does not use MongoDB
and has not migrated to the shell's Node/Vue architecture. Archived university
reference material under `docs/reference/NewSystem/` is reference-only.

The React source is under `frontend/`. Its primary analyst routes include
Overview, Alerts, Log Explorer, SOC Assistant, AI Governance, Response & Audit,
Threat Controls, Detection Tuning, Evidence Review, and User Admin.

## Supported Profiles

| Profile | Status | Normal use |
| --- | --- | --- |
| MFU shell-first + local SQLite | Locally reproducible | Primary laptop/team workflow |
| Explicit local recovery | Locally reproducible | Authorized diagnosis only |
| Versioned teammate shell package | Locally validated contract | Requires separate physical teammate acceptance |
| Shared PostgreSQL deployment | Repository assets implemented | Requires approved host and owner evidence |

## First Setup

Requirements:

- Windows 10 or 11 with PowerShell;
- Python 3.11;
- Node.js 20.19 or newer and npm;
- MongoDB running on `127.0.0.1:27017` for the MFU shell;
- approved `mfu-atdr-shell-1.4.0-atdr.1.zip`;
- private shell configuration supplied through the approved channel.

From the repository root:

```powershell
.\scripts\setup_team.cmd `
  -ShellPackage "D:\Approved Artifacts\mfu-atdr-shell-1.4.0-atdr.1.zip" `
  -ShellPrivateConfigRoot "D:\Private MFU Configuration"
```

Setup verifies the package, creates the Python environment, installs backend
and frontend dependencies, creates ignored private ATDR configuration, backs
up SQLite before migration, and applies additive Alembic migrations. It never
resets the configured database.

For a source directory explicitly approved by the advisor/team owner:

```powershell
.\scripts\setup_team.cmd -TemplateRoot "D:\Approved MFU Shell"
```

Do not use placeholder paths such as `C:\Path\To\ATDR`. Do not copy another
person's `.env`, database, API key, or protected evidence.

## Start The System

```powershell
.\scripts\start_system.cmd
```

Wait for `All components are ready`, then use the mandatory entry:

```text
http://localhost:8080/#/pages/login
```

The launcher starts:

- FastAPI: `http://127.0.0.1:8000`;
- React: `http://127.0.0.1:5173`;
- MFU shell API: `http://127.0.0.1:8214`;
- MFU shell UI: `http://localhost:8080`.

Check or stop the tracked processes:

```powershell
.\scripts\check_system.cmd
.\scripts\stop_system.cmd
```

To restart, stop and start. Use the `.cmd` wrappers when PowerShell execution
policy blocks direct `.ps1` execution.

Real MFU/Google sign-in still depends on the approved Web client, account
scope, IAM group mapping, provider-managed 2FA, recovery, and deprovisioning.
The application fails closed rather than bypassing those checks.

## Local Recovery

`ATDR_AUTH_MODE=local_recovery` is an explicit private recovery/development
profile. It is never selected by the normal launcher. Stop the shell-first
runtime and follow [Operations Runbook](docs/OPERATIONS_RUNBOOK.md) for direct
FastAPI/React startup. Return to `template_shell` before normal operation.

## Configuration References

- `.env.shell.example`: normal MFU shell-first local profile;
- `.env.example`: explicit local-recovery/development profile;
- `.env.lab.example`: optional PostgreSQL shared-lab profile;
- `.env.production.example`: fail-closed shared-host reference;
- `frontend/.env.example`: direct React component configuration.

Create only ignored private copies. Never place real values in the examples.

## Import And Detect

Keep private or large logs outside Git. Import through the dashboard or CLI:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.import_logs "D:\Private Logs\firewall.log" --limit 5000
```

Safe replay preview:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.replay_logs --dry-run --limit 20 --rate 5 --pretty
```

Live loopback receiver:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

Run detection from the dashboard after reviewing source and parser health.
Production-like non-loopback forwarding requires network-owner approval and a
real physical-source qualification.

## Detection And ML Status

The deterministic detector has 19 versioned rules and controlled coverage for
benign traffic, port/service probing, brute-force patterns, C2-like beaconing,
exfiltration suspicion, floods, policy violations, parser fallbacks, and
deduplication. The controlled suites are regression evidence, not real-world
accuracy claims.

Supervised ML is deliberately not active. v5.49b selected no candidate due
insufficient evaluation-role support and calibration-gate failures. A second
physical source, fresh untouched future windows, prediction-blind human labels,
stable performance, and separate activation approval remain mandatory.

IsolationForest remains an unusual-behavior signal only. It is not an
authoritative threat detector.

## SOC Assistant

Assistant context is assembled from bounded ATDR records through the service
layer: alert details, related normalized logs, source health, operation/jobs,
AI governance, and approved runbook guidance. Answers include citations and
provenance.

Gemini is supported through private configuration. ATDR sends only bounded,
redacted context; raw logs are excluded by default and IP redaction is enabled.
The key is never returned to the UI or audit log. Deterministic fallback remains
available if the provider fails.

The Assistant cannot run detection, create response actions, alter labels,
activate models, modify users, or delete data.

## Safety And Repository Hygiene

Never commit:

- `.env` files or credentials;
- database files;
- private/real logs or processed evidence;
- protected review decisions or labels;
- model artifacts;
- `ml_baseline_reviews/` or `demo_exports/`;
- generated reports, provider payloads, SBOMs, or acceptance manifests.

`RESPONSE_SIMULATION=true` and `RESPONSE_PROVIDER=simulation` must remain set.
No real firewall connector is enabled.

## Verification

Core local checks:

```powershell
node scripts/render-tasklist-progress-html.js .
node scripts/check-tasklist-progress-standard.js .
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m compileall -q atdr migrations
.\.venv\Scripts\python.exe -m pytest atdr/tests -q
.\.venv\Scripts\alembic.exe check
Set-Location frontend
npm.cmd run lint
npm.cmd run build
npm.cmd run test:e2e
```

Release/security/deployment checks are documented in [v5.54 Operator
Handoff](docs/V5_54_OPERATOR_HANDOFF.md). CI also validates PostgreSQL,
dependency audits, SBOM generation, deployment references, disaster recovery,
and CodeQL.

Run the release gate from the repository root:

```powershell
python -m atdr.scripts.verify_release --pretty
```

Set `ATDR_RUN_PLAYWRIGHT=1` only when intentionally asking the release gate to
include its optional browser smoke path; normal frontend verification uses
`npm.cmd run test:e2e` directly.

## Active Documentation

- [Quick Start For Team](docs/QUICKSTART_FOR_TEAM.md)
- [Operator Handoff](docs/V5_54_OPERATOR_HANDOFF.md)
- [Operations Runbook](docs/OPERATIONS_RUNBOOK.md)
- [Deployment Guide](docs/DEPLOYMENT_GUIDE.md)
- [External Owner Acceptance](docs/V5_54_EXTERNAL_OWNER_ACCEPTANCE.md)
- [Current System State](docs/CURRENT_SYSTEM_STATE_LOCK.md)
- [Current AI/ML Product Status](docs/CURRENT_AI_ML_PRODUCT_STATUS.md)
- [Product Requirements](docs/prd/PRD-ATDR.md)
- [Requirement Traceability](docs/ATDR_REQUIREMENT_TRACEABILITY.md)
- [University Compliance Checklist](docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md)
- [AI Documentation Index](docs/AI-DOCS-INDEX.md)

## Remaining External Gates

The release candidate remains externally constrained by:

1. MFU IAM lifecycle and real group-role acceptance;
2. an approved shared PostgreSQL/HTTPS host and operations evidence;
3. institutional Gemini privacy, retention, quota, cost, and key governance;
4. a separate physical teammate clean-clone/sign-in exercise;
5. independent physical-source detection evidence and future blind labels.

Exact owner actions are in
[v5.54 External Owner Acceptance](docs/V5_54_EXTERNAL_OWNER_ACCEPTANCE.md).
Until they are satisfied, `production_ready=false`.
