# MFU AI-Driven Log-Based Threat Detection And Response

ATDR is a defensive SOC platform for collecting firewall/syslog records,
preserving and normalizing evidence, running explainable detection, presenting
analyst-ready alerts, and supporting investigations with a read-only AI
Assistant.

ATDR is a controlled release candidate, not certified production software.
Deterministic rules remain alert-authoritative. The MFU behaviour model, trained
only on MFU's firewall traffic, adds experimental, low-confidence alerts where the
rules raise none (a recorded exception: no attack type passed its quality bar).
Supervised ML and anomaly scores are advisory. All accuracy figures come from one 21-minute MFU export (20 May 2026); treat them as low-confidence estimates until tested on more traffic. Response is analyst-confirmed and simulated by default;
automatic (unattended) response remains disabled in every profile. An
operator may explicitly opt a local/lab profile into real, host-scoped
enforcement (see [Response And Containment](#response-and-containment)); no
real network-firewall connector is implemented, and shared/production
deployments remain simulation-only regardless of configuration.

## Current State (29 Sep 2026)

- **Detection:** rule catalog v5.36.0 (22 rules). Context-only rules add points
  but never raise an alert alone. Every alert names its attack type, MITRE
  ATT&CK technique and response playbook. The live list holds 185 alerts after
  a rebuild with the current rules; the 3,676 older alerts are archived in full.
- **MFU behaviour model (v2):** trained only on MFU's firewall traffic plus
  simulated attacks blended into it. It gives its view on the Overview and on
  every alert, and raises alerts marked experimental where it flags a device
  and no rule alert covers it. No attack type passed its quality bar; the
  experimental alerts are a recorded exception (`docs/detection/ML_QUALITY_BAR.md`).
- **SOC Assistant:** a conversational model running on the laptop (qwen3:8b via
  Ollama) that looks facts up through read-only tools; every number it states
  is checked against what the tools returned. Built-in answers remain the
  fallback (`docs/SOC_ASSISTANT_CONVERSATIONAL.md`).
- **Evidence:** every figure, what kind it is and how far to trust it is in
  [Evidence Summary](docs/EVIDENCE_SUMMARY.md). What changed after the
  26 September presentation is in the
  [Improvement Phase Report](docs/IMPROVEMENT_PHASE_REPORT.md).

The earlier supervised classifier and IsolationForest anomaly scores remain
advisory and are not the MFU behaviour model. Their v5.6x history is archived
under `docs/archive/phases/`.

## What ATDR Does

1. **Collects logs:** file import, API import, durable large-file jobs, replay,
   and a lab UDP syslog receiver.
2. **Preserves evidence:** raw records are stored before parsing; malformed
   records remain available with parser warnings.
3. **Parses and normalizes:** PAN-OS TRAFFIC, THREAT, and SYSTEM layouts plus
   generic syslog and raw fallback produce consistent investigation fields.
4. **Detects threats:** a versioned deterministic rule catalog performs
   source/time correlation, grouping, scoring, and deduplication.
5. **Adds an MFU-trained model:** the MFU behaviour model reads each device's
   five minutes of traffic, names the likely attack and explains why; where
   no rule alert covers a device it flags, it raises an experimental,
   low-confidence alert. Older IsolationForest and supervised scores stay
   advisory and cannot create or suppress alerts.
6. **Explains findings:** alerts show why they were flagged, evidence strength,
   related logs, parser caveats, ATT&CK-style context, and recommended checks.
7. **Assists analysts:** a conversational assistant answers from ATDR's own
   read-only tools, with built-in deterministic answers as the fallback.
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
| Versioned teammate shell package | Automated clean-clone lifecycle verified | Real account and physical teammate acceptance remain external |
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

Running the same start command again while all four launcher-owned components
are healthy is safe: it reports the existing healthy runtime and does not
start duplicates. If runtime state is partial, follow the printed check and
stop commands before retrying.

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

The deterministic detector has 22 versioned rules covering port/service
probing, brute-force patterns, C2-like beaconing, firewall threat and malware
records, exploit attempts, exfiltration suspicion, floods, policy violations,
watchlist matches, parser fallbacks, and deduplication. See the
[Detection Rule Catalog](docs/DETECTION_RULE_CATALOG.md).

The MFU behaviour model, its quality bar and its experimental alerting switch
are described in `docs/detection/ML_MODEL_CARD.md` and the
[Operations Runbook](docs/OPERATIONS_RUNBOOK.md). Turn its alerts off with
`python -m atdr.scripts.model_alerts disable`.

All accuracy figures come from one 21-minute MFU export, so they are
low-confidence estimates. The official blind check and the other scores are
explained in `docs/detection/BLIND_CHECK.md` and the
[Evidence Summary](docs/EVIDENCE_SUMMARY.md). Another MFU export, even one
hour from another day, is what would raise confidence.

The older supervised classifier is deliberately not active (v5.49b selected no
candidate), and IsolationForest remains an unusual-behaviour signal only.

Before an advisor demonstration, run the complete disposable acceptance:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v5631_advisor_demo_acceptance `
  --use-temp-db `
  --execute-provider-probe `
  --pretty
```

The current run passes 10/10 stages and 24/24 workflow checks. It does not
access or reset the configured database.

## SOC Assistant

The SOC Assistant holds a normal conversation. Questions about ATDR's data are
answered through 10 read-only tools that wrap the same services the dashboard
uses: alerts, logs, rules, playbooks, concepts, dashboard guides and system
status. Before an answer is shown, ATDR checks every number against the tool
results and removes IP addresses and secrets; if the check fails or the model
is unavailable, the built-in answers are used.

The default engine is a local model (qwen3:8b through Ollama), so no data
leaves the laptop. Gemini is supported through private configuration with IP
redaction on; the key is never returned to the UI or audit log. Setup and
scores are in `docs/SOC_ASSISTANT_CONVERSATIONAL.md`.

The Assistant cannot run detection, create response actions, alter labels,
activate models, modify users, or delete data.

## Response And Containment

Blocking an IP from Response & Audit always requires an admin, a written
justification, and an evidence-linked alert where one is supplied; internal/
management IP ranges (RFC1918, loopback, link-local) and the ATDR backend
host's own address(es) are always protected and cannot be targeted. Every
action is audited regardless of outcome.

`RESPONSE_SIMULATION=true` (the default in every example profile) means a
block is recorded and shown in the dashboard, but nothing is changed on any
real device. An operator may explicitly opt a **local/lab** profile into real
enforcement with `RESPONSE_SIMULATION=false` and `RESPONSE_PROVIDER=windows_firewall`:
this creates a real, reversible Windows Firewall rule on the machine running
the ATDR backend, blocking inbound and outbound traffic to/from the target IP
on that host only. It never touches any other device, requires no external
network-owner approval (it is the operator's own machine), and is fully
undone by the matching unblock action. Blocks may include a timeout (capped
by `RESPONSE_MAX_BLOCK_MINUTES`, default 1440) after which they are lifted
automatically. This is the only implemented enforcement connector; any other
`RESPONSE_PROVIDER` value is recorded as `pending_connector` and takes no
action. Real enforcement is refused by configuration validation outside a
local/lab `ENVIRONMENT` and on a non-Windows backend host. See
`docs/changes/T1_T20_RESPONSE_REAL_ENFORCEMENT.md`.

## Safety And Repository Hygiene

Never commit:

- `.env` files or credentials;
- database files;
- private/real logs or processed evidence;
- protected review decisions or labels;
- model artifacts;
- `ml_baseline_reviews/` or `demo_exports/`;
- generated reports, provider payloads, SBOMs, or acceptance manifests.

`RESPONSE_SIMULATION=true` and `RESPONSE_PROVIDER=simulation` are the default
in every example profile and must remain set for any shared/production
deployment. A local/lab operator may explicitly opt into the real, host-only
Windows Firewall connector described under
[Response And Containment](#response-and-containment); no other real
firewall/network connector is implemented.

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

Release/security/deployment checks are documented in the [Release
Checklist](docs/RELEASE_CHECKLIST.md). CI also validates PostgreSQL,
dependency audits, SBOM generation, deployment references, disaster recovery,
and CodeQL.

Run the release gate from the repository root:

```powershell
python -m atdr.scripts.verify_release --pretty
```

Preview the genuine remote-clone acceptance using the separately supplied
shell archive:

```powershell
py -3.11 -m atdr.scripts.run_v560_clean_machine_acceptance `
  --shell-package "D:\Approved Artifacts\mfu-atdr-shell-1.4.0-atdr.1.zip" `
  --pretty
```

The full run requires the exact confirmation printed by preflight. It clones
`origin/main` into verified Windows temporary storage, uses only synthetic
configuration for lifecycle checks, exercises the safe analyst workflow, and
removes its temporary SQL, MongoDB, process, and filesystem state. It never
copies the current `.env` or claims a real MFU sign-in succeeded.

Inspect the effective detection roles without changing data:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v558_governed_hybrid_runtime --require-safe --pretty
```

Set `ATDR_RUN_PLAYWRIGHT=1` only when intentionally asking the release gate to
include its optional browser smoke path; normal frontend verification uses
`npm.cmd run test:e2e` directly.

## Active Documentation

- [Quick Start For Team](docs/QUICKSTART_FOR_TEAM.md)
- [Operations Runbook](docs/OPERATIONS_RUNBOOK.md)
- [Lab Runbook](docs/LAB_RUNBOOK.md)
- [Release Checklist](docs/RELEASE_CHECKLIST.md)
- [Deployment Guide](docs/DEPLOYMENT_GUIDE.md)
- [External Acceptance](docs/EXTERNAL_ACCEPTANCE.md)
- [Evidence Summary](docs/EVIDENCE_SUMMARY.md)
- [Improvement Phase Report](docs/IMPROVEMENT_PHASE_REPORT.md)
- [Conversational SOC Assistant](docs/SOC_ASSISTANT_CONVERSATIONAL.md)
- [Advisor Demonstration Runbook](docs/ADVISOR_DEMO_RUNBOOK.md)
- [AI And Model Governance](docs/AI_TRAINING_RUNBOOK.md)
- [Detection Rule Catalog](docs/DETECTION_RULE_CATALOG.md)
- [Product Requirements](docs/prd/PRD-ATDR.md)
- [Requirement Traceability](docs/ATDR_REQUIREMENT_TRACEABILITY.md)
- [University Compliance Checklist](docs/ATDR_UNIVERSITY_COMPLIANCE_CHECKLIST.md)
- [AI Documentation Index](docs/AI-DOCS-INDEX.md)

## Remaining External Gates

The release candidate remains externally constrained by:

1. MFU IAM lifecycle and real group-role acceptance;
2. an approved shared PostgreSQL/HTTPS host and operations evidence;
3. institutional Gemini privacy, retention, quota, cost, and key governance;
4. a separate physical teammate and real MFU-account sign-in exercise;
5. another MFU firewall export, or another physical source, for a clean
   end-to-end test, and future blind labels.

Exact owner actions are in [External Acceptance](docs/EXTERNAL_ACCEPTANCE.md).
Until they are satisfied, `production_ready=false`.
