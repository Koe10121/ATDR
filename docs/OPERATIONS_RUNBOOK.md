# ATDR Operations Runbook

This is the active operations reference for ATDR. Normal users enter through
the approved MFU shell. ATDR remains a controlled release candidate: rules are
alert-authoritative, supervised runtime is unqualified, the SOC Assistant is
read-only, and response is simulated by default in every profile. A local/lab
operator may explicitly opt into a real, host-scoped Windows Firewall
connector; no other real firewall/network connector exists, and
shared/production profiles remain simulation-only. See
[Response And Containment](../README.md#response-and-containment).

## Supported Profiles

| Profile | Purpose | Database | Entry |
| --- | --- | --- | --- |
| MFU shell-first local | Normal laptop and team use | SQLite | `http://localhost:8080/#/pages/login` |
| Local recovery | Authorized recovery/component diagnosis | SQLite | Direct React `http://127.0.0.1:5173` |
| Teammate distribution | Same shell-first flow from approved shell package | SQLite | MFU shell login |
| Shared deployment | Owner-approved multi-user host | PostgreSQL | HTTPS reverse proxy and MFU shell |

The Node/Vue/MongoDB companion is the authentication shell only. The ATDR
application remains FastAPI, React, SQLAlchemy/Alembic, and SQLite or
PostgreSQL.

The published v5.60 baseline passed its automated clean-machine acceptance
from a genuine remote clone and is CI/CodeQL green. v5.61 adds explicit anomaly
bootstrap capability without changing normal startup. This proves reproducible
local wiring; it does not replace real MFU sign-in or physical teammate
usability evidence.

## Start, Check, Stop, Restart

From the ATDR repository root:

```powershell
.\scripts\start_system.cmd
.\scripts\check_system.cmd
.\scripts\stop_system.cmd
```

Wait for `All components are ready` before opening the login page. To restart,
run `stop_system.cmd` and then `start_system.cmd`. The launcher tracks only the
four processes it owns and keeps logs in ignored `.atdr_runtime/logs/`.

ATDR does not start by itself after a restart. To have it start when you sign
in to Windows:

```powershell
.\scripts\autostart.cmd            # install
.\scripts\autostart.cmd -Status    # what is installed
.\scripts\autostart.cmd -Remove    # take it away
```

It registers a scheduled task that runs at your sign-in or, when Windows will
not let your account register one, puts a shortcut in your Startup folder.
Either runs `scripts\start_at_sign_in.ps1`: the normal start without opening a
browser, tried again for a few minutes while Windows services such as MongoDB
come up. Each sign-in start is logged in `.atdr_runtime\logs\autostart.log`.
No password is stored, and nothing starts before someone signs in.

Normal startup requires the approved shell package/private profile, Python
3.11, Node.js 20.19 or newer, npm, and MongoDB on loopback for the companion
shell. Redis is optional: the shell rate limiter has an in-memory local
fallback, although a shared deployment should provide its approved cache
service.

## Daily Operator Checks

1. Run `check_system.cmd`; require installation, provider, and all service
   checks to pass.
2. Review source health, parser warnings, failed imports, and stale jobs.
3. Review new High/Critical alerts, ownership, SLA state, and related evidence.
4. Confirm `RESPONSE_SIMULATION=true`, rules remain authoritative, and no model
   has been promoted.
5. Review Assistant provider health and provenance. Raw-log provider context
   must remain disabled.
6. Review audit events for failed logins, account changes, alert actions, and
   simulated response requests.

## MFU Behaviour Model Alerts

The MFU behaviour model raises experimental, low-confidence alerts where the
rules raise none, for the attack types switched on its model card. Every
detection run (the dashboard's Check all unchecked logs and automatic checks included) raises them for
the windows it checked; the scoreboard and blind check never do. A run's alert
count includes them, and its details separate rule alerts from model alerts. The
detection runtime status reports them as permitted by a recorded exception, not
as qualified.

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.model_alerts status
.\.venv\Scripts\python.exe -m atdr.scripts.model_alerts disable --actor "Name" --reason "Why"
.\.venv\Scripts\python.exe -m atdr.scripts.model_alerts enable --types all --actor "Name" --reason "Why"
.\.venv\Scripts\python.exe -m atdr.scripts.model_alerts run --actor "Name"
```

Each switch is written to the model card and the audit log; restart ATDR after
switching. `ATDR_MODEL_ALERTS=false` in the environment stops model alerts
without changing the card.

## Advisory Anomaly Capability

IsolationForest is optional supporting context. Its absence never prevents
startup or deterministic rule detection. The launcher, `/health`, and AI
Governance report `Advisory anomaly model unavailable` and show this read-only
preflight:

```powershell
.\scripts\bootstrap_advisory_anomaly.cmd -UseCommittedSyntheticSample -Pretty
```

Only a reviewed, exact-confirmation run may train. It uses disposable SQLite
and writes only an ignored artifact and sanitized manifest. Follow
`docs/archive/phases/V5_61_GOVERNED_ANOMALY_BOOTSTRAP.md`; never copy a developer artifact to
a teammate, commit it, or describe availability as validated threat accuracy.

API liveness is `GET /health/live`; operational health is `GET /health`.
Prometheus metrics are available only when the configured deployment profile
enables them.

## Log Ingestion And Detection

Prefer the dashboard for normal analyst work. A whole MFU firewall export
(about 600 MB for 21 minutes of traffic) goes through **Data & Detection >
Queue import**: the background worker imports it in checkpointed chunks. The
rules and watchlist then run over the new logs, by themselves when automatic
detection is on (below) or when you click **Check all unchecked logs**.
Rehearsed on 2026-09-27 with the 13:45-13:57 part of the MFU export (351 MB,
453,908 lines) on a copy of the database: upload 3 s, import 7.9 min, checks
2.9 min, 883 new alerts; dashboard and lists stayed under a second. Queued
imports take up to 1 GB by default (`OPERATION_JOB_MAX_INPUT_BYTES`).

For an operator-controlled file import, keep the log outside Git and pass its
private path only at runtime (about 1 ms per line):

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.import_logs "D:\Private Logs\firewall.log" --limit 5000
```

Overlapping exports are safe to import. A parsed Palo Alto record carries the
firewall's own serial and sequence number, so an exact copy of a stored one is
the same record imported again: every import path (queued, command line and
syslog) counts it as a duplicate and does not store it twice. A generic syslog
line, or a line that did not parse, has no such identity and can repeat for
real events (a burst of identical failed logins), so its repeats are counted
and kept as evidence. The counts appear in each import's result and in the
dashboard's data-quality figures.

To receive the firewall's logs as they are sent, use the syslog receiver (Live
Syslog, below).

Raw evidence is preserved before parsing. Parser failure does not discard the
row. Detection checks stored logs by itself when automatic detection is on, or
from the dashboard; check source/parser quality first for a new source.
Rule findings create authoritative alerts; anomaly and supervised scores add
advisory context only.

## Live Syslog

The firewall can send its logs to ATDR over UDP syslog instead of in exports.
With `SYSLOG_ENABLED=true`, `scripts\start_system.cmd` (and so the sign-in
start) runs the receiver beside the other parts, as `atdr-syslog`. A receiver
that stops on an error starts again after 5 seconds.

- `SYSLOG_HOST` is the address it listens on. The default, 127.0.0.1, accepts
  only this machine. To receive the firewall's logs, set it to this machine's
  address on the network the firewall reaches, and allow UDP `SYSLOG_PORT`
  (default 5514) from the firewall in Windows Firewall.
- One thread takes lines off the network into memory as they arrive; another
  saves them in batches of `SYSLOG_BATCH_SIZE` (default 1,000), no later than
  `SYSLOG_FLUSH_SECONDS` (default 2) after a line arrives, so a quiet stream is
  saved too and never holds the database.
- While another writer holds the database, such as a detection run writing
  its alerts, lines wait in memory, up to `SYSLOG_MAX_PENDING_LINES` (default
  100,000: about 100 MB, nearly 3 minutes of MFU's traffic). Beyond that a line
  is dropped and counted, not lost unseen.
- Data & Detection shows whether the receiver is receiving, its rate, the
  lines received, saved and lost since it started, and when the last line
  arrived. It says so when the receiver is on but has stopped reporting.

Run by hand, for a test on loopback:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_syslog_receiver --host 127.0.0.1 --port 5514
```

Measured on 2026-10-08 on a copy of the database, sending the first 8 min 44 s
of the MFU export at its recorded rhythm (a median of 568 lines a second, and
up to 1,014), then the same traffic again with its times moved later, so that
automatic checks ran while lines arrived. The blind-check lines were never
read.

| | Before the rebuild | After |
|---|---|---|
| Lines saved at MFU's rate | 80% (500 a second at most) | all 638,252 |
| When an automatic check ran | the receiver ended with "database is locked" | carried on, no retry needed |
| At four times MFU's rate (319,126 lines in 132 s) | not tried | all saved, at about 2,000 a second |

Before, the receiver saved one line at a time in the loop that read the
network, so lines that arrived meanwhile overflowed the operating system's
socket buffer, and Windows counted none of them as errors. A detection run
also held SQLite's write lock from its start to its final commit (44 seconds
for one window of MFU traffic); it now saves its run record first and holds
the lock only while it writes alerts.

Limits:

- UDP has no delivery guarantee: a line lost on the network before it reaches
  this machine cannot be counted.
- Stopping ATDR ends the receiver's process, so lines waiting in memory at that
  moment (normally a second or two of traffic) are lost. The next start closes
  its run as stopped, with the counts from its last report.
- With the receiver running, a detection check of one five-minute window of
  MFU's traffic (about 181,000 logs) takes about a minute.

### How Long Live Logs Are Kept

Logs from the live feed are kept for `SYSLOG_RETENTION_HOURS` (default 6),
then deleted. Imported files are datasets kept on purpose and are never
deleted this way.

- The background worker does it (`OPERATION_WORKER_ENABLED=true`): every 5
  minutes while it has no queued job, 2,000 logs a step, so the receiver and
  detection are never held up for long.
- An hour is summarised before it is deleted: one row for each source
  address, with its connections, denied connections, bytes sent and received,
  and how many destinations and destination ports it reached. Log Explorer
  shows them under **Older live traffic, by hour**, and its Source IP filter
  follows one address. Summaries are kept `SYSLOG_SUMMARY_RETENTION_DAYS` days
  (default 30).
- Whole hours only: an hour goes once all of it is past the limit, so a log
  stays 6 to 7 hours.
- Never deleted: a log detection has not checked yet, a log that is evidence
  for an alert, and a labelled log. With automatic detection off, nothing is
  deleted, and Data & Detection says so.
- Below `SYSLOG_MIN_FREE_DISK_GB` of free disk (default 10) the receiver stops
  saving and counts lines as lost until space is freed. The page shows it.

A stored log takes about 3.5 KB with its indexes (measured on 319,126 logs):
7.6 GB an hour at MFU's rate, about 46 GB for six hours. It was 6.2 KB: each
row also held the line's fields a second time (1.1 KB), which made a row too
big to share a 4 KB database page, so 42% of the table was empty. Log
Explorer's Parsed Payload reads those fields again from the raw line.

Rehearsed on 2026-10-08 with the feed running at MFU's rate, on a copy, with
two-minute steps and a three-minute limit standing in for the hours: all
638,252 lines were saved, 370,590 were deleted once detection had checked
them, the summaries' connections added up to 638,252, and all 46,533 evidence
logs were kept. Stored logs peaked at 413,309 and the database file stopped
growing, because SQLite reuses the space of deleted logs (the file itself does
not shrink). A five-minute window of MFU's traffic (180,924 logs) was checked
in 57 seconds meanwhile.

Limit: alert evidence is kept as long as its alert. In the replay 2.8% of
logs became evidence, which at MFU's rate adds about 5 GB a day (it was 7.3%
and about 13 GB before alerts were grouped as described under Alert
Grouping). Nothing deletes old evidence yet.

## Automatic Detection

With `AUTO_DETECTION_ENABLED=true` and the background worker running
(`OPERATION_WORKER_ENABLED=true`), new logs are checked without anyone clicking:

- The worker looks for unchecked logs whenever it has no queued job (every
  `AUTO_DETECTION_POLL_SECONDS`, default 15). Queued jobs come first.
- It checks a five-minute window of logs once the window after it is complete,
  that is, once a log two windows later has been stored. The rules count per
  source and five-minute window, on two clock grids, and the beaconing rule
  also reads the window after a log's own; checked earlier, a group is judged
  on part of its logs. For a live feed this means an alert 5 to 10 minutes
  after the traffic.
- When no log has been stored for `AUTO_DETECTION_QUIET_SECONDS` (default 120),
  an import has finished or the feed has gone quiet, and every unchecked log
  is checked.
- Each check is recorded like a manual one: an operation job requested by
  `auto_detection` and a detection run per step, with the MFU behaviour
  model's experimental alerts for the windows checked.

Data & Detection shows whether automatic checks are on, whether the worker is
running, and what the last check did. **Check all unchecked logs** still checks
everything at once. Switched on without the worker, nothing is checked by
itself, and the page says so.

Measured on 2026-10-07 with traffic that crosses a window edge
(`atdr/tests/test_auto_detection.py`): with this wait, logs arriving live get
exactly the alerts that checking the stored traffic window by window gives.
Checked as soon as its own window closed, the first half of a port scan was
raised as "multiple denied connections" (High) instead of a port scan
(Critical); checked half a window later, a beacon's alert kept four of its six
check-ins.

Limits:

- Detection is not real time: a live feed is alerted on 5 to 10 minutes after
  the traffic.
- A log that arrives late, for a window already checked, is checked on its own.
- SQLite has one writer, so a check that finds an import or a manual check
  writing waits for the worker's next look.

## Alert Grouping

- One alert for each kind of activity and source. New activity of the same
  kind from the same source joins the alert still open for it, up to 24 hours
  after that alert's last activity, whatever the port. So an attack that
  crosses a five-minute window, or a scanner that moves to another port, stays
  one alert. Close an alert and the next activity opens a new one.
- Scanning from the internet goes on one **Internet scanning** alert an hour
  (Medium). Its drawer lists the hour's scanners, busiest first. A scanner
  that does more keeps its own alert: a firewall threat or malware record, a
  watchlist match, brute force, another kind of alert still open, or its own
  scan alert still open. Scans from inside MFU and repeated denied attempts
  keep their own alerts too.
- From the live feed the scanning alert keeps 20 evidence logs for each
  scanner and hour and counts the rest, which are deleted with the other live
  logs. Imported logs are all kept as evidence.
- A large alert opens like a small one. Its drawer shows the first 100 linked
  logs and previews the first 25 evidence logs of its report, and says how
  many there are; the CSV and HTML downloads list every one.
- Which logs are flagged did not change (rule catalog v5.37.0): on the team's
  labels 382 right, 13 false and 3 missed before and after, while the 120,001
  imported logs give 78 alerts instead of 158.
- The live list was rebuilt under this grouping on 2026-10-09: its 165 alerts
  became 85 with the same 7,773 logs flagged, and 76 alerts for scanning from
  the internet became one that lists 130 addresses
  (`docs/detection/ALERT_REBUILD.md`).
- Measured at MFU's firewall rate on 2026-10-08 (8 min 44 s of the export,
  then the same traffic again): 214 alerts instead of 556. The repeated
  traffic raised 16 alerts instead of 186, one Internet scanning alert listed
  316 scanners, and 17,613 logs were kept as evidence instead of 46,533. An
  hour of real traffic would bring between about 110 alerts (the same
  sources carrying on) and about 940 (new sources arriving as fast as in the
  second five-minute window); it was about 1,900.

## Analyst Workflow

1. Open an alert and read `Why flagged`, evidence strength, parser caveats,
   related logs, and the recommended checks.
2. Compare nearby activity and source health before changing status or label.
3. Use the SOC Assistant for concise synthesis; verify its cited alert, log,
   source, job, or governance references in ATDR.
4. Record investigation notes and ownership.
5. Any response remains an analyst-confirmed simulation and is written to the
   audit trail. Never describe it as firewall enforcement.

## Backup And Restore

Preview a backup first, then write only to ignored or external storage:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.backup_database --output-dir .atdr_runtime\backups --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.backup_database --output-dir .atdr_runtime\backups --execute --pretty
```

Restore is deliberately restricted to a new empty target:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.restore_database `
  --backup-path "D:\Private Backups\atdr-backup" `
  --manifest-path "D:\Private Backups\manifest.json" `
  --target-database-url "sqlite:///./.tmp/restored-atdr.db" `
  --pretty
```

Execution additionally requires `--execute --confirm
RESTORE_TO_NEW_EMPTY_TARGET`. Never point a restore drill at the configured
database. Use the isolated disaster-recovery exercise for rehearsal:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_disaster_recovery_drill --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_disaster_recovery_drill --execute --confirm ISOLATED_V395_DRILL --pretty
```

## Local Recovery

Local username/password access is an explicit recovery profile, never a silent
fallback. Stop the shell-first runtime, make a private database backup, set
`ATDR_AUTH_MODE=local_recovery` only in the ignored local environment, then run
the established FastAPI and React component commands in separate terminals:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.check_dev_environment
.\.venv\Scripts\python.exe -m atdr.scripts.seed_users
.\.venv\Scripts\python.exe -m uvicorn atdr.app.main:app --host 127.0.0.1 --port 8000
```

```powershell
Set-Location frontend
npm.cmd run dev -- --host 127.0.0.1
```

Return the private profile to `template_shell` before normal operation. Never
use recovery credentials as a substitute for MFU account acceptance.

## Shared Deployment

The repository contains reference Nginx, systemd, worker, monitoring, secret,
backup, and recovery assets under `deploy/`. They are not proof of a deployed
environment. Before a shared-host claim, require PostgreSQL, migrations at
head, multiworker ownership, shared storage, HTTPS, managed secrets,
monitoring/alerts, backup/restore, measured RPO/RTO, rollback, load, and
disaster-recovery evidence from the host owner.

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_deployment_operations --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v553_release_readiness --pretty
```

## Troubleshooting

| Symptom | Safe action |
| --- | --- |
| PowerShell policy blocks `.ps1` | Use the tracked `.cmd` wrappers. |
| Startup says processes already run | Run `check_system.cmd`; use `stop_system.cmd` for launcher-owned processes. |
| A required port is occupied | Stop the owning application; do not kill unrelated processes blindly. |
| MongoDB is unavailable | Start MongoDB for the MFU shell; ATDR's SQL database is separate. |
| Shell backend briefly logs Redis timeout | Local fallback is expected; confirm `/healthz` becomes ready. |
| Google returns `400 invalid_request` | Use the exact approved origin and ask the MFU/Google owner to authorize the account/client. |
| MFU account is outside project scope | Ask the IAM owner for the approved group/scope; do not bypass it. |
| Backend reports database unavailable | Check `DATABASE_URL`; normal laptop use is `sqlite:///./atdr.db`. |
| Assistant provider fails | Confirm deterministic fallback, redaction, and raw-log exclusion; never expose the key. |
| Import stalls/fails | Inspect operation job state, worker heartbeat, staging capacity, and source/parser warnings. |

## Release Checks

Run the clean-machine preflight with the separately delivered approved shell
archive:

```powershell
py -3.11 -m atdr.scripts.run_v560_clean_machine_acceptance `
  --shell-package "D:\Approved Artifacts\mfu-atdr-shell-1.4.0-atdr.1.zip" `
  --pretty
```

Execution requires `--execute --confirm DISPOSABLE_V560_CLEAN_MACHINE`. It is
destructive only to its uniquely verified Windows temporary directory and its
uniquely named synthetic shell database. It never reads the configured ATDR
database or copies the current private environment.

Use `docs/QUICKSTART_FOR_TEAM.md` for installation and
`docs/EXTERNAL_ACCEPTANCE.md` for evidence that cannot be produced locally.
Configuration alone is never external acceptance, and
`production_ready` must remain false until every named owner has supplied real,
current evidence.
