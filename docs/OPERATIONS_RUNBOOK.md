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

From the folder ATDR runs from. On the team laptop that is the live copy,
`C:\ATDR-live` (see [Releasing A New Version](#releasing-a-new-version)); on
a machine without one it is the repository root:

```powershell
.\scripts\start_system.cmd
.\scripts\check_system.cmd
.\scripts\stop_system.cmd
```

The settings that count (`.env`), the database (`atdr.db`) and the logs
(`.atdr_runtime\logs`) are that folder's too. In the folder ATDR is developed
in, `start_system.cmd` refuses and names the live copy.

Wait for `All components are ready` before opening the login page. To restart,
run `stop_system.cmd` and then `start_system.cmd`. The launcher tracks only the
processes it owns and keeps logs in ignored `.atdr_runtime/logs/`. Two starts
never run at once: the second says that ATDR is being started by another
process and leaves.

The dashboard is served from its built files (`frontend/dist`), not from its
source, by `atdr.scripts.serve_dashboard` on the address it always had
(`http://127.0.0.1:5173`), with the security headers of
`deploy/nginx/atdr.conf.example`. `start_system.cmd` builds it first when the
source is newer than the build (about 15 seconds) and says so on its
`Dashboard:` line. A build that fails leaves the last good build in place and
is reported in yellow; the next start tries again. By hand:
`python -m atdr.scripts.build_dashboard` (`--force` to build anyway, `--check`
to ask only). A change to the dashboard's source shows after the next start,
or after that command and a reload of the page while ATDR runs; never by
itself. In a live copy the source changes only through a release, which
builds the dashboard as one of its steps. Do not run `npm run build` in the
folder ATDR runs from while it runs: it empties the folder the dashboard is
being served from. For live reload while changing the dashboard, stop ATDR
and run the API and `npm run dev` by hand as shown under Local Recovery.

## Keeping ATDR Running

By itself ATDR does not start after a restart and does not bring back a part
that stops. Install both, once for each machine and Windows user:

```powershell
.\scripts\autostart.cmd            # install
.\scripts\autostart.cmd -Status    # what is installed
.\scripts\autostart.cmd -Remove    # take it away
```

It registers two scheduled tasks. Neither needs an administrator, no password
is stored, and nothing runs before someone signs in. Both run without a
console window: on 2026-10-09 Windows closed the hidden window of the sign-in
start seconds after each of three sign-ins, and the start ended with it.

- **ATDR start at sign-in** runs `scripts\start_at_sign_in.ps1` at your
  sign-in. It first puts on record that ATDR is meant to run and starts the
  watcher, then makes the normal start without opening a browser, tried again
  for a few minutes while Windows services such as MongoDB come up. When
  Windows will not let your account register the task, a shortcut in your
  Startup folder does the same. Each sign-in start is logged in
  `.atdr_runtime\logs\autostart.log`.
- **ATDR keep running** runs the watcher, `scripts\watch_system.ps1`. Every 30
  seconds it looks at each part ATDR is set up to run (the API server, the
  dashboard, the background worker, the live syslog receiver when it is on,
  and the two parts of the MFU sign-in shell) and
  - starts a part whose process has gone;
  - stops and starts a part that is running but has not answered for three
    minutes (not in a part's first five minutes: the MFU shell compiles);
  - starts everything when nothing is running, such as after a sign-in start
    that failed;
  - starts the SOC Assistant's Ollama app when it is not running (looked at
    every five minutes).

  A part that keeps dying is started three times in ten minutes, then once
  every five. Windows looks every minute whether the watcher itself is
  running and starts it when it is not; while it runs, nothing is launched.
  When Windows will not let your account register this task, the installer
  says so: ATDR then starts at sign-in, but a part that stops stays stopped.

What ATDR is meant to be is on record in `.atdr_runtime\desired-state.json`,
so the watcher never undoes a stop:

| Command | ATDR is then | The watcher |
| --- | --- | --- |
| `start_system.cmd` | meant to run | brings back a part that stops |
| `stop_system.cmd` | stopped until the next sign-in, or until it is started | leaves it stopped |
| `stop_system.cmd -HoldHours 2` | stopped for two hours, across a sign-in too | starts it again after that time |

Use `-HoldHours` for work that needs ATDR down: an alert rebuild, a restore,
the full test suite. Without it a sign-in starts ATDR in the middle of the
work; with it, a stop that was forgotten still ends by itself. To start sooner
than the hold ends, run `start_system.cmd`.

To take the watcher away, use `autostart.cmd -Remove`. Do not end the **ATDR
keep running** task in Task Scheduler: Windows then also ends every part the
watcher had brought back.

Where to look:

- the **System** panel on Data & Detection (admins; the same as
  `GET /api/system/status`): each part, when it started, how often it was
  restarted in 24 hours, and what the watcher last had to do;
- `check_system.cmd`: the lines `Meant to be` and `Watcher`;
- `.atdr_runtime\logs\watch.log`: each start the watcher made and how it went;
- each part's own log in `.atdr_runtime\logs\`, for why it stopped.

Measured on the team laptop on 2026-10-09 by ending processes of the running
system:

| What was done | How long until it was back |
| --- | --- |
| Background worker ended | 11 s |
| Dashboard ended | 10 s |
| API server ended | 28 s |
| Both parts of the MFU sign-in shell ended together | 33 s and 45 s |
| Every part ended at once | 9 to 18 s |
| Dashboard frozen (running, answering nothing) | 3 min 49 s |
| The watcher itself ended | 13 to 24 s (started by Windows) |
| Laptop shut down at 12:07 and switched on at 14:46 | ATDR and the watcher were running after the sign-in, with nothing done by hand |

ATDR stopped with `stop_system.cmd` was still stopped 75 seconds later, and a
stop held for 40 seconds was ended by the watcher: the API answered 52 seconds
after the stop.

Two limits remain. Nothing runs before someone signs in to Windows, so after
a restart ATDR is down until the next sign-in. And nothing runs while the
laptop sleeps; on 2026-10-09 it was set to sleep after an hour without use on
mains power. Neither loses data while logs arrive only by import. Both must be
closed before the live syslog feed is switched on: start at boot (it needs an
administrator once) and no sleep on mains power.

Normal startup requires the approved shell package/private profile, Python
3.11, Node.js 20.19 or newer, npm, and MongoDB on loopback for the companion
shell. Redis is optional: the shell rate limiter has an in-memory local
fallback, although a shared deployment should provide its approved cache
service.

## Releasing A New Version

ATDR runs from a copy of its own, the **live copy** (`C:\ATDR-live` on the
team laptop). It only ever holds a version that was committed and checked.
The folder ATDR is developed in is where a change is made, tested and
committed; nothing done there reaches the running system until it is
released.

Before, ATDR ran from the folder it is developed in, and a part that
restarted or a sign-in loaded whatever the files held at that moment. On
2026-10-10 a held stop ran out overnight and the sign-in start brought ATDR up
on code that was neither finished nor committed, and again on 2026-10-11. A
hold only delays that.

Run in the folder ATDR is developed in:

```powershell
.\scripts\release.cmd            # what runs, and what is waiting to be released
.\scripts\release.cmd check      # check HEAD without releasing it
.\scripts\release.cmd go         # check HEAD and make it the version that runs
.\scripts\release.cmd back       # the version before, when a released one is still wrong
.\scripts\release.cmd recover    # after a release that was cut off: put back what was running
.\scripts\release.cmd setup      # once for each machine: make the live copy
```

`check`, `go` and `setup` take a commit after them; without one they mean
HEAD. Exit code 0: done; 1: refused, or the version before was put back; 2:
ATDR is not running.

**What counts as checked.** Only a commit on `main` that contains the version
that runs is released, and only once it is checked:

| The commit | What decides |
| --- | --- |
| is on GitHub and its checks have finished | They must all be green. Red is red: tests that pass on the laptop do not change it. |
| is on GitHub and still being checked | The release waits up to 30 minutes for the result. |
| is not on GitHub, or GitHub ran no check for exactly it | The whole suite runs on the laptop, as GitHub's two main jobs do: Python compiles, ruff, the backend tests, the migrations, the dashboard's lint and build, the browser tests. About 20 minutes. |

`--local` runs the tests on the laptop in any case. They only count for a
folder that holds exactly the commit: HEAD is that commit, no tracked file is
changed, and there is no new file outside `docs\` (a module nobody added to
the commit would make the tests pass on files the release does not have). The
tests get an empty database of their own under `.tmp\release-check`, so they
run while ATDR runs. A commit that passed is on record in
`.atdr_runtime\release-checks` and is not checked twice; everything the last
check said is in `.atdr_runtime\logs\release-check.log`.

**What a release does.**

1. While ATDR still runs: the live copy fetches the commit, and when the
   commit needs other Python packages they are installed into an environment
   of their own. A failure here ends the release with nothing touched.
2. ATDR's own parts are stopped (the API server, the background worker, the
   live syslog receiver, the dashboard). The MFU sign-in page stays up.
3. The files are moved to the commit. A version that changes the database is
   migrated behind a checked backup (purpose `before_release`, in the folder
   the scheduled backups go to; the newest three are kept). The dashboard is
   built.
4. The watcher starts the parts again, so they belong to its task like any
   part it brings back, and not to the window the release was run from.
5. The new version is watched for a minute: every part must stay up, as the
   same process, and answer; the API must report its database ready and at
   this version's schema.

When any step from 2 on fails, everything is put back as it was: the files,
the Python environment, the database (from the backup taken in step 3; what
the failed version left is kept in
`.atdr_runtime\release\database-of-failed-release`), the dashboard, and ATDR
is started and watched again. The release then ends with exit code 1 and says
which part or step was the cause.

**What the live copy holds.**

| | Where it comes from |
| --- | --- |
| The files of one commit, byte for byte | A clone of the development folder's repository, with no line-ending conversion |
| `.env` | Its own. Copied from the development folder when the copy was made; from then on this is the file that counts |
| `atdr.db` | Its own. Copied, and checked row for row, when the copy was made |
| Trained models, and the evidence the pages show (`atdr\models`, `demo_exports`, `ml_baseline_reviews`) | Copied when the copy was made. A retrained model goes live by copying its files there and restarting ATDR |
| Python | Its own interpreter in `.python`, and one environment for each set of packages in `.venvs`. `.venv` points at the one in use, so every written command works there too, and the environment of the version before is kept to go back to |
| `.atdr_runtime\release.json` | Which version runs, since when, how it was checked, and the last thirty releases |

A release never changes the live copy's `.env`. When a version knows a
setting the one before it did not, the release names it; it keeps its default
until it is put in `C:\ATDR-live\.env`.

**What keeps the two folders apart.**

- `start_system.cmd` in the development folder refuses and says where ATDR
  runs. `-Development` starts that folder's own copy anyway, which needs the
  live copy stopped first: both use the same addresses.
- `autostart.cmd` there neither installs nor removes the two tasks: they
  belong to the live copy.
- When the live copy was made, the development folder's `.env` was changed so
  that nothing started there writes into the backup folder or sends a
  message (`ATDR_BACKUP_DIRECTORY`, `ATDR_BACKUP_SCHEDULE_HOURS`,
  `ATDR_NOTIFY_EMAIL_TO`, `ATDR_NOTIFY_CHAT_WEBHOOK_URL`,
  `ATDR_NOTIFY_WINDOWS`). The file as it was is in
  `.atdr_runtime\config-backups`.
- A file changed by hand in the live copy would run at the next restart with
  no check at all. The background worker looks every five minutes and says so
  under the bell; the next release refuses until the file is put back
  (`git -C C:\ATDR-live checkout -- .`).
- The System panel shows the version that runs, when it went live and how it
  was checked.

**A release that was cut off** (the laptop went down in the middle) leaves
`.atdr_runtime\release-in-progress.json` in the live copy. While it is there
nothing starts that folder: its files may be half of one version and half of
another. `release.cmd recover` puts back the version that was running and
starts it.

**Going back.** `release.cmd back` makes the version before the one that runs
the version that runs, with the same steps. It refuses when the newer version
changed the database: what was stored since would not fit the older one. Fix
that with a new release.

Limits:

- A release needs the two tasks of `autostart.cmd` in the live copy: they are
  what starts ATDR.
- ATDR's own parts are down while the files change (measured below). Log
  lines a firewall sends by syslog in that time are lost.
- A newer Python is not installed by a release: the live copy keeps the
  interpreter it was made with.

Measured on the team laptop on 2026-10-11, when the live copy was made
(`release.cmd setup`, of the version GitHub had passed):

| Step | Time |
| --- | --- |
| With ATDR still running: the copy's files, its Python and 73 packages (837 MB), 1.3 GB of models and evidence in 10,102 files, the dashboard's build tools and build | 6 min 24 s, of which the packages 4 min 30 s |
| ATDR stopped; the 669 MB database copied and checked row for row | 11 s |
| The two tasks given to the copy; every part running from it | 54 s after the stop |
| The copy watched before it counted as running | 60 s |

The copy takes 3.1 GB. The System panel then showed the last backup of the
day before: the two backups on D: had followed the database to its new place.

## Notifications

ATDR tells people what they need to know without anyone opening a page:

- **New Critical alerts**, within about two minutes of being raised. The
  alerts of one burst are one message: ATDR waits until a minute has passed
  without a new one, five minutes at most. While alerts keep coming, the
  next message follows no sooner than 30 minutes after the last
  (`ATDR_NOTIFY_ALERT_MINUTES_BETWEEN`). `ATDR_NOTIFY_ALERT_SEVERITY="High"`
  sends High alerts at once as well.
- **A summary each day** at `ATDR_NOTIFY_SUMMARY_AT` (08:00): the alerts
  raised since the last summary by severity, what is open, and what about
  ATDR still needs attention. If the machine was off at that time, the
  summary goes when it is next on. A day without a summary means ATDR was
  not running.
- **Problems of its own**, when they begin and when they are over: a backup
  that failed, a part that keeps stopping, ATDR that could not be started,
  the live feed not running, losing lines or hearing nothing from the
  firewall, a disk almost full, an automatic check that failed. Two things
  are reminders only, in the bell and in each daily summary but not sent
  out: no recent copy of the backups on another disk, and no watcher.

Every notification is kept 90 days under the **bell** in the dashboard's
header; ATDR's own problems are shown there to admins only. A message names
the kind of attack, the severity, the alert's number and the time. It never
holds an IP address: the same words go to every channel.

An alert that was already on the list when notifications were first switched
on is not reported, nor are the alerts a rebuild or a reset raises.

### Where messages go

| Channel | Switched on by | Notes |
| --- | --- | --- |
| Bell in the dashboard | always | |
| Windows notification on ATDR's machine | `ATDR_NOTIFY_WINDOWS=true` (the default) | Clicking it opens the alert or the System panel. While Windows' Do Not Disturb is on it goes to the notification centre without a banner. |
| Email | `ATDR_NOTIFY_EMAIL_TO` and the `SMTP_*` settings | See below. |
| Chat group | `ATDR_NOTIFY_CHAT_WEBHOOK_URL` | Discord, Slack, Google Chat, or any service that takes `{"text": "..."}`. |

Settings are read when ATDR starts: after changing `.env`, run
`stop_system.cmd` and `start_system.cmd`. Then open Data & Detection. The
System panel lists each channel, says what is missing for one that is off,
and has a **Send a test** button for each one that is on. From a terminal:
`python -m atdr.scripts.notify --test email` (or `chat`, `windows`).

**Email through Gmail.** Use a Gmail account made for ATDR, not a personal
one. Switch on 2-Step Verification for it, create an app password (Google
Account, Security, App passwords), and put in `.env`:

```text
ATDR_NOTIFY_EMAIL_TO="first.person@example.org, second.person@example.org"
SMTP_HOST="smtp.gmail.com"
SMTP_PORT=587
SMTP_USERNAME="the.account@gmail.com"
SMTP_PASSWORD="the 16-letter app password"
SMTP_FROM_EMAIL="the.account@gmail.com"
SMTP_USE_TLS=true
```

A school or work Google account may have app passwords switched off by its
administrator. Gmail answers an account's own password with `Username and
Password not accepted`; ATDR then says that Gmail takes an app password. ATDR
encrypts the connection before it gives the password, refuses to send a
password over a connection that is not encrypted, and signs in once for each
message. An account that is named without a password (`SMTP_PASSWORD` empty)
leaves the email channel off, and the System panel says so.

**A chat group.** In Discord: the channel's settings, Integrations, Webhooks,
New Webhook, Copy Webhook URL. In Slack: an app with Incoming Webhooks. In
Google Chat: the space's Apps & integrations, Webhooks. Put the address in
`ATDR_NOTIFY_CHAT_WEBHOOK_URL`. It is a secret: whoever has it can post to
the group. ATDR never shows it; the System panel names only the service.

### When a channel fails

One channel failing does not hold up another. A message that could not be
sent is tried again after 1, 5, 15 and 60 minutes, then every hour, and is
given up when the notification is a day old (audit entry
`notification_failed`). A failure that only a changed setting can end is not
tried again at all: a sign-in the mail server refuses, a sender or addresses
it will not take, a chat address that no longer exists. Each try would be one
more refused sign-in on the account. Put the setting right and use Send a
test. An email that reached some of its addresses is not
sent again: the System panel says how many addresses the mail server refused.
The System panel shows what the last message through each channel did and,
when it failed, why. Each message sent is an audit entry, `notification_sent`.

The background worker looks for something to tell every 30 seconds and sends
the messages. The watcher reports a part that keeps stopping through
`python -m atdr.scripts.notify`, which sends by itself, so a worker that
stopped is still reported; it reports the part running again once it has
stayed up for ten minutes. Nothing can be sent while the machine is off or
asleep.

Measured on the team laptop on 2026-10-10: a test message from the System
panel arrived in Windows' notification centre. With the background worker
ended four times in two minutes, the watcher reported it 30 seconds after the
fourth time, started it again five minutes later, and reported it running
again once it had stayed up ten minutes; both reports arrived in Windows and
under the bell. Email was tried against Gmail once that day: the connection
and its encryption worked, and Gmail refused the sign-in because it was given
the account's own password, not an app password. No message has yet gone out
through a real mail account or chat group; both are otherwise tested against a
mail server and a web server that run inside the test suite. After setting
one up, use Send a test.

## Daily Operator Checks

1. Run `check_system.cmd`; require installation, provider, and all service
   checks to pass, and the line `Watcher: watching`.
2. Open Data & Detection and read the System panel: no part keeps stopping,
   the last backup is less than a day old, the copy on another disk is less
   than a week old, and no notification channel shows a failure. Look at
   the bell for anything unread.
3. Review source health, parser warnings, failed imports, and stale jobs.
4. Review new High/Critical alerts, ownership, SLA state, and related evidence.
5. Confirm `RESPONSE_SIMULATION=true`, rules remain authoritative, and no model
   has been promoted.
6. Review Assistant provider health and provenance. Raw-log provider context
   must remain disabled.
7. Review audit events for failed logins, account changes, alert actions, and
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

### Scheduled backups

With `ATDR_BACKUP_SCHEDULE_HOURS=24` in `.env` the background worker backs the
database up every day while ATDR runs. It looks for a due backup when it
starts and every five minutes after that, and writes into
`ATDR_BACKUP_DIRECTORY` (`backups\scheduled` beside the database when that is
empty). On the team laptop it is `D:\ATDR-backups`. `0`, the default, leaves
backups to whoever runs the command further down.

- The copy is made with SQLite's backup API while ATDR runs and then checked:
  its checksum must match its manifest and SQLite must find it healthy. A copy
  that fails is removed and reported, and the next try is an hour later.
- Scheduled backups are thinned to the newest of each of the last 7 days, 4
  weeks and 6 months that have one (`ATDR_BACKUP_KEEP_DAILY`, `_WEEKLY`,
  `_MONTHLY`): at most 17 files. A backup taken by hand or before a reset is
  never deleted. When the folder has no room for the next backup (the
  database's size and 512 MB to spare), the oldest scheduled ones go first and
  the newest never does.
- **A copy on another disk.** D: on the team laptop is a second partition of
  its only disk and is lost with that disk. So whenever a drive on another
  physical disk is connected that has a folder named `ATDR-backups` at its top
  (a USB drive; `ATDR_BACKUP_OFFSITE_FOLDER`), the worker copies the newest
  backup to it within five minutes, checks the copy there and thins that
  folder the same way. A second partition never counts as another disk. The
  System panel says when that copy was last made and warns once it is more
  than a week old.
- Each backup's manifest names the database it is a copy of: the computer and
  the database file. ATDR counts, thins and copies only the backups of the
  database it runs on. So two computers can share a folder or a USB drive,
  and a backup of another database that lands in the folder (a test copy, a
  teammate's backup put there to restore from) is neither counted nor ever
  deleted. After the database's folder is moved by hand or the computer is
  renamed, ATDR therefore starts a new series with a backup at once; the old
  series stays until someone deletes it. `release.cmd setup`, which moves the
  database into the live copy, takes its backups along: it writes the new
  place into their manifests.
- A release that changes the database takes a backup first (purpose
  `before_release`, listed among "other backups"); the newest three of those
  are kept. By hand, at any time:
  `.\.venv\Scripts\python.exe -m atdr.scripts.backup_now` takes a checked
  backup into the same folder, which is never thinned out.
- Each backup, each failure and each copy is an audit entry:
  `database_backup_created`, `database_backup_failed`,
  `database_backup_copied_offsite`. A failure that lasts is entered once a
  day, not at every try.
- A schedule needs the background worker (`OPERATION_WORKER_ENABLED=true`);
  the System panel says so when the worker is not running.

Measured on 2026-10-09: the 638 MB database was copied to D: and checked in 3
seconds, and a restore from that backup into a new file gave back all 120,001
logs, the 85 alerts and the alert numbering.

**Reset to sample data** (Data & Detection) asks for the word RESET, takes a
backup first, which is kept for good, and deletes nothing when that backup
fails or when the sample file it was given does not exist. The new audit log
opens with a `data_reset` entry that names the backup. The notifications
about the deleted alerts go with them, and the sample's alerts are not
reported as new.

### Restoring a backup

In the folder ATDR runs from (`C:\ATDR-live` on the team laptop):

```powershell
.\scripts\stop_system.cmd -HoldHours 1
.\.venv\Scripts\python.exe -m atdr.scripts.restore_database `
  --backup-path "D:\ATDR-backups\<backup>.sqlite3" `
  --target-database-url "sqlite:///./.tmp/restored-atdr.db" `
  --execute --confirm RESTORE_TO_NEW_EMPTY_TARGET --pretty
```

The restore refuses the configured database and any file that exists, so it
cannot overwrite what is there. When it says `restore_validated`: rename
`atdr.db` to `atdr.db.before-restore`, delete `atdr.db-wal` and `atdr.db-shm`
if they are there, move `.tmp\restored-atdr.db` to `atdr.db`, run
`.\.venv\Scripts\python.exe -m alembic upgrade head` (the backup may be older
than the newest migration), then `.\scripts\start_system.cmd`.

### By hand

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
| Startup says ATDR is being started by another process | The sign-in start or the watcher is starting it; wait a minute, then run `check_system.cmd`. |
| ATDR starts again after it was stopped | A sign-in ends a plain stop. Stop with `stop_system.cmd -HoldHours <n>` for work that needs it down. |
| The System panel says a part keeps stopping | Read that part's log in `.atdr_runtime\logs\` for the cause; the watcher goes on trying every five minutes. |
| The dashboard does not show a change to its source | It is built at the next start; to have it now, run `python -m atdr.scripts.build_dashboard` and reload the page. With a live copy, a change shows after `release.cmd go`. |
| Startup says this is the folder ATDR is developed in | ATDR runs from the live copy it names. Start it there, or release a new version with `release.cmd go`. |
| A change does not show in the running system | It is in the development folder only. Commit it and run `release.cmd go`; `release.cmd` says how many commits are waiting. |
| A release says the version did not go live | The version before was put back and runs. The message names the part or step; that part's log is in the live copy's `.atdr_runtime\logs\`. Fix it in the development folder, commit, release again. |
| Startup says a release into this folder did not finish | In the development folder run `release.cmd recover`. |
| The bell says ATDR's files were changed outside a release | `release.cmd` names the files. Put them back with `git -C C:\ATDR-live checkout -- .` and make the change in the development folder. |
| A release says the tests would not be testing the commit | Something in the development folder is not committed. Commit it or put it aside; notes under `docs\` do not count. |
| The System panel says the last backup failed | It names the cause (no free space, folder not usable, copy not healthy); the worker tries again an hour after each failure. |
| No Windows notification appears | Use Send a test on the System panel. In Windows Settings, System, Notifications: notifications on, "MFU ATDR" allowed, Do Not Disturb off. |
| The System panel says a channel failed | It says why. Email: check the account's name and app password, the server and the port. Chat: 404 means the webhook was deleted; make a new one. |
| Too many messages about alerts | Raise `ATDR_NOTIFY_ALERT_MINUTES_BETWEEN`; everything is still under the bell. |
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
