# ATDR after the presentation: what we did and where we are

26 to 29 September 2026. The numbers and their caveats are in
`EVIDENCE_SUMMARY.md`; this page tells the story.

**All accuracy figures come from one 21-minute MFU export (20 May 2026); treat
them as low-confidence estimates until tested on more traffic.**

## Where we started

At the presentation on 26 September the professor asked for three things:

1. When MFU is attacked, the system should know it, say what is happening and
   how to fix it, on the dashboard, with a model trained on MFU traffic only.
2. An assistant that talks like a chat assistant, not a fixed menu.
3. A higher level of quality overall.

That day ATDR held 3,676 alerts collected since May. Against the team's labels
fewer than half were right (precision 48.9%, false alarms 43.3%). Most came from
rules that fire on context, such as an app's vendor risk rating, rather than on
behaviour. The ML models only scored logs, and neither had shown it could find
attacks. The assistant answered from a fixed list of question types.

## What we did

### 1. Detection that knows what is happening

- **Measured before changing.** A scoreboard runs the current rules over a copy
  of the database and scores them against the labels. A blind check scores them
  against 150 logs labeled without seeing ATDR's verdicts, drawn from traffic
  the rules were never tuned on.
- **Cut the noise.** Rules that describe context (risky app, busy source,
  inbound direction, large transfer) now add points but never raise an alert
  alone. Campus apps' busy two-way traffic is no longer called a flood.
  BitTorrent is policy activity, not an attack. Single internet probes are
  summarised, not alerted. Informational firewall records that name no attack
  ("Non-RFC Compliant SSL Traffic") support other evidence only.
- **Fixed how detection runs.** Results no longer depend on batch size; every
  log is checked once; a whole firewall export imports safely, and overlapping
  exports store each record once.
- **Every alert names the attack.** Attack types now come from the evidence as
  well as the rule: the firewall's threat signature, the kind of watchlist
  indicator, whether a probe was answered. A new type, exploit attempt (MITRE
  T1190), covers Shellshock and path-traversal attacks. Unclassified alerts
  fell from 53% to 10%, and to 6% once duplicate log copies were removed on 4 October (the same 10
  alerts are 12% of the shorter list of 9 October). Each type has its MITRE technique and a response
  playbook.
- **Every alert in plain words** (1 October). The alert drawer opens with a few
  sentences written from all of the alert's evidence logs, not by the language
  model: when it happened, which device contacted what, what the firewall
  recognised and whether it blocked it, what that may mean, and the first
  question to answer. For #4179: "On 20 May, 13:36–13:39, an MFU device
  ([address]) made 7 connections to 4 outside servers on port 14444. The
  firewall recognised it as 'XMRig Miner Command and Control Traffic Detection'
  and blocked all 7." The assistant reads the same sentences when it explains
  an alert.
- **The Overview in plain words** (1 October). The Overview opens with "What's
  happening, in plain words", also written by ATDR from the open alerts and
  their logs: how many are open and from which traffic (20 May, so not live),
  one line per kind of attack, most dangerous first, with the threats the
  firewall or the watchlist named and whether the firewall blocked them, and
  the alert to open first: a named threat the firewall let through, which is
  #4163, the GHOSTENGINE server.
- **A dashboard that reads like a product** (2 October). Presentation, lab and
  research wording left the pages: data caveats, documentation paths, the
  release checklist, "lab" and "demo" labels, and the Overview's validation
  panel. The evidence and its limits are in the slides and in this report.
  Every page and feature still works, and the assistant is unchanged.
- **Threat intelligence.** 2,324 known-bad addresses from Feodo Tracker and
  ThreatFox are on the watchlist.
- **Rebuilt the alert list** with the current rules, keeping analyst-worked
  alerts and archiving the rest in full: 3,676 alerts became 178.
- **Removed duplicate log copies** (4 October). Importing the same file again used to store
  its lines again, so the first 10,000 lines of the export were stored up to eight times:
  31,001 of the 151,002 stored logs were copies. They were removed, each line keeping its
  newest label, and the list rebuilt on the 120,001 logs that remain: 165 alerts. Three
  Critical brute-force alerts had each been one denied connection stored six or seven
  times; they are gone. An alert's number is now never given to another alert.
- **Detection that runs by itself** (7 October). Detection used to run only when someone
  clicked the button. The background worker can now check new logs without that: a
  five-minute window at a time, once the window after it is complete, or two minutes after
  logs stop arriving. Waiting matters: checked as soon as its own window closed, the first
  half of a port scan across a window edge was raised as "multiple denied connections"
  instead of a port scan. The Data & Detection page says whether automatic checks are on
  and what the last one did, and ATDR can start when its Windows user signs in
  (`docs/OPERATIONS_RUNBOOK.md`).
- **Taking the firewall's full log rate** (8 October). Sent the first 8 min 44 s of the
  MFU export at its recorded rhythm (a median of 568 lines a second, up to 1,014), the
  syslog receiver saved 80% of the lines, and when the first automatic check began it
  ended with "database is locked": a detection run held SQLite's only write lock for the
  44 seconds it spent judging a window. The receiver now takes lines off the network in
  one thread and saves them in batches in another, waits out a busy database, and counts
  any line it has no room for. A detection run takes the lock only to write its alerts.
  Measured again: all 638,252 lines saved with two automatic checks running meanwhile, and
  all 120,001 at four times MFU's rate. The receiver starts with ATDR when switched on,
  and Data & Detection shows what it has received, saved and lost (runbook, Live Syslog).
- **Keeping the live feed within the disk** (8 October). At MFU's rate a stored log cost
  6.2 KB, 13 GB an hour, on a laptop with 160 GB free. Each row held the line's fields a
  second time, which also made it too big to share a database page (42% of the table was
  empty). Without that copy a log takes 3.5 KB, 7.6 GB an hour, and the receiver saves
  about 2,000 lines a second. Logs from the live feed are now kept six hours, summarised
  by hour for each source address, then deleted; an imported file, a log detection has not
  checked, alert evidence and a labelled log never are. The receiver stops saving before
  the disk fills, and says so. Three reads of every stored log in automatic detection and
  in each detection batch were bounded; rebuilding every alert on a copy of the live data
  gave the same 165 alerts. Rehearsed with the feed running (two-minute steps and a
  three-minute limit standing in for hours): all 638,252 lines saved, 370,590 deleted once
  checked, every line counted in a summary, all 46,533 evidence logs kept, and a
  five-minute window of MFU's traffic checked in about a minute.
- **Fewer alerts for the same findings** (8 October, rule catalog v5.37.0). At MFU's rate the
  rules raised about 1,900 alerts an hour: every scanner was alerted on again for each
  five-minute window and each port, and 4 alerts in 10 were scanning from the internet.
  Now activity of the same kind from the same source joins the alert still open for it,
  for a day, and internet scanning that does nothing else goes on one alert an hour that
  lists the scanners. The same logs are flagged: on the team's labels 382 right, 13 false
  and 3 missed before and after, while the 120,001 imported logs give 78 alerts instead of
  158. At MFU's rate the replay raised 214 alerts instead of 556: the traffic sent a second
  time raised 16 instead of 186, one alert listed 316 scanners, and 17,613 logs were kept as
  evidence instead of 46,533. The behaviour model counts a scanner on that hourly alert as
  covered, so it no longer raises its own alert for it. On 9 October the live list was
  rebuilt this way: its 165 alerts became 85 with the same 7,773 logs flagged, and 76 alerts
  for scanning from the internet became one that lists 130 addresses
  (`detection/ALERT_REBUILD.md`).
- **A large alert opens as fast as a small one** (9 October). Rehearsing that rebuild on a
  copy put an hour of internet scanning on one alert with 5,547 evidence logs. Opening it
  asked for its timeline and its whole report, which loaded every evidence log (4.7 s) and
  worked out a behaviour window for each (141 s, 7.6 MB); a status change, a note, an
  assignment or an escalation loaded them all again (4 to 8 s each). Those actions no
  longer read the evidence. The report fetches it in one query and works out behaviour
  windows for its first 25 logs, and the drawer asks for a preview of 25 and says how many
  there are; the CSV and HTML downloads still list every log. On the live list the same
  alert's timeline takes 0.02 s and its report preview about a second, an action 0.02 s
  or less, and the CSV of all 5,547 logs 0.3 s.
- **A system that looks after itself** (9 October). The database had been backed up by
  hand, eleven times in a month, into the folder it is in; a part that stopped stayed
  stopped until someone noticed; "Reset to sample data" deleted every log, alert and audit
  entry after one click, with no copy kept; and the dashboard ran from its development
  server. Now the background worker backs the database up every day, checks each copy,
  thins old ones out by age and copies the newest to a USB drive whenever one with an
  `ATDR-backups` folder is connected. A reset asks for the word RESET and takes a backup
  first. A watcher looks at every part each 30 seconds and brings back one that has stopped
  or no longer answers, without undoing a deliberate stop. The dashboard is served from
  its built files, and Data & Detection has a System panel that shows all of this.
  Measured by ending processes of the running system: a part was back 9 to 45 seconds
  after it was ended, a frozen one in under four minutes, and after a shutdown and
  power-on ATDR and its watcher were running again with nothing done by hand. The 638 MB
  database is copied and checked in 3 seconds, and a restore from that backup gave back
  every log and alert (`docs/OPERATIONS_RUNBOOK.md`, Keeping ATDR Running).
- **Telling people** (10 October). A Critical alert, a failed backup or a part that kept
  stopping was on a page that had to be open, and ATDR's mail settings were a placeholder
  that never sent anything. Now the worker looks every 30 seconds. A new Critical alert is
  reported within about two minutes; a burst is one message, and while alerts keep coming
  the next follows no sooner than 30 minutes later (at MFU's rate the replay raised 45
  Critical alerts in under nine minutes). One summary a day covers the rest. A problem of
  ATDR's own is reported once it has lasted and again when it is over, and the watcher
  reports a part that keeps stopping by itself, so a worker that stopped is still reported.
  Every notification is under a bell in the dashboard; the same words, which never hold an
  IP address, go out as a Windows notification, by email and to a chat group once those
  are set up, each with a Send-a-test button. A channel that fails is tried again for a day
  and does not hold up the others. Email was tested against a mail server and chat against
  a web server that run inside the tests. On the running system the test message from the System panel arrived in Windows, and when the worker was ended four times in two minutes the watcher told people 30 seconds after the fourth, started it again five minutes later, and told them it was running again once it had stayed up ten minutes.
  (`docs/OPERATIONS_RUNBOOK.md`, Notifications).

### 2. A model trained on MFU traffic

- **The MFU behaviour model** reads each device's five minutes of traffic,
  names the likely attack (port scan, brute force, flood, malware / C2, data
  exfiltration), says why in plain words, and shows how to respond. It was
  trained only on MFU's own traffic plus simulated attacks blended into it,
  and it shows on the Overview and on every alert.
- **A quality bar, declared before training,** decides whether a type may
  raise its own alerts: its extra finds must prove real in a blind review, it
  must find 90% of fresh simulated attacks, and rules plus model must not be
  less accurate than rules alone.
- **Version 2** fixed what the first version's review found. No type fully
  passed. Port scan came closest (4 of 4 judged extra finds real, one left
  Unsure, 5 needed); C2's extra finds were routine check-ins.
- **Experimental alerts.** Because no more MFU data exists to test on, the
  team lead switched every type on as a recorded exception on 28 September:
  where the model flags a device and no rule alert covers it, ATDR raises an
  alert marked "Found by the MFU behaviour model: experimental, low
  confidence". It never triggers a response on its own. Six are on the live
  list.
- **A real find.** The first model flagged a campus device calling a server
  every 14 seconds; Elastic Security Labs lists that address as GHOSTENGINE
  malware command-and-control. No rule had alerted. It is now a Critical
  watchlist alert. The firewall also named 8 campus devices as XMRig
  cryptocurrency miners; ATDR now alerts on them as malware, not as scans.

### 3. A conversational assistant

- The SOC Assistant is now a language model running on the laptop (qwen3:8b)
  that answers in conversation. It looks facts up through read-only tools, and
  every number and address it states is checked against what the tools
  returned. It cannot take actions.
- On a set of 85 realistic analyst questions it answered 83 well; on 27
  questions written after tuning, 26. The older menu-style assistant answered
  about half.
- Since 1 October an answer takes under 5 seconds instead of 10: the model's
  working memory was cut to 8,192 tokens so the whole model fits on the
  laptop's graphics card. The latest run (7 October) answered 122 of 122 and 26 of 27.
- Asked to summarize the security situation, it relays a summary ATDR writes itself, in the
  Overview's plain words: what is open, what is new in the period asked about, each kind of
  attack with what the firewall did, and the alert to open first.

### 4. Honest evidence

- **The team review pack** put every check that needs a person in one
  anonymized workbook: the model's extra finds, the blind-check labels, and
  groups of team labels that contradicted the firewall or the team's policies.
  It came back with answers drafted by AI and checked row by row by a person,
  and is recorded that way. A follow-up gave more detail on the rows left
  Unsure.
- **Found and fixed a data problem.** 1,231 early labels had been attached to
  the wrong logs when the database was re-imported in May. They are archived,
  not deleted, and the scoreboard now counts each firewall record once.
- **One evidence summary** lists every number with what kind it is (blind,
  second look, agreement, simulated) and how far to trust it.
- **An outside code review** (30 September) found five issues. Four were fixed
  the same day: the assistant's checks trusted numbers from the question and
  sent unredacted text to a hosted engine; the experimental model alerts were
  worded and reported inconsistently ("99.5% confident" for what is 1 minus
  the probability of normal traffic); an unblock could mark a real firewall
  block removed after a mode switch; and one query worked only on SQLite. The
  fifth was fixed on 1 October: the live syslog receiver kept records unsaved
  until a batch of 100 filled, and meanwhile held the database's only write
  lock. It now saves within 2 seconds of a record arriving.
- **Test and lab data out of the live system.** Checks on 29 and 30 September
  found 7 alerts built on synthetic test, demo and lab logs rather than MFU
  traffic. They are archived and those logs removed, so every stored log is
  MFU firewall traffic.

## Where we are now (1 October)

| | Result | Kind |
|---|---|---|
| Blind check, rules on presentation day (official) | precision 50.9%, recall 81.8%, F1 62.7% | Blind |
| Same, labels human-checked | precision 56.4%, recall 83.6%, F1 67.3% | Blind |
| Blind check, current rules, labels human-checked | precision 93.5%, recall 78.2%, F1 85.2% | Second look; partly because 5 flagged rows became Unsure |
| Rules plus MFU model, same labels | F1 90.1% | Second look |
| MFU model on fresh simulated attacks | port scan 96.5%, brute force 97.5%, flood 100%, C2 88.5%, exfiltration 98.0% | Simulated |
| Team labels, current rules | precision 96.7%, recall 99.2% | Agreement, not accuracy |
| Assistant | 122 of 122 (31 reviewer questions and the demo's conversation added), and 26 of 27 held-out questions, in about 5 seconds per answer (7 Oct on the cleaned data, and again on 9 Oct on the regrouped list; 84 of 85 and 26 of 27 on 30 Sep; runs vary by a question or two) | Automatic scoring |
| Tests | 1,791 backend and 91 browser tests passing (10 Oct) | |

The live dashboard holds 85 alerts (Critical 23, High 11, Medium 39, Low 12) on
120,001 logs, since the list was regrouped on 9 October (165 before, with the same
logs flagged). Each names its attack type: port scan 39, malware / C2 14, policy
violation 9, data exfiltration 7, flood 3, exploit attempt 3, unclassified 10.
Six are the MFU model's experimental alerts, and one lists the hour's 130 internet
scanners.

On 29 September a check of the live list found 4 alerts (3 Critical, 1 High)
built on 46 synthetic lab logs that a test tool had written into the live
database on 27 September. They were archived and the logs removed; the tool now
uses a temporary database by default. The model, the labels and the blind check
never contained them. On 30 September three more Critical alerts, built on demo
and lab logs imported in June and on 23 September, were archived with those 240
logs, so every stored log is now MFU firewall traffic.

## What the numbers cannot tell us

- **One export.** Everything was built, tuned and tested on 21 minutes of one
  day from one firewall. No part of it is left untouched, so there is no fair
  test left. This is the main limit on every figure above.
- **Labels.** The blind labels came from an AI reviewer and were checked by a
  person; the team's own labels were AI-assisted. Neither is independent
  ground truth.
- **Attack types.** The real attacks in the data are mostly scans and probing,
  firewall threat and malware records, and one C2 beacon. Brute force, flood
  and exfiltration were only tested on simulated attacks.
- **The model's alerts are experimental.** None of its attack types passed the
  bar it was given; its C2 alerts in particular are expected to include false
  alarms.

## What would raise confidence

Another MFU firewall export, even one hour from another day, would allow one
clean end-to-end test of the rules, the model and the assistant. Until then the
system works end to end, and the figures are the best estimates the data allows.
