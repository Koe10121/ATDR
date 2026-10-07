# Rebuilding alerts after the rules change

ATDR keeps an alert until someone closes it. When the rule catalog changes,
alerts raised by retired or narrowed rules stay on the list, so the dashboard
shows what ATDR used to detect rather than what it detects now. A rebuild
brings the list up to date without losing history.

## What a rebuild does

1. **Keeps every alert an analyst has worked on**, exactly as it is: status
   changed from open, assigned, escalated, ticketed, noted, or with a response
   action.
2. **Archives every other alert** in the `alert_archive` table: all its
   columns, its evidence log ids, the reason, the catalog that replaced it,
   who did it and when. Archived alerts leave the alert list, counts and
   exports; the archive is never deleted.
3. **Re-runs the current rules and watchlist over every log**, the same way
   the "check every unchecked log" action does. Logs cited by a kept alert stay
   out of new alerts.
4. Writes an `alerts_rebuilt` entry to the audit log with the counts.

## How to run it

```
scripts\stop_system.cmd
python -m atdr.scripts.backup_database --output-dir backups --execute
python -m alembic upgrade head
python -m atdr.scripts.rebuild_alerts                        # dry run: what would change
python -m atdr.scripts.rebuild_alerts --apply --actor <name>  # backs up again, then rebuilds
scripts\start_system.cmd
```

To undo, stop ATDR and restore the backup taken before the rebuild.

## 2026-09-27 rebuild (rule catalog v5.34.0)

The live database held 3,676 alerts collected since May, mostly from rules
that v5.32.0 made supporting-only (app risk 4: 1,806; suspicious app
characteristic: 567) and from the old anomaly model, which may no longer raise
alerts (548). Rehearsed first on a copy, then applied (backup
`backups/atdr-sqlite-20260927T133400Z-7f69246e.sqlite3`).

- Kept 5 alerts with analyst work; archived 3,671.
- The current rules and watchlist raised 309 alerts over the 151,242 logs,
  including one Critical watchlist alert for the device beaconing to a known
  GHOSTENGINE C2 address (18 connections), traffic the old list had filed
  under "app risk 4".

Against the team's 2,132 reviewed labels:

| Alert list | Alerts | Precision | Recall | False-alarm rate | F1 |
|---|---|---|---|---|---|
| Before (accumulated since May) | 3,676 | 48.9% | 87.6% | 43.3% | 62.8% |
| After the rebuild | 314 | 93.9% | 80.4% | 2.5% | 86.6% |

Most of the recall difference is BitTorrent that the team labeled as threats
and that ATDR now treats as policy activity (catalog v5.34.0; see
`../DETECTION_RULE_CATALOG.md`). These labels are the team's own, made while
the rules were tuned, so they measure agreement; the blind check
(`BLIND_CHECK.md`) is the fair accuracy estimate.

## 2026-09-28 rebuild (rule catalog v5.35.0)

After the rules began summarising internet background probing, the list was
rebuilt again (backup `backups/atdr-sqlite-20260928T042514Z-0313c07d.sqlite3`):
the same 5 worked alerts kept, the 309 v5.34.0 alerts archived, 244 raised by
the current rules, 249 in all (Critical 39, High 43, Medium 150, Low 17),
still including the Critical GHOSTENGINE watchlist alert. That run's audit
entry reports 0 new alerts: the count compared ids with the old maximum, and
SQLite reuses ids after a deletion. The count is fixed; the audit entry is
left as written.

## 2026-09-28 rebuild (rule catalog v5.36.0)

Applied after alerts began taking their attack type from the evidence and
informational firewall records that name no attack became supporting evidence.
Migration `d9e3f4a5b6c7` first (backup
`backups/atdr-sqlite-20260928T055316Z-314be493.sqlite3`), then the rebuild
(backup `...055331Z-c9ca4af1`): the same 5 worked alerts kept, 244 archived,
175 raised, 180 in all (Critical 40, High 44, Medium 79, Low 17). Each of the 8
campus devices the firewall names as an XMRig miner now has its own Critical
"Palo Alto malware or C2 threat" alert; the GHOSTENGINE watchlist alert stays.
Unclassified alerts: 133 before the attack-type work, 18 now.

## 2026-09-29 synthetic test data removed

A readiness check found three Critical alerts from 203.0.113.x, a documentation
address range, on the live list. On 27 Sep, `run_no_hardware_soak` had been run
with its defaults, which then wrote its synthetic lab logs into the configured
database: 46 logs from sources `soak-firewall-1`, `soak-router-1` and
`soak-workstation-source`. The 28 Sep rebuild turned them into 4 alerts
(#3848-#3851: 3 Critical, 1 High). They had no notes, labels, assignments or
responses; the model's training set, the blind and holdout sets and the labels
never contained these logs.

After a backup (`backups/atdr-sqlite-20260929T042429Z-7620c8dd.sqlite3`), the 4
alerts were archived in full, and the 46 logs, their 9 import runs and the 3
sources removed. The audit trail keeps the original import records and a
`synthetic_test_data_removed` entry. The live list went from 185 to 181 alerts
(Critical 37, High 43, Medium 81, Low 20). The soak tool now uses a temporary
database unless given `--use-configured-db`.

## 2026-09-30 demo and lab data removed

Looking for more of the same, a second check found three Critical alerts whose
evidence was demo or lab data with documentation-range addresses: #3224 and
#3225 (port scans from 203.0.113.44, built on the June demo sources
`final-demo-firewall`, `final-demo-firewall-live` and `lab-firewall-sim-1`) and
#3676 (brute force from 198.51.100.23, five of its six logs from a
`lab-fw.example.invalid` test import on 23 Sep). They had survived the 28 Sep
rebuild because they were assigned or marked investigating.

After a backup (`backups/atdr-sqlite-20260930T104122Z-7be51505.sqlite3`), the 3
alerts were archived in full, and the 240 synthetic logs, their 10 import
records, the 3 demo sources, 7 empty lab source registrations from May and 5
July shadow observations recorded on the demo sources were removed; the audit
entries (`synthetic_test_data_removed`) keep the details. Five finished import
jobs were unlinked from the deleted import records. The one log that carries
the MFU firewall's own name stays. The live list went from 181 to 178 alerts
(Critical 34, High 43, Medium 81, Low 20), and every stored log (151,002) is now
MFU firewall traffic from 20 May 13:36-13:39.

## 2026-10-04 duplicate log copies removed

The 151,002 stored logs held 120,001 distinct firewall lines. Until 27
September an import stored a line again each time the same file was imported,
and the first 10,000 lines of the export (13:36:15-13:36:32) had been stored
two to eight times, on 27 May, 23 September and 26 September, so 31,001 rows
were copies. Imports have stored each line once since then (`raw_line_hash`),
but the old copies stayed.

Rules that count events counted the copies. The three Critical brute-force
alerts (#3684, #3709, #3739) were each one denied connection to port 22 stored
six or seven times, which passed the rule's threshold of five attempts; #3738
listed 18 events for 13 connections; and 87 of the 178 alerts cited at least
one copy.

With ATDR stopped and after two backups
(`backups/atdr-sqlite-20261004T070619Z-42dcc25d.sqlite3` before the migration
below, `backups/atdr-sqlite-20261004T070634Z-bb62b28f.sqlite3` before the
clean-up), `python -m atdr.scripts.remove_duplicate_logs --apply` kept the first
stored copy of each line and removed the others
(`atdr/app/services/duplicate_log_service.py`):

- 604 of the 2,016 labels sat on removed copies. Where such a label was the
  newest made for its line it moved to the kept copy (390); the other 214 went
  to `ml_label_archive`. The copies of 12 lines disagreed, each time `benign`
  against `benign_unusual`; no line was a threat on one copy and harmless on
  another.
- The 1,709 evidence rows that cited a copy, the evidence ids of 1,379 archived
  alerts and 1,157 archived labels now point at the kept copy.
- The alert list was rebuilt: 176 alerts archived, 2 kept because a response is
  recorded on them (#2049, #2637), 157 raised by the rules and the watchlist, and
  6 by the MFU behaviour model.

The live list went from 178 to 165 alerts (Critical 30, High 39, Medium 84,
Low 12) on 120,001 logs. By rule, against the list before: no brute-force
alerts (3 before), 3 flood alerts (4), 11 for unidentified applications (19),
30 for unusual destination ports (32), 6 for repeated denied connections (7), 1
for a single denied connection (0), and 6 experimental alerts from the model
(5). The other rules raised the same number of alerts as before. The alerts the
reports and slides name have new numbers: #3738 (the GHOSTENGINE server) is
#4033 with 13 events, #3773 is #4067, #3839 is #4134, #3853 is #4145, and the
model's alerts are #4143 to #4148. The audit entries `duplicate_logs_removed`
and `alerts_rebuilt` keep the details.

## Alert numbers after a rebuild

An alert's number is never given to another alert. Until 4 October 2026 SQLite
numbered a new alert one above the highest remaining id, so a rebuild's new
alerts took the numbers of the alerts it had archived, and a number quoted
before a rebuild could name a different alert afterwards. Migration
`a8f1c0d2e3b4` made SQLite remember the highest number it has given
(AUTOINCREMENT) and started it at the highest number ever used, #3985 in the
archive, so the 4 October rebuild numbered its alerts from #3986. PostgreSQL's
sequence already worked this way.

From the earlier rebuilds the archive can hold the same original number more
than once (one row per rebuild that archived it; tell them apart by
`archived_at` and `superseded_by_catalog`). Until migration `d9e3f4a5b6c7` it
could not, and a third rebuild failed on it and rolled back without changing
anything.
