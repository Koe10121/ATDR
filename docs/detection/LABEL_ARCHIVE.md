# Labels that described other logs

## What happened

The team's first labels were made on 23-25 May. On 27 May the logs were wiped and
imported again, and the new import gave the old log ids to other firewall records.
The labels kept their log ids, so 1,231 of them (794 counted as reviewed) sat on
logs they were not made for. Found on 28 Sep, when a review of the team pack
noticed label notes that did not match their logs.

The notes show it. Where a note names something the log records:

| Note mentions | Labels made before the re-import that contradict their log | Labels made after |
|---|---|---|
| ICMP or ping | 91 of 93 (98%) | 1 of 89 (1%) |
| Denied or dropped traffic | 120 of 122 (98%) | 2 of 48 (4%) |
| UDP | 24 of 33 (73%) | 0 of 280 |
| Inbound (external to internal) | 20 of 39 (51%) | 0 of 171 |
| BitTorrent or peer-to-peer | 19 of 29 (66%) | 0 of 88 |
| An app by name (`app=...`) | 226 of 229 | none name one |
| An IP address | 131 of 131 | none name one |

No backup from before 27 May exists, so the labels cannot be moved back to their
own logs.

## What was done

A label made before its log was imported cannot be about that log. All 1,231
moved to the `ml_label_archive` table on 28 Sep (migration `7c2e91f4b0a3`), each
kept in full with its original id, the log id it pointed at, when it was made and
the reason, and an `ml_labels_archived` audit entry. They are out of every count,
the behaviour model's data and the log pages. Backups: before the migration
`backups/atdr-sqlite-20260928T103606Z-459f1fb3.sqlite3`, before the archive
`backups/atdr-sqlite-20260928T103610Z-de4a7033.sqlite3`. 1,755 labels remain;
none predates its log.

```
python -m atdr.scripts.archive_misattached_labels                     # dry run
python -m atdr.scripts.archive_misattached_labels --apply --actor NAME  # backs up, then archives
```

The same day the detection scoreboard began counting each firewall record once:
re-imports before duplicates were skipped had stored 31,129 extra copies of
10,112 lines (20% of the stored logs), and some copies carried their own label.
A record now counts once, with its latest label, and is alerted if any copy is.

## What changed in the numbers

Team labels against rule catalog v5.36.0 (agreement, not accuracy):

| Labels | Labeled | Precision | Recall | False alarms | F1 |
|---|---|---|---|---|---|
| Before: every reviewed label, per stored log | 2,132 | 95.6% | 72.4% | 1.6% | 82.4% |
| After: archived labels out, each record once | 1,489 | 97.0% | 79.3% | 1.5% | 87.3% |
| After, held-out test split only | 405 | 95.4% | 84.5% | 1.8% | 89.7% |

The blind check does not use these labels and is unchanged.

The MFU behaviour model v1 and v2 took labels by line fingerprint, so their
training saw some archived labels: 394 "normal", 21 port scan, 5 data
exfiltration and 2 brute force. The model trains mostly on simulated attacks and
unlabeled normal traffic, so the effect is small, but its one real exfiltration
example came from a wrong label. The next model version trains on the cleaned
labels; v2 stays as frozen for its pending review.
