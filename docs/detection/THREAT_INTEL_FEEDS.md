# Threat intelligence feeds on the watchlist

## Why

ATDR's rules judge behaviour. Some attacks look like ordinary traffic and are
known only because someone has seen the server before. In the MFU log, a
campus device called 111.90.158[.]40, a GHOSTENGINE C2 server listed by
Elastic Security Labs, every 14 seconds over plain HTTP. A behaviour rule for
"steady beacon to a destination only one device uses" would also fire on
30-35 harmless monitors and keep-alives every ten minutes
(`ML_MODEL_CARD.md`, Known limits). A list of known-bad addresses catches it
without that noise.

## How it works

- A feed file is downloaded first; ATDR itself never reaches the internet.
- Each address becomes a destination-IP watchlist item tagged with the feed's
  name. An MFU host contacting one raises a `watchlist_match` alert
  (Critical when the feed is confident: Feodo "online" entries and ThreatFox
  confidence 75 or more add 60 points, the rest 40).
- Re-importing a newer file of the same feed replaces that feed's list:
  new addresses are added, addresses no longer listed are disabled (feeds
  retire servers that were cleaned up or reassigned), returning ones are
  switched back on. Hand-added watchlist items are never touched.
- Private and reserved addresses are skipped, so a feed can never put MFU's
  own hosts on the list.
- Matching uses a lookup table: a full re-check of 151,242 logs with 2,325
  watchlist entries takes about as long as with none (49 s).
- The Threat Controls page shows each feed as one row (addresses, last
  import, matches) instead of one card per address.

Supported files: abuse.ch Feodo Tracker `ipblocklist.csv`, abuse.ch ThreatFox
CSV exports of `ip:port` indicators, and plain lists (one IP per line, `#`
comments).

## Refreshing

```
curl -o threatfox.csv https://threatfox.abuse.ch/export/csv/ip-port/recent/
python -m atdr.scripts.import_threat_intel --file threatfox.csv --source "ThreatFox recent"                    # dry run
python -m atdr.scripts.import_threat_intel --file threatfox.csv --source "ThreatFox recent" --apply --actor <name>
```

ThreatFox's "recent" export covers the last 48 hours, so refresh it daily.
The report also says how many stored logs already contacted the listed
addresses. New indicators apply to logs checked from then on; to re-check
history, run `rebuild_alerts` (`ALERT_REBUILD.md`).

## Limits

- Addresses change hands: a listed server may later belong to someone else.
  That is why feeds are refreshed and stale entries disabled, and why an
  alert says which feed listed the address and when.
- Firewall traffic logs carry IP addresses, not domain names, so domain and
  URL indicators are left out.

## Imported 2026-09-27

| Feed | Addresses | Stored logs already contacting them |
|---|---|---|
| Feodo Tracker (file dated 2026-03-04) | 5 | 0 |
| ThreatFox recent (2026-09-27, 3,191 entries, 2 private skipped) | 2,319 | 0 |

No stored log matches, as expected: the feeds list servers active in
September 2026 and the MFU log is from 20 May 2026.
