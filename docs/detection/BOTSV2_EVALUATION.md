# A second dataset: BOTSv2

Everything else in ATDR was built and tested on one MFU firewall export. On
15 October ATDR's rules were run, unchanged, on Palo Alto logs from a firewall
they had never seen: Splunk's *Boss of the SOC v2* (BOTSv2) lab, in which an
attacker group breaks into a fictional brewery called Frothly in August 2017.

## Data

- **Source.** The "attack only" BOTSv2 set (3.2 GB,
  `botsv2_data_set_attack_only.tgz`, MD5 `6ea8f15c…` as published at
  [github.com/splunk/botsv2](https://github.com/splunk/botsv2), public domain).
  It ships only as Splunk index files. The raw events are stored as plain
  text inside each `rawdata/journal.gz`, so they were read out without
  installing Splunk.
- **Palo Alto logs.** 414,962 TRAFFIC records and 2 THREAT records from
  3 to 29 August 2017. The firewall runs an older PAN-OS than MFU's. ATDR's
  parser read every line and correctly marked the layout as partial
  ("structural schema drift"), because the newer trailing fields are missing.
- **Session ends only.** BOTSv2's firewall writes a record when a session
  starts and another when it ends (222,202 and 192,758). MFU's firewall logs
  session ends only, so the main run imports 192,762 records: session ends,
  denies and threats. A second run imports the start records too (below).
- **Ground truth.** Splunk sends its official questions and answers only on
  request, so they were not used. The truth here comes from the lab's other
  sensors, recorded alongside the firewall: 1,629 Suricata IDS alerts and the
  firewall's own 2 THREAT records. Neither is complete: Suricata missed some
  of the attack, and one of its biggest alert groups is itself a false alarm.

The data stays on `D:\ATDR-datasets\botsv2` in its own databases. Nothing
was imported into ATDR's live database.

## What the lab sensors flagged

| What | Seen as | ATDR before | ATDR after |
|---|---|---|---|
| Four computers (10.0.2.107, 10.0.2.109, 10.0.1.100, 10.0.1.101) in constant HTTPS contact with the attacker's command server 45.77.65.211: 24,180 connections over two days, every 2 to 4 seconds | Suricata: invalid TLS handshakes from 45.77.65.211 | **missed** | **found**: one Medium alert naming all four |
| A user uploading files by FTP to 160.153.91.7, one named `topsecretyeast.pdf`, with an exploit-laden PDF blocked | Firewall THREAT records | found (High) | found (High), plus the two blocked uploads |
| The firewall itself (10.0.1.1) probing port 135 on inside computers, 1,547 Suricata alerts | Suricata: "Unusual Port 135 traffic, potential scan" | no alert | no alert |
| A few connections to Tor relays and to Java download servers | Suricata | no alert | no alert |

The port-135 probing is the firewall's own user-identification feature, not
an attack, so staying quiet there is correct. The Tor and Java contacts are
three or fewer connections each, below anything ATDR's rules count.

## What ATDR got wrong, and what changed

**725 "services open to the internet" from one FTP upload.** In active-mode
FTP the outside server opens each data connection from its port 20 to a high
port the user's computer names. ATDR listed every one of those ports as an
MFU service that answered the internet, and the same connections also made
two hours of "internet scanning". They belong to the user's own outgoing
session. ATDR now recognises them: FTP, from port 20, to a port of 1024 or
above. A real FTP server on port 21, a passive-mode data port or SSH sent
from port 20 still count. That removed 727 alerts. MFU's data has no such
connections.

**Every session counted twice.** With BOTSv2's start records imported, ATDR
counted each session twice. The start records also pulled down the bar for
"unusually large session", because a start record carries no bytes yet. Now
detection leaves out session starts from a firewall that also logs session
ends, and the size bar ignores them. A firewall that logs only session starts
keeps them. With the start records imported, the alerts are now exactly those
of the end records alone.

**The command server.** The beaconing rule looks at five-minute windows,
wants connections 5 to 300 seconds apart, and wants a second sign: an unusual
port, an unnamed application, a firewall THREAT, or a risk-5 application.
Plain HTTPS to port 443 every 2 to 4 seconds shows none of these. What gave
the server away was something else: it was the second-busiest outside address
in the data, while only four inside computers ever used it. A new check,
*constant contact with a rarely used outside address*
(`persistent_contact_service.py`), raises a Medium alert when:

- an inside computer makes at least 120 connections to one public outside
  address within an hour;
- those connections fall in at least six five-minute windows of that hour,
  so they last half an hour or more;
- no more than five inside computers used that address in the hour.

Name lookups (DNS), time (NTP) and pings are left out, because they are
steady by design.

## Results

| | Before | After the fixes | With one suppression (below) |
|---|---|---|---|
| Alerts on 192,762 BOTSv2 logs | 860 | 135 | 29 |
| Of them, about Frothly's own Splunk server | 109 | 109 | 3 |
| Command server found | no | yes | yes |
| FTP theft found | yes | yes | yes |
| MFU detection scoreboard (F1, all labels) | 98.0% | 98.0%, the same 80 alerts | (no suppression on MFU) |

Most of the remaining alerts concern 52.40.10.231, an Amazon address where
Frothly's computers send their logs to Splunk Cloud: 12.7 GB on port 9997,
labelled `splunk` by the firewall. That is legitimate, but it is exactly what
ATDR's rules call large outbound transfers and repeated contact. An analyst
would mark it once, but ATDR's suppression rules could match a source, an
application or an alert type, not a destination. The new check also flagged
it (1 of its 2 alerts), as its alert text warns it may for update and
monitoring agents.

A suppression can now name a destination address (Threat Controls,
Suppressions). It silences an alert only when all of the alert's traffic went
to that address, so a scan that touched the server once is still a scan. The
new constant-contact alert honours it too. With one rule for 52.40.10.231 the
135 alerts became 29, and the rule counted 2,623 suppressed hits. The 3 alerts
that still mention the server are scans whose other targets were elsewhere.
The command server, the FTP theft and the blocked uploads all remain.

## Limits

- **The new check has not been tried on MFU traffic.** MFU's export covers
  21 minutes, and ATDR's database holds 3 minutes 15 seconds of it. Half an
  hour of contact cannot occur in either. On BOTSv2 it raised 2 alerts: the
  command server, and the Splunk server. Its alerts are Medium for that
  reason, and the alert says so.
- **The attack-only set is a cut.** It keeps the hours around the attack,
  about eight hours of the command-server contact, not the whole month.
  Normal traffic outside those hours, where most false alarms would come
  from, is not in it.
- **The ground truth is partial.** Without the official answers, an attack
  step that neither Suricata nor the firewall flagged cannot be counted as
  missed.

## Running it again

The scripts are in `.tmp/claude-tools/botsv2/`:

1. `extract_pan.py <journals> <out>` reads the Palo Alto events and Suricata
   alerts out of the journals.
2. Import `pan_session_end.log` into a fresh database with
   `python -m atdr.scripts.import_logs <file> --limit 2000000`, with
   `DATABASE_URL` pointing at that database.
3. `evaluate.py --detect <suricata_alerts.jsonl> <report.json>` runs
   detection and compares the results with the lab's sensors.
