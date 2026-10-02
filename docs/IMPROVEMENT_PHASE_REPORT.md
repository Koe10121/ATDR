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
  fell from 53% to 10%. Each type has its MITRE technique and a response
  playbook.
- **Every alert in plain words** (1 October). The alert drawer opens with a few
  sentences written from all of the alert's evidence logs, not by the language
  model: when it happened, which device contacted what, what the firewall
  recognised and whether it blocked it, what that may mean, and the first
  question to answer. For #3773: "On 20 May, 13:36–13:39, an MFU device
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
  #3738, the GHOSTENGINE server.
- **A dashboard that reads like a product** (2 October). Presentation, lab and
  research wording left the pages: data caveats, documentation paths, the
  release checklist, "lab" and "demo" labels, and the Overview's validation
  panel. The evidence and its limits are in the slides and in this report.
  Every page and feature still works, and the assistant is unchanged.
- **Threat intelligence.** 2,324 known-bad addresses from Feodo Tracker and
  ThreatFox are on the watchlist.
- **Rebuilt the alert list** with the current rules, keeping analyst-worked
  alerts and archiving the rest in full: 3,676 alerts became 178.

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
  confidence". It never triggers a response on its own. Five are on the live
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
  laptop's graphics card. The latest run answered 102 of 102 and 27 of 27.

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
| Team labels, current rules | precision 96.0%, recall 99.7% | Agreement, not accuracy |
| Assistant | 102 of 102 (14 reviewer questions added), and 27 of 27 held-out questions, in under 5 seconds per answer (2 Oct; 84 of 85 and 26 of 27 on 30 Sep; runs vary by a question or two) | Automatic scoring |
| Tests | 1,560 backend and 81 browser tests passing | |

The live dashboard holds 178 alerts (Critical 34, High 43, Medium 81, Low 20).
Each names its attack type: port scan 119, malware / C2 14, policy violation 10,
data exfiltration 7, flood 4, brute force 3, exploit attempt 3, unclassified 18.
Five are the MFU model's experimental alerts.

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
