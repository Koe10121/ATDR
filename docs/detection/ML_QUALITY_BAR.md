# Quality bar for the MFU behaviour model

Declared on 2026-09-27, before the model was trained or tested. The model may
raise alerts on its own only for attack types that pass this bar. Every other
type stays advisory: the dashboard shows the model's opinion next to the
rules' alerts, but the model creates no alert for it.

## What the model is

A supervised classifier, trained only on MFU traffic, that looks at what one
source did in a 5-minute window (the same unit the rules use) and names the
attack type: port scan (including horizontal scans), brute force, flood or
denial of service, malware/C2 beaconing, possible data exfiltration, or normal.

It is trained on 20 May 13:36-13:45 only: the team's reviewed labels, real
traffic, and simulated attacks blended into real traffic. The 13:45-13:57 part
of the file is not used for training or tuning in any way.

## The bar

An attack type T passes only if all three hold on the untouched test window,
20 May 13:50-13:55:

1. **Real-world precision of the extra alerts.** Take the windows the model
   labels T that the rules did not alert on ("model-only alerts"). Up to 20 of
   them, chosen at random with a fixed seed, are labeled blind by the team,
   mixed with an equal number of random unflagged windows so the reviewers
   cannot tell which is which. At least 90% of the reviewed model-only alerts
   must be real threats ("Unsure" left out). If the model makes no model-only
   alerts of type T, this condition cannot be shown and T does not pass.
2. **Recall on simulated attacks.** Simulated attacks of type T, generated with
   a seed and intensities never used in training, are blended into the real
   test window. The model must find at least 90% of them.
3. **No harm to the whole system.** On the blind-check labels
   (`BLIND_CHECK.md`), the F1 of "rules or model" must not be lower than the F1
   of the rules alone.

## Rules for the test window

- The model is frozen (trained, threshold chosen) before it sees the test
  window. The threshold is chosen on training data only.
- If a type fails and the model is changed, any later result on the same
  window is reported as a second look at data already seen, not as a clean
  test.
- All results are reported, including the types that fail.

## Addendum: v1 result and the plan for v2 (declared 2026-09-27, before v2 was built)

**v1 on condition 1** (22-row blind review of the 13:50-13:55 window):

| Attack type | Model-only windows judged Threat | Condition 1 |
|---|---|---|
| Port scan | 1 of 1 | passes |
| C2 beaconing | 1 of 7 | fails |
| Data exfiltration | 0 of 3 | fails |
| Brute force, flood | no model-only windows | cannot be shown |

Port scan passes all three conditions as written, but on one window, and one
window cannot show 90% precision. It stays advisory. Passing the bar is
required before a type may alert; it does not oblige us to switch it on.

**What v2 changes, and nothing else:**

1. *Beaconing.* A new feature: how many sources contacted the destination of
   the source's steadiest repeated connection in the same window. Six of the
   seven C2 false alarms were phones and laptops checking in with Google, LINE
   and CDN servers that many campus devices use; a C2 server is usually
   contacted by one or a few infected hosts.
2. *Direction.* C2 and data exfiltration are flagged only when most of the
   source's connections leave MFU (inside zone to outside zone). All three
   exfiltration false alarms were internet clients uploading into MFU's public
   web services, which is data coming in, not leaving.
3. *Training labels follow the current rules* (catalog v5.34.0), as the
   training procedure always has: rule-alerted windows nobody labeled are left
   out, and fewer windows are rule-alerted now.

The training period, simulator, classifier, validation split and threshold
rule stay the same.

**How v2 is tested:**

- 13:50-13:55 has been seen (blind check and the v1 review), so v2's numbers
  there are reported as a second look.
- The fresh test windows are 20 May 13:45-13:50 and 13:55-13:57 (the file ends
  at 13:57). Nothing was trained, tuned or reviewed on them; the blind check
  read them only as aggregate context for its 13:50-13:55 samples.
- Condition 1 uses the fresh windows. Model-only means flagged by v2 and not
  alerted by the rules as they are now (v5.34.0). Up to 20 per type, mixed with
  an equal number of random unflagged windows, anonymized and reviewed blind.
  Two additions, declared now: a type needs **at least 5 reviewed model-only
  windows** ("Unsure" left out), so one lucky window cannot pass it; and a
  type is switched on only if the review was **done by a person, or
  AI-assisted with a person checking every row**, as stated on the sign-off.
- Condition 2 uses fresh simulated attacks (a new seed) blended into the fresh
  windows.
- Condition 3 uses the blind-check labels; since those have been read, it is
  a second look.
- All results are reported, including the types that fail.

## Addendum: experimental exception (declared 2026-09-28, after the v2 review)

No attack type passed the bar. Port scan came closest (4 of 4 judged extra finds
real, one left Unsure, against 5 needed); C2's reviewed finds were routine
check-ins; brute force, flood and exfiltration had too few or no extra finds.
Every part of the 20 May export has now been used, and no further MFU traffic is
available, so a better-tested model is not possible for now.

The team lead (Sai Myat Thura Koe) therefore switched every attack type on as an
**experimental exception**, recorded on the model card and in the audit log. This
does not change the bar or its result: no type has passed. What it allows:

- The model raises its own alert only where it flags a device's five minutes of
  traffic and no rule alert covers them. Where the rules alerted, its opinion
  stays on that alert.
- Every such alert says it was found by the MFU model, is experimental and low
  confidence, and why; it is Low severity, or Medium when the model's
  non-normal estimate is 99.5% or more, and never triggers a response on its
  own. That estimate is 1 minus the model's probability that the traffic is
  normal: it is not confidence in the named attack type, and it is not
  calibrated.
- The scoreboard and the blind check keep measuring the rules alone.
- `python -m atdr.scripts.model_alerts disable` switches it off again.

All accuracy figures come from one 21-minute MFU export (20 May 2026); treat them as low-confidence estimates until tested on more traffic.
