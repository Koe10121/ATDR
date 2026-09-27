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
