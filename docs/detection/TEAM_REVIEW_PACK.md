# Team review pack

ATDR's accuracy figures and its MFU-trained behaviour model still rest on labels
made by an AI reviewer, by ATDR's own rule scores, or by the team while the rules
were being tuned. The team review pack is one workbook with every check that
needs a person, so the team can do them in one sitting (about two hours for one
person; the parts can be split).

## What is in it

| Part | Rows | What the reviewer does | What it decides |
|---|---|---|---|
| A. Model finds | 30 | Judges five minutes of one device's traffic: Threat, Normal, Normal but unusual, Unsure. 15 rows are the model's extra finds (flagged, no rule alert), 15 are random; the reviewer is not told which. | Condition 1 of the model's quality bar. Port scan is the only type that can pass this round, and only if its 5 finds are real. |
| B. Blind-check logs | 83 | Judges each blind-check log from scratch. The AI reviewer's decision is hidden. | Whether the blind labels hold up. ATDR compares the two and re-scores the blind check with the person's labels; the official result is not replaced. |
| C. BitTorrent labels | 5 | Still a threat, or policy activity? | Team labels that contradict the file-sharing policy (v5.34.0). |
| D. Label patterns | 6 groups, 257 labels | Relabel as proposed, keep, or unsure, per group, from examples. | Team labels that contradict the firewall's own threat record or an agreed policy. |

Part D's groups, as of 28 Sep (after the misattached labels were archived, `LABEL_ARCHIVE.md`):

| Group | Labels | Question |
|---|---|---|
| File sharing labeled a threat (policy violation) | 83 | Policy activity, per the 27 Sep decision? |
| Single unanswered internet probes labeled threats | 63 | Background probing, per the team's policy? |
| Shellshock (Bash remote code execution) labeled port scan | 4 | Threat, type exploit attempt? |
| XMRig miner command-and-control labeled policy violation or unknown | 30 | Threat, type malware / C2? |
| Campus devices using apps the firewall could not identify, labeled threats | 76 | Normal but unusual? The answer also decides whether ATDR keeps alerting on such traffic: made supporting-only, it would lift the blind check's precision from 80.6% to 87.9% with no Threat lost, and drop 17 Low alerts. |
| An informational "Non-RFC Compliant" record labeled a threat | 1 | Normal but unusual? |

The reviewer judges only from the file (outside lookups of internet addresses
are fine), never looks rows up in ATDR, and never asks an AI which rows were
flagged. If AI helps, a person must check every row and say so on the Sign-off
sheet: only a review done or checked by a person can switch a model type on or
make the labels "AI-assisted, human-verified". A return counts only with a
person's method, the date it was finished, and no note calling it an AI draft;
the first return (28 Sep) picked a person's method but its note said it was an
AI draft with the human review pending, so it does not count and was not scored.

MFU addresses are replaced by the same stand-ins as every earlier review file
(`mfu-lan-3.12.7`); internet addresses stay real. The build refuses to write a
file that still contains an MFU address.

## The 28 Sep return

The second return was signed "By a person without AI", but parts A and B were
the first return's AI draft word for word; the team lead confirmed a person
checked every row, so it is recorded as "AI-assisted and a person checked every
row" (`signoff.json` keeps both, with the reason). What it changed:

- **A.** Port scan: 4 of 4 judged finds real, 1 Unsure; the bar needs 5 judged,
  so no type passes this round. C2 0 of 3 judged real (5 Unsure), exfiltration
  0 of 1 (1 Unsure). Recorded on the model card.
- **B.** Every Threat-or-not verdict kept (74 of 74); 11 decisions changed, 5 of
  them rule-flagged rows moved to Unsure. The blind check with these labels:
  rules v5.32.0 precision 56.4%, recall 83.6%, F1 67.3% (the official method);
  rules v5.36.0 93.5%, 78.2%, 85.2%, most of the precision gain from rows moved
  to Unsure. `score.json` is unchanged.
- **C and D.** 185 labels relabeled after each group's condition was checked
  (backup `backups/atdr-sqlite-20260928T111657Z-4815c6a1.sqlite3`): 151 became
  Normal but unusual (83 file sharing, 62 isolated probes, 5 BitTorrent, 1
  informational record), 34 stay threats with the type the firewall names (30
  malware / C2, 4 exploit attempt). One probe kept its label because its source
  was not isolated. The unidentified-app group was left Unsure, so the rule
  that alerts on it stays as it is.

The reader checks each group's condition before relabeling, as the reviewer
asked: a label becomes harmless only if it is in no alert and its source has no
firewall record naming an attack (a background probe also only while its
source stays within the background limits in the five minutes around it); a
type is corrected only where the log's own firewall record names it. Labels
that fail keep their label and are listed in `label_conditions.json`.

## For the team lead

```
python -m atdr.scripts.team_review_pack build                       # needs openpyxl
python -m atdr.scripts.team_review_pack read --pack "returned.xlsx"
```

`build` writes `.tmp/team_review/ATDR_team_review_pack.xlsx` (send this) and
`.tmp/team_review/pack_key.json` (never send it; it maps rows back to logs, as
`.tmp/review_ip_key.json` maps stand-ins back to addresses).

`read` changes nothing in ATDR. It writes, under `.tmp/team_review/`:

- `model_review_decisions.csv` for part A;
- `blind_comparison.json` (how often the person and the AI reviewer agree, by
  why each row was chosen), `blind_decisions_human_checked.csv` and
  `blind_score_human_checked.json` (the blind check re-scored the official way
  with the person's labels) for part B;
- `label_decisions.json` for parts C and D;
- `signoff.json`, and whether the sign-off counts as a person's review.

It then prints the commands that apply the results, each of which reports its
effect before writing:

```
python -m atdr.scripts.evaluate_behavior_model --out-dir .tmp/mfu_model/v2_fresh --review-decisions .tmp/team_review/model_review_decisions.csv --min-reviewed 5
python -m atdr.scripts.evaluate_behavior_model --out-dir .tmp/mfu_model/v2_fresh --record-bar --blind-dir .tmp/mfu_model/v2_second_look --min-reviewed 5 --review-method "<as the sign-off says>"
python -m atdr.scripts.apply_label_review .tmp/team_review/label_decisions.json --reviewer "<names>"   # then --apply
```

Label changes are added as new reviewed labels; earlier labels stay as history.
Part D can also correct a label's attack type while keeping it a threat
(`attack_type` in a label-review decision). After applying, re-run the
detection scoreboard and update `../EVIDENCE_SUMMARY.md`.
