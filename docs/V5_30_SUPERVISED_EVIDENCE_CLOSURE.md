# v5.30 Supervised ML Evidence Closure And Promotion-Readiness Decision

## Status

v5.30 consolidates ATDR's supervised evidence into one read-only, fail-closed
decision. It does not train, recalibrate, serialize, select, activate, or
promote a model. It does not create labels, alerts, detection runs, or response
actions. The lifecycle remains `shadow_observation`, deterministic rules remain
alert-authoritative, and response automation and real firewall blocking remain
disabled.

## Canonical Evidence Inventory

| Evidence | Count / status | Permitted use |
| --- | ---: | --- |
| Latest trainable configured-DB labels | 2,672 | Development diagnostics |
| Genuine human-provenance latest labels | 1,672 | Development diagnostics; not independent blind evidence |
| Assisted or weak latest labels | 1,000 | Weighted development evidence only |
| Assisted rows carrying `reviewed=true` | 563 | Still assisted/weak; never counted as human authorship |
| Rule / ML / hybrid assisted rows | 966 / 7 / 27 | Development support only |
| Configured-label source identities | 1 | Insufficient for source holdout |
| Configured-label calendar days | 1 | Insufficient for independent temporal claims |
| Safe synthetic scenario files / rows | 24 / 171 | Controlled regression, not accuracy ground truth |
| Private native PAN-OS rows | 773,551 | Unlabeled native-schema development evidence |
| Native fit / calibration / threshold / locked-future rows | 433,499 / 116,422 / 111,626 / 112,004 | Predeclared roles; locked future stays excluded from selection |
| Sealed native blind rows | 40 | Prediction-blind human review only |
| Genuine human decisions in sealed pack | 0 | Blind metrics withheld |
| External cross-schema rows | 20,000 total; 885 comparable | Failed transfer diagnostic, not native promotion evidence |

All 2,672 configured label rows are the latest trainable label for a distinct
normalized log; there are no superseded trainable rows in the current database.
No reviewer-name assistance flag was found among the 1,672 manual-provenance
rows. This is a provenance-contract check, not proof of reviewer expertise or
independence.

## Evidence Lock Result

All 15 custody and leakage checks pass:

- v5.19 predictions were frozen before labels and labels were not used for
  tuning;
- the v5.19 terminal lock remains present;
- native exact and near-duplicate families remain contained across roles;
- v5.22 did not sample future/blind roles or use them for candidate selection;
- v5.26 froze predictions before opening label fields and counted no assisted
  value as human; and
- v5.27 did not rerun predictions or compromise blindness.

The private file was freshly inspected through a CLI argument in disposable
storage. All 773,551 rows parsed, zero failed, 22 chronological windows were
available, duplicate families remained contained, temporary storage was
removed, and the configured database was neither accessed nor written. No
path, raw row, IP address, private identifier, fingerprint, or secret was
returned.

## Candidate And Artifact Distinction

Two supervised objects must not be conflated:

1. The registered v5.1 calibrated ExtraTrees artifact is valid and available
   for governed read-only shadow scoring.
2. The newer v5.22 hierarchical two-stage ExtraTrees configuration is a frozen
   diagnostic candidate only. It intentionally has no executable artifact and
   cannot be rerun or activated by v5.30.

The v5.22 candidate passed 0/4 complete development views. Across those views,
F1 ranged `0.8025-1.0000`, FPR `0.0000-0.0476`, suspicious recall
`0.5000-0.9861`, malicious recall `1.0000`, ECE `0.0018-0.3741`, and maximum
confidence gap `0.0021-0.7099`. These are development diagnostics, not blind
promotion metrics.

## Registered Shadow Diagnostic

The registered artifact was scored read-only against the 1,672 current
human-provenance rows. Training overlap cannot be independently excluded, all
rows come from one source and one calendar day, and 567 rows belong to
near-duplicate groups. Therefore every value below is explicitly non-promotion
diagnostic evidence.

| View | F1 | FPR | Suspicious recall | Malicious recall | ECE | Queue rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| All current human-provenance rows | 0.6214 | 0.1167 | 0.3537 | 0.6452 | 0.2098 | 0.3080 |
| Single-day temporal tail | 0.2319 | 0.2354 | 0.1290 | 0.3265 | 0.6287 | 0.2394 |
| Random grouped seed 7 | 0.5685 | 0.1339 | 0.2234 | 0.5714 | 0.2117 | 0.2908 |
| Random grouped seed 17 | 0.6652 | 0.0961 | 0.3926 | 0.7684 | 0.1713 | 0.3367 |
| Random grouped seed 42 | 0.6260 | 0.0899 | 0.3009 | 0.6222 | 0.2373 | 0.2829 |
| Source holdout | withheld | withheld | withheld | withheld | withheld | withheld |

The complete all-current diagnostic is: threat precision `0.8078`, threat
recall `0.5049`, threat F1 `0.6214`, benign-like FPR `0.1167`, suspicious
recall `0.3537`, malicious recall `0.6452`, macro F1 `0.6842`, weighted F1
`0.6851`, Brier score `0.2272`, ECE `0.2098`, maximum confidence/accuracy gap
`0.5853`, abstention rate `0.0000`, and estimated review queue `515/1,672`
(`0.3080`).

Source/time reporting fails closed rather than inventing independence. The
only configured source aggregate and the only configured calendar-day
aggregate are both the same 1,672-row all-current diagnostic above. The
single-day temporal tail contains 472 rows and remains explicitly
non-independent. Source holdout metrics are withheld because there is only one
source identity. The private native stream has 22 chronological windows but no
human ground truth, so per-window accuracy, FP/FN, and calibration metrics are
also withheld.

Schema compatibility coverage was 100% with zero abstentions on these native
configured rows. The source holdout fails closed because only one real source
identity is represented.

The locked external adapter-recovery diagnostic also remains failed: 885
comparable rows, F1 `0.6504`, FPR `0.9978`, and weak calibration. It is
cross-schema evidence and cannot substitute for native PAN-OS human labels.

## Fixed Promotion Gates

v5.30 fixes its gates before accepting any outcome metric:

- at least 20 legitimate independent blind reviews and both binary classes;
- at least 1,000 independent comparable rows and 100 per binary class;
- at least two real source identities and two independent time windows;
- F1 at least `0.85`, recall at least `0.80`, and benign-like FPR at most
  `0.05`;
- suspicious and malicious recall each at least `0.70`;
- ECE at most `0.10` and maximum confidence/accuracy gap at most `0.15`;
- valid role/duplicate/leakage locks; and
- valid artifact, fail-closed schema abstention, zero lifecycle/response writes.

Five of ten evidence/contract checks pass. Independent quality checks remain
unevaluable because the sealed native pack has zero legitimate human
decisions, the configured evidence has one source/day, and the external
transfer gate failed.

## Decision

The only honest decision is:

- lifecycle: `shadow_observation`;
- activation eligible: `false`;
- production promoted: `false`;
- independent quality metrics: withheld;
- rules alert-authoritative: `true`;
- ML output: decision support only; and
- response automation / real blocking: `false` / `false`.

No new review pack was generated. The existing sealed 40-row pack is still the
correct next human-evidence artifact; creating another AI-assisted pack would
not close the independent-review gate.

## Remaining Evidence

1. A qualified independent reviewer must complete at least 20 sealed rows with
   both queue classes; stronger promotion evidence still requires the fixed
   1,000-row/100-per-class support gate.
2. A second genuine firewall/router source and independent collection window
   are required for source/time generalization.
3. A future repaired model must use development roles only, freeze before a
   new blind evaluation, and pass every fixed quality/calibration gate.
4. Any lifecycle change requires a separate explicit governance decision; it
   must not be performed by this audit.

## Verification

The complete local matrix passed:

- taskboard render and standards checks;
- repository Ruff and compileall;
- backend tests: `856 passed, 1 skipped`, reproduced by the official release
  gate; the skip is the existing hardware-dependent live-source check;
- Alembic: no new upgrade operations;
- React lint and production build;
- npm audit: zero vulnerabilities at moderate or higher;
- Playwright: `31 passed, 1 skipped`;
- controlled scenarios: `24/24`;
- layered validation: `288/288`;
- Assistant QA: `20/20` with zero authoritative side effects;
- rule/scenario contract: 18 rules and 24 scenarios, no issues;
- replay dry-run: two safe rows parsed and zero writes;
- read-only performance smoke: Overview `0.8405s`, cached Overview `0.0115s`,
  ML Governance `1.2837s`, alerts `0.0642s`, cases `0.0235s`, no warnings;
- registered-shadow audit and complete 773,551-row private disposable
  preflight; and
- official release gate: `ok: true` with no failed required checks; and
- repository hygiene: exact `20/20` cumulative v5.29.1-v5.30 path boundary,
  empty staging, clean diff check, and zero forbidden tracked private/generated
  artifacts.

These engineering passes do not change the failed evidence gates or authorize
model promotion.
