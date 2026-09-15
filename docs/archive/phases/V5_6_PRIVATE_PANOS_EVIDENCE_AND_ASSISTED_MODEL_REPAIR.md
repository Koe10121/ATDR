# v5.6 Private PAN-OS Evidence And Assisted Model Repair

Date: 2026-07-26

## Decision

v5.6 safely processes the complete private PAN-OS file through bounded
streaming and disposable SQLite storage. It builds a chronological evidence
protocol before applying a fixed conservative assisted-label policy, compares
six supervised strategies, and audits four diagnostic IsolationForest
contamination settings.

The best supervised diagnostic is
`calibrated_hist_gradient_boosting`. It is frozen as an ignored,
development-only candidate and is not active or production promoted.
Lifecycle remains `shadow_observation`, deterministic rules remain
alert-authoritative, and response automation and real firewall blocking remain
disabled.

The strong private future-window scores measure agreement with the fixed
assisted-label policy on one device. They are not independent ground-truth
accuracy and do not authorize activation.

## Private Evidence Processing

The private path was supplied only as a CLI argument. It is not returned in
reports, stored in tracked files, or imported into the configured database.

| Measure | Result |
| --- | ---: |
| Rows streamed | 773,551 |
| Parser successes | 773,551 |
| Parser failures | 0 |
| TRAFFIC records | 771,932 |
| THREAT records | 1,619 |
| Exact duplicate rows | 0 |
| Near-duplicate rows | 52,881 |
| Configured-database overlap rows | 120,000 |
| Quarantined rows after family containment | 120,626 |
| Distinct eligible minute windows | 19 |
| Peak configured chunk size | 2,000 |
| Complete file loaded in memory | false |

The 120,626-row quarantine includes the 120,000 direct configured-database
overlaps and related rows retained with quarantined families. Exact and near
families cross zero evidence-role boundaries.

Dominant applications are QUIC (`278,711`), SSL (`205,278`), incomplete
(`47,947`), ping (`25,163`), Facebook (`23,620`), DNS (`19,246`), LINE
(`18,283`), and TikTok (`13,494`). Allow traffic accounts for `771,272`
events, while alert/drop/deny total `2,279`. Port 443 accounts for `610,814`
events. These distributions explain why ordinary encrypted web traffic is a
major false-positive risk.

## Chronological Protocol

Roles were assigned before assisted labels were calculated. The latest four
eligible windows were reserved for untouched private future validation.

| Role | Events | Representative families | Windows | Use |
| --- | ---: | ---: | ---: | --- |
| Development fit | 352,312 | 327,464 | 10 | Development fitting only |
| Calibration | 113,519 | 105,955 | 3 | Development calibration only |
| Threshold | 75,090 | 70,333 | 2 | Development threshold selection only |
| Untouched future validation | 112,004 | 104,759 | 4 | Opened once after candidate freeze |
| Quarantine | 120,626 | 112,159 | 4 | Excluded |

The tracked v5.4 evidence lock matched exactly. v5.3 temporal-final, rolling,
external, and quarantine labels contributed zero rows to v5.6 model selection.
The private future labels remained sealed until a diagnostic candidate was
frozen.

## Assisted-Label Policy

No private assisted decision is represented as human review. Every decision
uses one of `codex_assisted`, `rule_assisted`,
`vendor_threat_assisted`, or `weak_supervision`, includes the fixed policy
version, and has `human_reviewed=false`.

Development/calibration/threshold event counts:

| Assisted decision | Events |
| --- | ---: |
| benign | 151,716 |
| benign_unusual | 4,770 |
| needs_context | 131,180 |
| suspicious | 248,681 |
| malicious | 4,574 |

| Provenance | Events |
| --- | ---: |
| codex_assisted | 166,643 |
| rule_assisted | 252,175 |
| vendor_threat_assisted | 1,080 |
| weak_supervision | 121,023 |

The development roles contain `409,741` high-confidence training-eligible
events and `131,180` ambiguous `needs_context` events excluded from training.
The model comparison uses bounded deterministic representative samples:
6,000 fit, 2,400 calibration, and 2,627 threshold rows. It also retains 1,467
governed human-reviewed development rows separately and assigns assisted rows
strictly lower sample weights.

No import-ready human-review file was created and no label was written to the
configured database.

## Supervised Diagnostic Comparison

Six memory-only strategies were evaluated across three nested chronological
development views:

- calibrated ExtraTrees;
- assisted/class-weighted ExtraTrees;
- calibrated HistGradientBoosting;
- calibrated Logistic Regression;
- three-class ExtraTrees SOC queue; and
- hierarchical two-stage ExtraTrees.

`calibrated_hist_gradient_boosting` ranked first. Its development ranges were:

| Metric | Range | Mean |
| --- | ---: | ---: |
| Threat/SOC queue F1 | 0.9888-1.0000 | 0.9960 |
| Benign-like false-positive rate | 0.0000-0.0016 | 0.0005 |
| Suspicious recall | 1.0000-1.0000 | 1.0000 |
| Malicious recall | 0.9778-1.0000 | 0.9926 |
| Expected calibration error | 0.0030-0.0150 | 0.0085 |
| Maximum confidence/accuracy gap | 0.0055-0.4969 | 0.2761 |

It passed `0/3` complete fixed gates because sparse confidence buckets had
large confidence/accuracy gaps. The run also exposed and fixed a chronological
calibration edge case: if a dedicated calibration role lacks one of the fitted
model classes, calibration now skips explicitly instead of crashing.

## Untouched Private Future Result

After the candidate was frozen, the future role was opened once and a capped
3,400-row representative sample was scored.

| Metric | v5.5 locked result | v5.6 private future |
| --- | ---: | ---: |
| Threat/SOC queue F1 | 0.4925 | 0.9889 |
| Benign-like false-positive rate | 0.0773 | 0.0211 |
| Suspicious recall | 0.3824 | 1.0000 |
| Malicious recall | 0.4143 | 1.0000 |
| Expected calibration error | 0.5405 | 0.0155 |
| Maximum confidence/accuracy gap | 0.7076 | 0.8143 |
| Review queue rate | 0.1523 | 0.4962 |

The candidate produced 37 false-positive assisted decisions and zero false
negatives against this policy. The false positives were ordinary allowed
traffic, mainly Microsoft Excel and Google Play on port 443 in the earliest
future minute.

The maximum confidence/accuracy gap remains unacceptable, so calibration is
`weak`. More importantly, these labels come from the same fixed assisted
policy used to construct development evidence. The result therefore shows
chronological policy consistency on this private source, not independent
accuracy or cross-device generalization.

## IsolationForest Audit

Diagnostic alternatives used high-confidence benign development evidence only.
The selected development contamination was `0.02`.

| Metric | v5.5 | v5.6 private future |
| --- | ---: | ---: |
| Benign-like false-positive rate | 0.2773 | 0.0057 |
| Threat capture / queue recall | 0.0818 | 0.4576 |
| Queue F1 | not reported | 0.6253 |
| Suspicious recall | not reported | 0.1600 |
| Malicious recall | not reported | 0.7935 |
| Review queue rate | 0.1820 development | 0.2250 |

The low future FPR is accompanied by weak suspicious recall and large
application-specific rate differences. Web-browsing and SSL dominate anomaly
output, while vendor THREAT rows are not consistently anomalous.
IsolationForest therefore remains advisory and is not a standalone detector.

## Safety And Lifecycle

- Configured database rows before and after are identical.
- Labels, model runs, detection runs, alerts, and response actions created:
  `0`.
- Existing supervised and IsolationForest artifact hashes are unchanged.
- The optional v5.6 candidate artifact is ignored and separate from active
  artifacts.
- Active model artifact written or replaced: `false`.
- Model activated or production promoted: `false`.
- ML changed authoritative alerts: `false`.
- Rules remain alert-authoritative: `true`.
- Response automation enabled: `false`.
- Real firewall blocking enabled: `false`.
- Private path, raw logs, IP addresses, secrets, and reusable row fingerprints
  returned: `false`.

Readiness remains `shadow_observation`. The supervised and IsolationForest
future gates fail, independent multi-device evidence is unavailable, and the
private evidence has no genuine human ground truth.

## Verification

- Taskboard render and standards checks passed.
- Whole-repo Ruff and compileall passed.
- Combined v4.9/v5.6 focused tests passed `21/21`.
- Full backend tests passed `679`, with one hardware-dependent skip.
- The official release gate independently passed the same
  `679 passed, 1 skipped` suite with no failed required check.
- Alembic reported no new upgrade operation.
- React lint and production build passed.
- Playwright passed `26`, with one live-hardware scenario skipped.
- Controlled detection passed `24/24`.
- Layered validation passed `288/288`, with zero false-positive or
  false-negative controlled runs.
- SOC Assistant QA passed `20/20`, with required citation rate `1.0`, safe
  refusal, and zero response/detection/model/label/alert/log side effects.
- Replay dry-run parsed two safe rows and wrote or sent zero.
- Performance smoke passed with no warnings: Overview `0.1776s`, cached
  `0.0103s`, alerts `0.0440s`, cases `0.0762s`, ML Governance `1.2231s`, and
  feature generation `0.0071s`.
- `git diff --check`, tracked sensitive-file checks, ignored-output checks, and
  private-output redaction checks passed.

## Remaining Evidence

1. Human-reviewed chronological evidence from a separate collection period.
2. Reviewed evidence from at least two independent real source devices.
3. A new untouched schema-compatible external benchmark.
4. Confidence calibration with adequate support in every bucket.
5. Independent confirmation that assisted suspicious/malicious rules reflect
   analyst truth rather than policy agreement.
6. Continued shadow monitoring before any later activation discussion.

Generated reports and the optional diagnostic artifact remain ignored under
`ml_baseline_reviews/`. This document authorizes no commit or push.
