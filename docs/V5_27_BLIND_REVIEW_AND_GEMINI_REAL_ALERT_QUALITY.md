# v5.27 Independent Blind Review Intake And Gemini Real-Alert Quality

## Status

`human_review_handoff_required`; Gemini bounded real-record quality passed on
2026-08-08.

v5.27 adds the missing independent-review validator and locked metric
evaluator for the already-frozen v5.26 predictions. It also evaluates the
configured Gemini SOC Assistant against privacy-safe disposable snapshots of
existing dashboard records.

The supervised lifecycle remains `shadow_observation`. Deterministic rules
remain alert-authoritative. No model, label, alert, detection run, user, or
response authority changed.

## Blind Review Intake

The private evidence audit found:

| Item | Result |
| --- | ---: |
| Rows in sealed pack | 40 |
| Valid independent human reviews | 0 |
| Excluded rows | 40 |
| Exclusion reason | not reviewed |
| Assisted values counted as human | 0 |
| Predictions rerun | false |
| Metrics calculated | false |

The pack identity, token set, v5.21 structural lock, v5.26 prediction lock,
prediction-before-label flag, and privacy flags all match. A private ignored
integrity seal is created on the first write-enabled v5.27 run. No token,
reviewer identity, fingerprint, prediction value, private path, raw row, IP
address, or secret appears in tracked or console-safe results.

Metrics are withheld because the fixed gate requires at least 20 legitimate
human decisions and both queue classes. Consequently, v5.27 makes no
confusion-matrix, precision, recall, F1, FPR, calibration, false-positive, or
false-negative claim for the blind pack.

## Review Validation Contract

The validator checks:

- real reviewer identity and timezone-aware review timestamp;
- explicit reviewed and human-confirmed flags;
- allowed five-class decision and 1-100 confidence;
- meaningful review notes and threat attack type where required;
- unique tokens and exact token agreement with the private prediction lock;
- unchanged blind role and pack structure;
- absence of assisted, weak, rule, model, or prediction-exposed content; and
- continued non-import-ready status.

The full field and decision procedure is in
`docs/detection/V5_27_BLIND_REVIEWER_GUIDE.md`.

## Locked Evaluator

When legitimate support exists, the evaluator reads the existing prediction
lock and joins accepted decisions by opaque token. It does not import labels,
rerun any detector, refit a model, write an artifact, or alter the configured
database.

It calculates queue confusion counts, precision, recall, F1, benign-like FPR,
suspicious and malicious recall, macro and weighted F1, queue rate, human
`needs_context` rate, ECE, Brier score, confidence gap, and aggregate FP/FN
patterns for rules, IsolationForest, supervised shadow, and hybrid. Pattern
reports cover application, action, port, parser quality, evidence strength,
THREAT records, scan-like behavior, QUIC/443, incomplete/80, ICMP, unknown
TCP/UDP, and duplicate groups without returning individual evidence.

Any result is final-test evidence only. Repair recommendations are restricted
to development data, and a repaired candidate requires a new blind pack.

## Gemini Real-Record Evaluation

The configured provider is Gemini. Six bounded questions were evaluated over
three representative alerts, derived cases, three sources, and 24 linked-log
records copied into disposable in-memory storage. The snapshot replaced IPs,
source names, user fields, and raw log values before Assistant execution.

| Measure | Result |
| --- | ---: |
| Questions using Gemini | 6/6 |
| Quality and safety checks | 12/12 |
| Median provider latency | 3,521.5 ms |
| P95 provider latency | 3,878 ms |
| Total provider tokens | 21,973 |
| Configured DB mutations | 0 |
| Disposable authoritative mutations | 0 |
| Raw-log context included | false |
| IP redaction enabled | true |
| Forced provider failure fallback | passed |

The question set covered alert explanation, related-log follow-up, safe next
steps, investigation brief, source health, and case handoff. Checks passed for
record-context retention, trusted citations, expected evidence, unsupported-ID
prevention, concise visible output, safe recommendations, provider use,
privacy, deterministic fallback, and zero authoritative side effects.

This is bounded automated evidence, not proof of universal semantic accuracy.
Provider behavior, quotas, costs, and latency can change. Human semantic review
and institutional privacy/key-governance approval remain deployment gates.

## Safety State

- supervised lifecycle: `shadow_observation`;
- active/promotion changes: none;
- rules: alert-authoritative;
- IsolationForest, supervised, hybrid, and Gemini: advisory/read-only;
- raw-log Assistant context: disabled;
- IP redaction: enabled;
- automatic response: disabled; and
- real firewall blocking: disabled.

## Verification

- focused v5.27 regression: `8 passed`;
- complete backend/release suite: `840 passed, 1 skipped`;
- Alembic: no drift;
- React lint and production build: passed;
- Playwright: `27 passed, 1 skipped` (external live-source acceptance);
- controlled detection scenarios: `24/24` passed;
- layered detection matrix: `288/288` passed;
- deterministic Assistant QA: `20/20` passed;
- replay dry-run: parsed two safe rows and wrote zero rows;
- configured Gemini evaluation: six calls and `12/12` checks passed;
- 145,232-row performance smoke: no warnings, Overview `0.1687s`, cached
  Overview `0.0105s`, alerts `0.0409s`, cases `0.0267s`, and ML Governance
  `0.347s`; and
- official release gate: `ok: true` with every required check passing.

The only skipped browser test is the existing non-loopback live-source gate.
No verification step reset or deleted the configured database.

## Remaining Major Phases

At least three supervised evidence phases remain:

1. qualified independent review of the existing blind pack and one locked
   read-only evaluation;
2. development-only repair if fixed gates fail, without tuning on this pack;
3. a new untouched blind qualification plus a genuine second-source holdout.

At least two Assistant product-evidence phases remain:

1. human semantic/privacy evaluation over representative approved records;
2. approved-host quota, cost, key rotation, monitoring, and fallback acceptance.

These are evidence dependencies rather than arbitrary version targets. The
supervised path cannot be honestly completed by Codex or Gemini assigning the
human decisions.

## Commands

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v527_blind_review_evaluation --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v527_gemini_real_alert_quality --execute-provider --provider-interval-seconds 1 --pretty
```

Both commands write only ignored diagnostics. Neither changes normal startup
commands or runtime authority.
