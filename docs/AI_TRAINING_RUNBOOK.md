# ATDR AI And Model Governance Runbook

This is the active model and Assistant governance reference. It deliberately
separates implemented algorithms from evidence-qualified runtime authority.

## Current Runtime Decision

| Layer | Runtime state | Authority |
| --- | --- | --- |
| Deterministic rules | `active_authoritative` | May create explainable alerts |
| IsolationForest | `active_advisory` when an eligible artifact is available | Unusual-behavior context only |
| Supervised SOC queue | `unqualified` | Ordinary inference fails closed |
| Hybrid triage | `active_advisory` | Ranks supporting evidence only |
| SOC Assistant | Read-only deterministic/Gemini synthesis | Explanation and decision support |
| Response | `simulation_only` | Analyst-confirmed simulation only |

The immutable v5.49b evaluation consumed 180 genuine protected decisions once,
ran all eight fixed strategies, and selected no supervised candidate. The
evaluation role lacked suspicious support and every strategy failed the fixed
calibration gap. No artifact was activated or promoted. That evidence must not
be rerun, repartitioned, or used for tuning.

## Alert Authority

Rules remain authoritative because their conditions and evidence are directly
auditable. IsolationForest does not establish malicious intent. Supervised and
hybrid outputs cannot create, suppress, close, or change the severity of an
authoritative alert, and none may authorize response.

Inspect the effective contract without changing data:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v558_governed_hybrid_runtime --require-safe --pretty
```

## Label Integrity

Allowed analyst decisions are `benign`, `benign_unusual`, `needs_context`,
`suspicious`, and `malicious`. Suspicious or malicious decisions require an
attack type and evidence-based rationale.

- Human-reviewed means a genuine analyst independently reviewed displayed
  evidence and confirmed the decision.
- Rule-, ML-, or AI-assisted suggestions remain weak labels.
- Synthetic labels remain synthetic.
- Existing manual labels are protected from automated overwrite.
- Protected review rows, identities, predictions, fingerprints, and decisions
  remain private and ignored.

Never change labels to satisfy a class quota or improve a metric.

## Future Supervised Qualification

v5.62 provides the fresh protocol foundation. v5.63 preserves its 300 rows and
adds 700 non-overlapping development-safe rows in seven protected batches,
reaching 1,000 selected comparable rows. Selection is not human review. Check
only safe aggregate status with:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v562_supervised_qualification_campaign --status-only --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.run_v563_fresh_evidence_expansion --status-only --pretty
```

Do not rerun preparation over either existing workspace. Use **Evidence Review
-> Supervised Qualification** to complete the original workspace and each
supplemental batch. Development code cannot load labels before every required
closure and can never load the untouched future-evaluation role.

Qualification still requires:

1. Complete all 300 original and 700 supplemental decisions without forcing
   class quotas.
2. Close all seven supplemental batches to make decisions immutable.
3. Obtain and safely preflight a second genuine physical source.
4. Collect prediction-blind human labels with adequate benign-like,
   suspicious, and malicious support.
5. Preserve the locked fit, calibration, threshold, and untouched future roles.
6. Freeze features, strategies, gates, thresholds, and calibration before the
   final labels are accessed.
7. Demonstrate stable precision, recall, FPR, class recall, queue rate,
   calibration, and split behavior.
8. Select at most one diagnostic candidate.
9. Require separate human approval before any shadow activation.

Failure at any gate keeps supervised runtime `unqualified`. A historical model
file or registry entry is not authorization.

## IsolationForest Review

Treat anomaly score as a prioritization feature. Monitor application, schema,
missingness, time-window, and queue-rate drift. Pay special attention to benign
QUIC/443, incomplete/80, ping/ICMP, and unknown UDP/TCP patterns. Never tune an
anomaly threshold against a consumed final window.

### Interpreting Runtime Telemetry

`current_anomaly_rate` is the percentage of **scored rows** currently flagged.
`scoring_coverage_percent` is the percentage of stored normalized rows that
have an anomaly score. `stored_anomaly_prevalence_percent` is the percentage of
all stored rows currently flagged. Never present one denominator as another.

Run the development-only v5.63.1 reliability comparison without installing:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v5631_anomaly_reliability `
  --sample-path "<private-log-file>" `
  --limit 50000 `
  --pretty
```

The private path is an input only. Output must not contain paths, raw records,
network addresses, identities, row fingerprints, or secrets. Install remains
fail-closed unless one candidate passes every fixed gate and the operator gives
the exact confirmation. v5.63.1 selected and installed no candidate.

Run the stricter v5.64 chronology/context comparison with no installation path:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v564_window_aware_anomaly_redesign `
  --sample-path "<private-log-file>" `
  --limit 50000 `
  --pretty
```

v5.64 selected no candidate. Its best diagnostic reached 0% controlled benign
anomaly, 85.71% suspicious scenario capture, and 50% malicious scenario
capture, with 99.01% rule overlap. The untouched candidate holdout remained
unused. Do not tune thresholds against it or treat rule-overlapping anomaly
signals as independent threat evidence.

### Governed Bootstrap

A clean clone intentionally has no model artifact. Normal setup and startup do
not train one. Preflight the committed synthetic capability sample without
writing:

```powershell
.\scripts\bootstrap_advisory_anomaly.cmd -UseCommittedSyntheticSample -Pretty
```

After reviewing all gates, execute only with the exact confirmation:

```powershell
.\scripts\bootstrap_advisory_anomaly.cmd `
  -UseCommittedSyntheticSample `
  -Execute `
  -Confirm GOVERNED_ADVISORY_ANOMALY_BOOTSTRAP `
  -Pretty
```

Private evidence may be supplied through `-EvidencePath` at runtime. The
command never returns that path, raw rows, IPs, or fingerprints. Training and
acceptance use disposable SQLite; only the ignored configured artifact and
sanitized `.bootstrap.json` manifest remain. This validates capability, not
threat accuracy. See `docs/V5_61_GOVERNED_ANOMALY_BOOTSTRAP.md`.

## SOC Assistant Governance

Assistant facts come from bounded ATDR services and approved runbook snippets.
Gemini is a synthesis layer, not the source of alert facts. The provider receives
no raw logs by default; IP redaction is mandatory and API keys are never exposed
through status, answers, or audit records.

The Assistant cannot execute detection, response, label changes, model changes,
account changes, or deletion. Unsupported, ungrounded, unsafe, malformed,
oversized, timeout, quota, or provider-failure output falls back to the
deterministic answer.

Run controlled quality checks with disposable data:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_assistant_qa --pretty
.\.venv\Scripts\python.exe -m atdr.scripts.test_assistant_chat_provider --execute --pretty
```

Before an advisor demonstration, exercise the whole bounded workflow with:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v5631_advisor_demo_acceptance `
  --use-temp-db `
  --execute-provider-probe `
  --pretty
```

The acceptance command must not access the configured database. A provider
failure may fall back deterministically, but a live-provider claim requires
the explicit probe to pass.

## Reporting Rules

Always report evidence role, provenance, sample support, split design, FPR,
precision, recall, F1, class recall, calibration, queue rate, and known
limitations. Controlled synthetic results must not be described as real-world
accuracy. Configuration must not be described as provider acceptance.

The historical experiment and command ledger through v5.58 remains unchanged
at `docs/archive/runbooks/AI_TRAINING_RUNBOOK_THROUGH_V5_58.md`.
