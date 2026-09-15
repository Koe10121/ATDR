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

A future protocol must use fresh evidence not consumed by v5.49b:

1. Acquire chronological native PAN-OS development windows with provenance and
   duplicate groups.
2. Obtain a second genuine physical source.
3. Collect prediction-blind human labels with adequate benign-like,
   suspicious, and malicious support.
4. Predeclare fit, calibration, threshold, and untouched future roles.
5. Freeze features, strategies, gates, thresholds, and calibration before the
   final labels are accessed.
6. Demonstrate stable precision, recall, FPR, class recall, queue rate,
   calibration, and split behavior.
7. Select at most one diagnostic candidate.
8. Require separate human approval before any shadow activation.

Failure at any gate keeps supervised runtime `unqualified`. A historical model
file or registry entry is not authorization.

## IsolationForest Review

Treat anomaly score as a prioritization feature. Monitor application, schema,
missingness, time-window, and queue-rate drift. Pay special attention to benign
QUIC/443, incomplete/80, ping/ICMP, and unknown UDP/TCP patterns. Never tune an
anomaly threshold against a consumed final window.

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

## Reporting Rules

Always report evidence role, provenance, sample support, split design, FPR,
precision, recall, F1, class recall, calibration, queue rate, and known
limitations. Controlled synthetic results must not be described as real-world
accuracy. Configuration must not be described as provider acceptance.

The historical experiment and command ledger through v5.58 remains unchanged
at `docs/archive/runbooks/AI_TRAINING_RUNBOOK_THROUGH_V5_58.md`.
