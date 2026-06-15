# ATDR Final System Status

## Status Summary

| Item | Current Status |
| --- | --- |
| Engineering checkpoint | v2.0 |
| Readiness decision | `final_controlled_validation_candidate` |
| Readiness gate | v8, 22/22 checks |
| Selected candidate | `independent_fpr_stabilized` |
| Production promoted | false |
| Model activated | false |
| Response automation | disabled |
| Real firewall blocking | disabled |
| Intended use | controlled lab SOC triage decision support |

ATDR has completed controlled engineering validation for a lab-scale academic
prototype. This status is not production certification.

## What Works

- FastAPI backend and React SOC dashboard.
- Local JWT login with admin/analyst RBAC.
- File import, replay, and controlled syslog/source scenarios.
- Raw evidence preservation and normalized log storage.
- `palo_alto`, `generic_syslog`, and `raw_fallback` parser profiles.
- Source management, health, data quality, and run history.
- Rule-based detection and behavior-window evidence.
- IsolationForest anomaly scoring.
- Supervised ML triage and hybrid risk scoring.
- Explainable alerts with `Why flagged?`.
- Alert deduplication and occurrence tracking.
- Lightweight case grouping.
- Human label review and AI Governance.
- Simulated analyst-approved response with protected-IP safeguards.
- Audit trail for allowed and denied actions.
- Performance smoke and automated release gate.

## Fresh Blind Validation

| Metric | Result |
| --- | ---: |
| Rows | 700 |
| Sources | 7 |
| Scenario families | 16 |
| Exact overlap | 0 |
| Near-pattern overlap | 335 |
| Threat precision | 0.8906 |
| Threat recall | 0.9459 |
| Threat F1 | 0.9174 |
| Benign-like false-positive rate | 0.1303 |
| Suspicious recall | 0.8556 |
| Malicious recall | 0.9000 |
| Macro F1 | 0.8680 |
| Weighted F1 | 0.8753 |

The candidate was evaluated without threshold tuning on the fresh blind
holdout.

## Confidence Calibration

Raw-confidence assessment:

- status: passed;
- ECE: 0.0757;
- threat-positive Brier score: 0.0751;
- maximum confidence/accuracy gap: 0.1878;
- blind labels used to fit calibration: no.

## Controlled Source Validation

- raw logs preserved: 28;
- normalized logs: 28;
- parse successes: 25;
- tracked parse failures: 3;
- alerts: 2;
- cases: 2;
- deduplicated alert update: 1;
- source registration and health: passed;
- parser fallback tracking: passed;
- `Why flagged?` evidence: passed;
- protected-IP denial: passed;
- audit recording: passed;
- automatic responses: 0;
- real firewall changes: 0.

The workflow used safe synthetic replay/syslog-style data and temporary SQLite
databases.

## Final Demonstration Scenario

The final dashboard scenario uses:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name final-demo-firewall --source-type firewall --parser-profile palo_alto --run-detection --pretty
```

Expected demonstration result:

- source health: healthy;
- logs received/normalized: 10/10;
- parse success/failure: 10/0;
- detection evaluated: 10;
- critical port-scan alerts created: 1;
- cases created: 1;
- occurrence count: 10;
- related logs: 10;
- run-scoped top attack type: `port_scan (1)`;
- automatic response actions: 0.

The scenario deliberately contains incomplete/unknown application values.
Their data-quality note is expected and does not indicate ingestion failure.

## Safety Position

- ML output is advisory.
- A model cannot directly create a response action.
- Response requires an authorized analyst, confirmation, and justification.
- Protected internal/management targets are denied.
- Response records are simulations.
- Denied attempts are audited.
- No real enforcement connector is implemented.

## Remaining Limitations

- No real router/firewall forwarding certification.
- No long-duration soak, retention, or disaster-recovery validation.
- SQLite is the normal local database; shared managed deployment is untested.
- Local JWT/RBAC is not enterprise production IAM.
- OIDC groundwork is disabled and the full external login flow is not built.
- No real firewall response connector.
- Cases are lightweight correlation, not full incident/ticket management.
- Synthetic and reviewed benchmark evidence cannot establish production
  accuracy.
- More independently reviewed real-source labels and drift monitoring are
  required.

## Recommended Next Phase

The next engineering phase should be a controlled real-device lab pilot:

1. connect one approved router or firewall to a test syslog receiver;
2. validate UDP/TCP forwarding and parser profile behavior;
3. observe source stability and drift over multiple days;
4. review real-source false positives with analysts;
5. keep response simulation and manual approval unchanged.

## Final Reference Documents

- `docs/FINAL_DEMO_RUNBOOK.md`
- `docs/FINAL_DEFENSE_TALKING_POINTS.md`
- `docs/FINAL_ACCEPTANCE_CHECKLIST.md`
- `docs/FINAL_ENGINEERING_VALIDATION_SUMMARY.md`
- `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- `docs/LAB_RUNBOOK.md`
