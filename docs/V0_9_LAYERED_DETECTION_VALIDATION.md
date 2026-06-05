# ATDR v0.9 Layered Detection Validation

## Status

ATDR v0.9 validates and explains the contribution of each detection layer in controlled lab-scale scenarios:

- rule-based detection
- IsolationForest anomaly detection
- supervised ML / SOC triage
- hybrid risk scoring

The goal is not to claim that ML is perfect. The goal is to show a layered SOC architecture where rules catch known patterns, anomaly detection can add unusual-behavior signals, supervised ML supports analyst triage, and hybrid scoring combines evidence into a decision-support risk score.

## Safety Boundaries

- No real attacks are executed.
- No offensive tools or exploit payloads are used.
- Only safe synthetic/replay/public-style logs are used.
- Response actions remain simulated and analyst-approved.
- Automatic response remains disabled.
- Real firewall blocking remains disabled.
- ML remains decision support only.
- Reports are generated under ignored `demo_exports/layered_detection/`.

## Detection Modes

`rules_only`
: Runs the existing rule-first detection service without applying anomaly scoring first. This is the primary known-pattern layer for scans, brute-force-like attempts, beaconing-like behavior, exfiltration suspicion, policy/app-risk signals, and connection-flood-like behavior.

`anomaly_only`
: Runs IsolationForest anomaly scoring as a diagnostic layer. It reports anomaly signals when available, but it is not required to catch every controlled scenario. Tiny synthetic batches may not produce strong anomaly contribution.

`supervised_only`
: Runs supervised SOC triage predictions as advisory decision support. Candidate model output is reported when available. It does not trigger response and does not replace per-class validation limits.

`hybrid`
: Runs detection with layered context and reports rule, anomaly, supervised, and hybrid evidence. Hybrid risk combines rule score, anomaly score, supervised threat probability, and optional context weighting.

## Commands

Run a focused validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_layered_detection_validation --scenario port_scan_like_traffic --scenario normal_web_dns_quic_traffic --variants 1 --pretty
```

Run the full v0.9 validation suite against a temporary database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_layered_detection_validation --all --variants 3 --pretty
```

Only write generated variants to the current dashboard database when intentionally inspecting them in React:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_layered_detection_validation --scenario port_scan_like_traffic --variants 1 --write-to-current-db --pretty
```

## Current Validation Result

The latest controlled v0.9 run validated:

- 14 scenario families
- 42 generated variants
- 4 detection modes per variant
- 168 total mode runs
- 168 / 168 passed
- false positives: 0
- false negatives: 0

Layer contribution summary from the controlled run:

- Rules contributed to known-pattern scenarios.
- Anomaly-only contributed on a limited subset of unusual synthetic rows.
- Supervised-only produced advisory SOC triage signals where the candidate model had enough signal.
- Hybrid preserved rule detection and added layered decision-support context.

## Dashboard Impact

The React Overview page shows a compact “Layered Modes” card from `/api/dashboard/validation-summary`:

- mode runs passed
- false positives
- false negatives
- latest report metadata

The dashboard does not show full technical reports inline. Generated JSON/Markdown reports remain in ignored `demo_exports/layered_detection/`.

## Limitations

- This is controlled synthetic/replay validation, not production certification.
- It does not replace real router/firewall forwarding validation.
- Anomaly contribution depends on the IsolationForest artifact and the size/shape of the sample.
- Supervised ML remains SOC triage decision support and is not production-promoted.
- Response automation remains disabled.

## Next Recommended Phase

Use v0.9 to explain layered detection clearly to advisors, then move to controlled real-source validation when router/firewall/syslog forwarding is available.
