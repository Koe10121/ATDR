# v3.17 Parser, Detection, And Explainability Hardening

## Status

v3.17 strengthens the core ATDR advisor requirements without changing detection thresholds, supervised ML model behavior, IAM behavior, startup commands, or response safety.

This phase adds:

- read-only parser/normalization quality validation
- controlled detection-quality validation summary
- richer log/alert explanation fields for analyst decision support
- tests and documentation updates

ATDR remains a controlled lab prototype. ML remains decision support only. Response automation and real firewall blocking remain disabled.

## Source Evidence

| Area | Evidence |
| --- | --- |
| Palo Alto parser and parser profiles | `atdr/app/parsers/paloalto_parser.py` |
| Raw/normalized log persistence | `atdr/app/services/log_service.py` |
| Detection orchestration | `atdr/app/services/detection_service.py` |
| Rule catalog and attack mapping | `atdr/app/detection/rules.py`, `atdr/app/detection/attack_mapping.py`, `docs/DETECTION_RULE_CATALOG.md` |
| Explanations | `atdr/app/detection/explanations.py` |
| Log detail API/UI | `atdr/app/routers/logs.py`, `frontend/src/pages/LogExplorer.tsx` |
| Alert detail API/UI | `atdr/app/routers/alerts.py`, `frontend/src/pages/AlertsTriage.tsx` |
| Existing validation suite | `atdr/scripts/validate_detection_pipeline.py`, `atdr/scripts/run_detection_validation_suite.py` |
| New parser validation | `atdr/scripts/validate_parser_normalization.py` |
| New quality validation | `atdr/scripts/validate_detection_quality.py` |
| Tests | `atdr/tests/test_detection_explanations.py`, `atdr/tests/test_v317_parser_detection_validation.py` |

## Parser / Normalization Validation

Command:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_parser_normalization --pretty
```

Latest targeted result:

| Metric | Result |
| --- | ---: |
| Files checked | 15 |
| Sample lines checked | 119 |
| Parsed successfully | 116 |
| Parse failures | 3 |
| Raw fallback count | 3 |
| Missing timestamp count | 4 |
| Missing source IP count | 8 |
| Missing destination IP count | 8 |
| Missing action count | 8 |
| Unknown app count | 63 |

Interpretation:

- The parser handles safe Palo Alto scenario samples.
- Generic syslog is preserved with limited normalized fields.
- Raw fallback preserves malformed evidence and counts parse failures without crashing.
- Unknown/incomplete app values are expected in several scan/brute-force/incomplete-traffic scenarios and are visible as data-quality signals.

## Detection Quality Validation

Command:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.validate_detection_quality --pretty
```

Latest targeted result:

| Metric | Result |
| --- | ---: |
| Core scenarios | 6 |
| Passed scenarios | 6 |
| Expected alerts | 2 |
| Actual alerts | 2 |
| Alerts created | 1 |
| Alerts deduplicated | 1 |
| Raw logs imported in temp DB | 33 |
| Normalized logs created in temp DB | 30 |
| Parse failures | 3 |
| Explanation completeness score | 1.0 |
| Response actions created | 0 |

Validated scenarios:

- `normal_allowed_traffic`
- `normal_web_dns_quic_traffic`
- `port_scan_like_traffic`
- `repeated_dedup_traffic`
- `generic_syslog_mixed`
- `malformed_raw_fallback`

## Explanation Improvements

Log-level triage explanations now include:

- status: flagged / not flagged
- why flagged / why not flagged summary
- normalized fields used
- normalized signals
- rule evidence summary
- anomaly evidence
- ML evidence placeholder marked decision support only
- parser warnings
- analyst next steps
- safety note

Alert detection summaries now include:

- detection source
- attack type
- ATT&CK-style mapping
- normalized fields used from primary evidence log
- rule evidence
- anomaly evidence
- supervised ML decision-support evidence if available
- hybrid risk
- behavior-window features
- top evidence points
- analyst next steps
- safety note

## Safety Controls Preserved

- No automatic response.
- No real firewall blocking.
- No ML activation or production promotion.
- No external IAM/OIDC/Google login.
- No DB reset or deletion.
- No raw evidence deletion.
- No production readiness claim.

## Known Limitations

- Scenario validation is controlled and synthetic/replay based.
- Real-source traffic may reveal new parser profiles, vendor fields, or noisy patterns.
- Unknown app rate can be high in incomplete-traffic scenarios by design.
- Explanation completeness checks are structural and do not replace analyst judgment.
- ML outputs remain SOC triage decision support only.

## Manual Dashboard Checks

After starting backend/frontend:

1. Open Log Explorer.
2. Select a normal log and check "Why not flagged?"
3. Select a log linked to an alert and check "Why flagged?"
4. Open Alerts and verify the alert detail evidence panel.
5. Ask the SOC Assistant about the alert.
6. Confirm Response & Audit shows no automatic response actions.

