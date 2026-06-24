# v3.19 No-Hardware Soak And Parser Drift Validation

## Status

v3.19 adds a controlled no-hardware soak validator for ATDR. It simulates multiple named log sources using only safe synthetic scenario files under `data/samples/scenarios/`, imports them into a temporary SQLite database by default when validation is requested with `--use-temp-db`, runs rule detection when requested, and reports parser drift, alert noise, source health, explanation completeness, and safety.

This does not change detection thresholds, ML behavior, response behavior, startup commands, database schema, external IAM, or production-readiness status.

ATDR remains a controlled lab prototype. ML remains decision support only. Response automation and real firewall blocking remain disabled.

## Source Evidence

| Area | Evidence |
| --- | --- |
| No-hardware soak runner | `atdr/scripts/run_no_hardware_soak.py` |
| Scenario registry and synthetic samples | `atdr/scripts/run_source_scenario.py`, `data/samples/scenarios/*.txt` |
| Parser profiles | `atdr/app/parsers/paloalto_parser.py` |
| Import and raw evidence preservation | `atdr/app/services/log_service.py`, `atdr/app/db/models.py` |
| Detection and deduplication | `atdr/app/services/detection_service.py`, `atdr/app/services/alert_service.py` |
| Source health and quality | `atdr/app/services/source_service.py` |
| Explanations | `atdr/app/detection/explanations.py` |
| Tests | `atdr/tests/test_v319_no_hardware_soak.py` |

## Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_no_hardware_soak --use-temp-db --iterations 3 --source-count 3 --run-detection --pretty
```

Dry-run mode parses only and does not write database rows:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_no_hardware_soak --dry-run --iterations 1 --source-count 3 --pretty
```

## Default Scenario Mix

The default soak mix includes:

- normal Palo Alto traffic
- incomplete/unknown application rows
- generic syslog rows
- malformed raw-fallback rows
- malformed Palo Alto-like vendor rows
- repeated suspicious/dedup traffic
- horizontal scan-like traffic
- denied SSH burst traffic
- C2-like beaconing traffic

`benign_repeated_internal_service` and `malicious_like_exfiltration_burst` remain available for targeted runs. They are intentionally not in the default pass/fail soak because repeated benign service traffic can become a useful connection-flood noise probe, and exfil-like rows can collide with C2-style grouping when mixed with prior C2-like activity in the same source/window. Those are follow-up rule-noise topics, not v3.19 default stability failures.

## Latest Targeted Result

Latest targeted 3-iteration / 3-source temp-DB result:

| Metric | Result |
| --- | ---: |
| Events | 27 |
| Events passed | 27 |
| Logs attempted | 138 |
| Raw logs imported | 138 |
| Normalized logs created | 138 |
| Parse failures | 9 |
| Duplicate raw logs | 92 |
| Alerts created | 4 |
| Alerts deduplicated | 8 |
| False-positive scenarios | 0 |
| False-negative scenarios | 0 |
| Unexpected attack type count | 0 |
| Parser warnings | 114 |
| Raw fallback count | 9 |
| Missing timestamp count | 12 |
| Missing source IP count | 24 |
| Missing destination IP count | 24 |
| Missing action count | 27 |
| Unknown app count | 105 |
| Explanation completeness | 1.0 |
| Response actions created | 0 |
| ML model runs created | 0 |

## Source Health Result

| Source | Parser Profile | Status | Logs | Parse Success | Parse Failures | Notes |
| --- | --- | --- | ---: | ---: | ---: | --- |
| `soak-firewall-1` | `palo_alto` | healthy | 120 | 120 | 0 | Unknown/incomplete app values are expected for scan-style and partially established synthetic rows. |
| `soak-router-1` | `generic_syslog` | warning | 9 | 9 | 0 | Generic syslog preserves evidence but extracts limited structured fields. |
| `soak-workstation-source` | `raw_fallback` | error | 9 | 0 | 9 | Raw fallback preserves evidence and marks limited parsing as non-fatal. |

## Safety Result

- No automatic response actions were created.
- Real firewall blocking remained disabled.
- ML was not activated, promoted, or retrained.
- The default validation used a temporary in-memory database.
- Raw evidence was preserved for malformed and fallback rows.

## Known Limitations

- This is no-hardware controlled validation, not real router/firewall forwarding.
- It does not prove production detection accuracy.
- It does not tune rule thresholds or ML.
- Real-source parser drift and long-duration hardware syslog validation remain future work.
- Targeted repeated-benign service traffic can still surface connection-flood noise and should be reviewed in a later rule-noise tuning phase.
