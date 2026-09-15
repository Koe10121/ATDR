# v0.7 Detection Quality Hardening

ATDR v0.7 improves controlled detection validation quality without changing the normal local workflow, enabling automatic response, or claiming production readiness.

## Scope

v0.7 validates that the defensive detection pipeline handles both threat-like and normal traffic in a controlled lab setting:

- positive-control threat-like scenarios still create expected alerts;
- negative-control normal scenarios avoid high/critical false positives;
- mixed traffic can contain benign, threat-like, and odd/malformed rows without crashing;
- risk and severity are checked against expected lab ranges;
- alert evidence includes concrete analyst-facing clues;
- response actions remain simulated and analyst-approved only.

This is synthetic/replay validation only. It is not real attacker testing and not production certification.

## Scenario Additions

New safe samples under `data/samples/scenarios/`:

| Scenario | Purpose | Expected Result |
| --- | --- | --- |
| `normal_web_dns_quic_traffic` | Normal web, DNS, and QUIC traffic | No high/critical alerts and no noisy alert creation. |
| `normal_high_volume_but_allowed_traffic` | Approved moderate-volume business traffic | No exfiltration alert because volume stays below lab threshold and context is benign. |
| `normal_repeated_same_service_traffic` | Repeated allowed access to one common service | No scan/beacon alert because the service is common and allowed. |
| `mixed_small_subnet_validation` | Benign rows plus scan-like, brute-force-like, beacon-like, and odd rows | Expected threat alerts appear, raw evidence remains linked, and no response actions are created. |

Existing v0.6 scenarios remain active:

- `normal_allowed_traffic`
- `port_scan_like_traffic`
- `brute_force_like_traffic`
- `malware_c2_like_beaconing`
- `data_exfiltration_suspicion`
- `ddos_or_connection_flood_like`
- `repeated_dedup_traffic`
- `generic_syslog_mixed`
- `malformed_raw_fallback`
- `policy_violation_suspicious_app`

## Validation Suite

Run all scenarios safely against a temporary in-memory SQLite database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_validation_suite --all --pretty
```

Default behavior is safe:

- no current database changes;
- no real logs imported;
- no offensive tools;
- no real firewall blocking;
- no automatic response actions.

To intentionally publish validation rows to the current dashboard database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_detection_validation_suite --scenario mixed_small_subnet_validation --write-to-current-db --pretty
```

## Reports

The suite writes ignored reports to `demo_exports/detection_validation/` unless `--no-report` is passed:

- `detection_validation_<timestamp>.json`
- `detection_validation_<timestamp>.md`
- `detection_validation_<timestamp>_risk_calibration.md`

The risk calibration report checks:

- expected versus actual severity;
- expected versus actual risk score range;
- alert count;
- evidence point count;
- pass/fail by scenario.

Generated reports must remain ignored and must not be committed.

## Dashboard Visibility

The Overview page now has a compact controlled-validation summary that reads the latest local validation report:

- scenarios passed / total scenarios;
- latest report filename;
- latest risk-calibration report filename;
- lab validation status;
- manual approval and simulated response reminders.

The API endpoint is:

```text
GET /api/dashboard/validation-summary
```

It returns only safe metadata and report filenames. It does not expose report contents, secrets, or private full paths.

## Current Expected Result

The v0.7 suite covers 14 scenarios. A healthy run should report:

```text
14 / 14 scenarios passed
```

The scenario suite also verifies that response action count remains unchanged.

## Limitations

- Synthetic/replayed logs are not a replacement for real router/firewall syslog validation.
- Risk thresholds are lab calibration targets, not production SLAs.
- ML remains decision support only.
- Response actions remain simulated and analyst-approved.
- Real firewall blocking remains future approved work only.
