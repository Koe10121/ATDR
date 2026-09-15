# ATDR Final Evidence Checklist

Use synthetic or approved sanitized evidence only. Do not capture secrets,
private log payloads, passwords, JWT tokens, `.env` contents, database files,
or private model/review artifacts.

## Presentation Environment

- [ ] Repository path and branch are recorded.
- [ ] `git status --short` has been reviewed.
- [ ] No real logs, DB files, `.env`, model artifacts, review CSVs, generated
      reports, or processed logs are staged.
- [ ] Backend terminal shows successful startup on `127.0.0.1:8000`.
- [ ] Frontend terminal shows successful Vite startup on `127.0.0.1:5173`.
- [ ] `/health` returns a healthy response.
- [ ] Browser is logged in with the intended demo role.

## Overview Evidence

- [ ] Overview page screenshot.
- [ ] `Final Controlled Validation Candidate` visible.
- [ ] `Decision Support Only` visible.
- [ ] `Not Production Promoted` visible.
- [ ] `Response Automation Disabled` visible.
- [ ] Operations Health visible.
- [ ] Latest ingestion and detection run visible.
- [ ] Log Sources panel visible.

## Final Scenario Evidence

- [ ] Preflight command and successful `ok: true` output captured.
- [ ] Dashboard-visible scenario command captured.
- [ ] Source name is `final-demo-firewall-live`.
- [ ] Source health is healthy.
- [ ] Logs received: 10.
- [ ] Normalized logs: 10.
- [ ] Parse success/failure: 10/0.
- [ ] Detection evaluated: 10.
- [ ] Alerts created or deduplicated are explained correctly.
- [ ] Recent run attack type shows `port_scan (1)` only.
- [ ] Unknown/incomplete app note is described as expected scan-scenario data
      quality, not system failure.
- [ ] Automatic response count remains 0.

## Source Detail Evidence

- [ ] Source type and `palo_alto` parser profile visible.
- [ ] Last seen and log counters visible.
- [ ] Parse success/failure visible.
- [ ] Source-level unknown-app rate/note visible.
- [ ] Recent ingestion run visible.
- [ ] Recent detection run visible.
- [ ] Run attack types show `port_scan (1)`.

## Investigation Evidence

- [ ] Log Explorer filtered by `final-demo-firewall-live`.
- [ ] Raw evidence is visible without exposing private data.
- [ ] Normalized source, destination, port, action, app, and timestamp visible.
- [ ] Source-aware filter is visible.
- [ ] Parser status is visible.

## Alert Evidence

- [ ] Critical port-scan alert visible.
- [ ] Alert title references source `203.0.113.44`.
- [ ] Severity and risk score visible.
- [ ] Attack type and detection source visible.
- [ ] Occurrence count: 10.
- [ ] Related-log count: 10.
- [ ] `Why flagged?` visible.
- [ ] Port range / repeated destination-port evidence visible.
- [ ] Deny/drop or incomplete-session behavior visible.
- [ ] ATT&CK-style context visible where available.
- [ ] Recommended analyst action visible.

## Case Evidence

- [ ] One related port-scan case visible.
- [ ] Related alert count visible.
- [ ] Total related logs visible.
- [ ] Source IP visible.
- [ ] First seen / last seen visible.
- [ ] Top ports and actions visible.
- [ ] Recommended analyst focus visible.

## Response Safety Evidence

- [ ] Response & Audit page screenshot.
- [ ] Simulated response wording visible.
- [ ] Manual approval requirement visible.
- [ ] Confirmation dialog visible.
- [ ] Justification-note requirement demonstrated.
- [ ] Approved test action is clearly marked simulated, if demonstrated.
- [ ] Protected-IP attempt is denied.
- [ ] Denied attempt appears in audit.
- [ ] No real firewall state change is claimed.
- [ ] No ML output creates an automatic response.

## AI Governance Evidence

- [ ] Candidate `independent_fpr_stabilized` visible.
- [ ] Readiness v8 22/22 visible.
- [ ] Fresh blind holdout: 700 rows / 7 sources / 16 scenarios visible.
- [ ] Threat precision: 0.8906.
- [ ] Threat recall: 0.9459.
- [ ] Threat F1: 0.9174.
- [ ] Benign-like FPR: 0.1303.
- [ ] Suspicious recall: 0.8556.
- [ ] Malicious recall: 0.9000.
- [ ] Calibration passed with no blind-label fitting.
- [ ] Decision-support and non-production language visible.

## Automated Verification Evidence

- [ ] Ruff passed.
- [ ] Compileall passed.
- [ ] Backend tests passed.
- [ ] Alembic check reports no drift.
- [ ] React lint passed.
- [ ] React build passed.
- [ ] Playwright passed, with any intentional live-test skip explained.
- [ ] Replay dry-run passed without DB writes.
- [ ] Performance smoke passed without warnings.
- [ ] Release gate passed.
- [ ] Final scenario preflight passed using a temporary DB.

## Final Performance Evidence

Record presentation-day values:

| Check | Value |
| --- | --- |
| Overview summary | |
| Cached Overview | |
| ML Governance summary | |
| Alert list | |
| Case summary | |
| Feature generation sample | |
| Warnings | |

## Submission Evidence

- [ ] `docs/FINAL_REPORT_OUTLINE.md`
- [ ] `docs/FINAL_REPORT_DRAFT.md`
- [ ] `docs/FINAL_PRESENTATION_SLIDE_CONTENT.md`
- [ ] `docs/FINAL_DEMO_SCRIPT.md`
- [ ] `docs/FINAL_DEFENSE_QA.md`
- [ ] `docs/SUPERVISOR_FINAL_STATUS_SUMMARY.md`
- [ ] `docs/FINAL_SYSTEM_STATUS.md`
- [ ] `docs/FINAL_ENGINEERING_VALIDATION_SUMMARY.md`
- [ ] `docs/FINAL_ACCEPTANCE_CHECKLIST.md`
- [ ] `docs/ATDR_REQUIREMENT_TRACEABILITY.md`
- [ ] Final report references use the required university citation style.
- [ ] Screenshots are stored outside Git unless explicitly approved.
- [ ] Final commit contains source/docs only.
