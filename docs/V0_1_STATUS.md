# ATDR v0.1 Lab-Ready Status

## Current Stage

ATDR v0.1 is a lab-ready defensive SOC prototype for small-office or university-lab validation. It is not certified production software and should not be connected to real firewall enforcement without a reviewed connector, allowlist, rollback plan, and change approval.

## What Works

- FastAPI backend with JWT authentication and admin/analyst roles.
- React SOC dashboard at `http://127.0.0.1:5173`.
- Palo Alto syslog CSV parsing with raw evidence preservation.
- Manual log import and optional localhost UDP syslog ingestion.
- Normalized log search and evidence review.
- Rule-first grouped alert generation.
- Alert workflow: New, Investigating, Needs More Context, Contained, Resolved, False Positive.
- Computed related-alert case grouping.
- IsolationForest anomaly scoring.
- Supervised ML decision-support model with weak-label, reviewed-label, active-learning, and model governance workflows.
- Hybrid risk scoring and "why flagged" explanations.
- ML Governance with weak/reviewed label separation and model-promotion warnings.
- Simulated response action recording.
- Audit trail for auth, alert workflow, labels, detection, and response actions.
- Optional lab scenario runner and release verification gate.

## What Is Simulated

- IP block/unblock response actions are simulated.
- No real firewall API enforcement is active.
- Response state is recorded in ATDR database and audit logs only.
- Docker/PostgreSQL is optional lab-pilot scaffolding and is not required for local testing.

## Current AI Status

- Model status: `candidate_improved`.
- Analyst review eligible: yes.
- Production promoted: no.
- Automatic response from ML output: disabled.
- Threat-positive triage is strong.
- Exact suspicious-versus-malicious separation is still imperfect.
- Suspicious recall remains below target.
- Metrics remain mixed-label / weak-label influenced and must not be presented as production accuracy.

## Current Response Safety Status

- Response mode defaults to simulation.
- Block/unblock requires admin role.
- Simulated response requires confirmation in the React UI.
- Justification note is required.
- Internal/management IP ranges are protected.
- Alert-linked block is denied when the alert has no evidence logs.
- Denied response attempts are audited.

## Current Lab-Readiness Status

- Local SQLite workflow is preserved.
- Backend command is unchanged.
- Frontend command is unchanged.
- Config Doctor and release gate pass with only expected local-demo JWT warning.
- Optional lab scenario runner can import safe sample logs, run detection, report timings, and skip reset by default.
- Local syslog smoke path is documented and can be validated with temporary SQLite databases.

## Known Limitations

- Not a full enterprise production UI yet.
- No real firewall connector.
- No high-availability deployment validation.
- Docker/PostgreSQL validation still depends on a Docker-capable host.
- Supervised model quality depends on more reviewed labels, especially suspicious/malicious boundary cases.
- Live syslog receiver is UDP/local-lab oriented and should not be exposed publicly.
- SQLite is fine for local testing but not recommended for shared lab operation.

## Recommended Next Development Phase

Move into v0.2 lab pilot validation:

- Use safe replay mode to simulate near-real-time ingestion before connecting lab hardware.
- Validate Docker/PostgreSQL on a capable host.
- Run live syslog forwarding from a lab firewall or log forwarder.
- Monitor alert deduplication and case grouping quality during repeated replay/live tests.
- Tune alert thresholds against reviewed baseline traffic.
- Add operator backup/restore rehearsal.
- Expand reviewed labels for suspicious/malicious boundary quality.
- Design a formal real-firewall connector approval flow, but keep enforcement disabled until approved.
