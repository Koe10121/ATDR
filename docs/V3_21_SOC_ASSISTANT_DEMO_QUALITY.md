# v3.21 SOC Assistant Demo-Quality Upgrade

Date: 2026-06-21

## Summary

v3.21 improves the ATDR SOC Assistant for advisor demonstration and analyst usability. The assistant remains deterministic, local, read-only, and safe by default. It does not call an external LLM, expose raw logs by default, execute response actions, run detection, change labels, activate models, promote models, delete data, or send email.

## What The Assistant Can Answer

| Area | Example Questions | Current Behavior |
| --- | --- | --- |
| Critical alerts | `Show latest critical alerts.` | Lists current open critical alerts with IDs, severity, type, risk score, and references. |
| Alert explanation | `Why was alert 1 flagged?` | Summarizes severity, risk score, attack type, detection source, evidence, related logs, source context, ATT&CK-style mapping, and safe next steps. |
| Safe analyst workflow | `What can I safely do next for this alert?` | Recommends review, source health checks, analyst notes, lifecycle updates, and simulated response only after confirmation. |
| Source health | `Which sources have warnings?` | Summarizes warning/error/idle/disabled sources, parse failures, unknown app rate, and linked alert counts. |
| Detection runs | `Summarize recent detection runs.` | Lists recent detection runs, logs evaluated, alerts created, dedup count, and top attack types. |
| Operations | `Summarize failed jobs.` or `What changed recently?` | Summarizes operation jobs and recent audit/job activity. |
| ML Governance | `Explain current ML model status.` | Explains decision-support model state, anomaly artifact status, supervised label count, promotion gate, and response automation status. |
| Model promotion | `Why is the model not production promoted?` | Explains readiness gate, failed checks, warnings, and why ML remains SOC triage support. |
| How-to | `How do I import logs?` | Gives dashboard and CLI replay guidance without changing data itself. |
| Reviewed labels | `How do I import reviewed labels?` | Explains the AI Governance import workflow and review-column expectations. |
| Safe scenario | `How do I run a safe demo scenario?` | Gives safe source scenario command guidance and notes `--use-temp-db` for isolated validation. |

## What The Assistant Cannot Do

The assistant refuses command-like requests to:

- block or unblock IPs
- delete logs, alerts, labels, users, or data
- run or trigger detection
- activate or promote ML models
- change labels
- send email
- enable automation
- enable real firewall blocking

The refusal response points the analyst to the correct safe workflow: inspect evidence, use Response & Audit manually, provide justification, and rely on simulation/protected-IP controls.

## Frontend Demo Improvements

The React SOC Assistant page now has clearer prompt presets:

- Latest Critical Alerts
- Explain Alert
- Source Health
- Source Warnings
- Detection Runs
- Failed Jobs
- Recent Activity
- ML Status
- Promotion Gate
- Import Logs
- Import Reviewed Labels
- Run Demo Scenario

Safety badges remain visible:

- Read Only
- Decision Support Only
- Response Automation Disabled
- Simulation Mode

Technical details stay inside a collapsible, scrollable context block so long JSON cannot break the dashboard layout.

## Demo Questions To Ask

Use these during advisor review:

```text
Show latest critical alerts.
Why was alert 1 flagged?
What can I safely do next for this alert?
Which sources have warnings?
Summarize recent detection runs.
Summarize failed jobs.
Explain current ML model status.
Why is the model not production promoted?
How do I import logs?
How do I import reviewed labels?
How do I run a safe demo scenario?
Can you block this IP?
Can you activate the model?
```

Expected safety behavior:

- Helpful questions return concise summaries with citations.
- Unsafe command requests are refused.
- No response action is created.
- No detection run is triggered.
- No model is activated or promoted.
- No raw log context is included by default.
- External provider remains disabled by default.

## Safety Rules

- External LLM calls are disabled by default.
- Raw log context is disabled by default.
- IP redaction is enabled by default.
- Assistant questions are audited.
- The assistant is read-only and cannot mutate ATDR state.
- Response remains simulated and analyst-approved.
- ML remains decision support only.

## Known Limitations

- The assistant is deterministic and template/context based, not a full natural-language reasoning agent.
- Alert and source summaries depend on available normalized fields and parser quality.
- It can explain model status but does not improve or retrain models.
- It can explain how to run workflows but cannot run them.
- External LLM support requires a separate privacy/security review and provider configuration.

## Future External LLM Path

If external LLM support is considered later:

1. Keep it disabled by default.
2. Configure provider/API key only through `.env` or a secret manager.
3. Keep raw log sharing disabled unless explicitly approved.
4. Add redaction and context limits.
5. Add audit logs for provider use.
6. Add tests proving no response/model/data mutation can happen through the assistant.

