# v3.61 SOC Assistant Presentation Hardening

## Status

Implemented as a read-only assistant and dashboard-preset hardening pass for professional SOC walkthroughs.

v3.61 improves the SOC Assistant's demo reliability without changing detection logic, ML logic, response safety, model activation, labels, or database schema.

## What Changed

- Added a **SOC Playbook** preset group in the SOC Assistant:
  - Latest Critical Alert
  - Explain Alert
  - Investigation Brief
  - Source Health
  - AI Governance Summary
  - Controlled Validation Scenario
  - Response Safety
- Improved deterministic assistant fallbacks when demo context is missing:
  - no matching/open alert
  - missing source ID
  - missing supervised-output policy report
- Added a direct response-safety answer for questions about blocking, automation, and what the assistant is allowed to do.
- Expanded unsafe-request detection for raw-log exposure and account/user mutation requests.
- Preserved citations and structured answer sections for presentation-friendly explanations.

## SOC Playbook Behavior

The assistant can now reliably answer analyst walkthrough questions such as:

- Explain the latest critical alert.
- Why was alert 1 flagged?
- Create investigation brief for alert 1.
- Summarize source health.
- What supervised ML output is safe?
- How do I run a controlled validation scenario?
- What are response safety rules?

If no alert is available, the assistant does not guess. It suggests using the Alerts page or running the safe port-scan scenario:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_source_scenario --scenario port_scan_like_traffic --source-name controlled-validation-firewall --source-type firewall --parser-profile palo_alto --run-detection --pretty
```

## Safety

The assistant remains:

- read-only
- deterministic/local by default
- external LLM disabled by default
- raw-log context disabled by default
- IP-redacted by default
- audited

The assistant cannot:

- execute response actions
- run detection
- import/review labels
- activate/promote models
- enable automation
- enable real firewall blocking
- expose raw logs
- create/delete/disable users
- send email

No response action, detection run, model run, label change, user/account change, model activation, production promotion, or real firewall action is introduced by v3.61.

## Verification Scope

Expected checks:

- Backend assistant tests cover SOC playbook questions, missing-context fallbacks, unsafe raw-log refusal, and no side effects.
- Playwright smoke test covers the SOC Playbook preset group and long-response containment.
- Standard release gates remain required before handoff.
