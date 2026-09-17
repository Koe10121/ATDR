# ATDR Presentation Brief

## What The System Does

ATDR collects firewall/syslog logs, preserves raw evidence, normalizes supported
PAN-OS and generic formats, runs explainable rule detection, displays alerts and
related evidence, recommends analyst checks, and offers a read-only SOC
Assistant with optional Gemini synthesis.

## Architecture

- MFU Node/Vue shell: school sign-in and one-time secure handoff.
- FastAPI: ingestion, detection, investigation, Assistant, and operations APIs.
- React: analyst dashboard.
- SQLAlchemy/Alembic: SQLite locally, PostgreSQL for approved shared deployment.
- Python/scikit-learn: advisory anomaly and supervised model workflows.

## Detection Truth

- Nineteen deterministic rules are active and alert-authoritative.
- Rules use normalized fields, time/source correlation, scoring, grouping, and
  deduplication.
- IsolationForest highlights unusual behavior but does not prove a threat.
- The current anomaly rate is 2.36% among scored rows; 41.47% of stored rows
  have scores. The older 0.98% figure was all-row prevalence, not 98%.
- The supervised pipeline is implemented and rigorously governed, but the
  latest immutable evaluation selected no qualified candidate.
- Supervised runtime therefore fails closed as `unqualified`.

## Why An Alert Was Flagged

The alert view shows the matching rule and signals, evidence strength, parser
caveats, related logs, source context, ATT&CK-style mapping, and recommended
verification steps. Controlled suites validate behavior, but they are not
presented as real-world accuracy.

## SOC Assistant

Assistant facts come from bounded ATDR database/service context and approved
runbook guidance. Gemini can make the answer shorter and easier to read; it is
not the source of alert facts. Answers retain citations, raw logs are excluded
by default, IPs are redacted, and deterministic fallback handles provider
failure. The Assistant cannot execute actions.

## Safe Demonstration

Preflight the complete disposable workflow:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v5631_advisor_demo_acceptance --use-temp-db --execute-provider-probe --pretty
```

Require 10/10 stages and 24/24 workflow checks.

1. Start with `scripts/start_system.cmd` and sign in through the MFU shell.
2. Show Overview and source/parser health.
3. Open an alert and explain its evidence and next checks.
4. Ask the SOC Assistant why the alert was flagged, then ask a scoped follow-up.
5. Show AI Governance: rules authoritative, ML advisory/unqualified.
6. Show Response & Audit: simulation only and analyst-confirmed.

Current proof points: deterministic scenarios `24/24`, layered detection
`288/288`, Assistant QA `30/30` plus follow-up continuity, and a bounded live
Gemini structured probe with raw-log context disabled.

## Honest Finish Line

ATDR is a controlled local release candidate, not certified production
software. Remaining acceptance requires university IAM owners, institutional
Gemini governance, an approved shared host, a teammate clean-room exercise, and
independent physical-source detection evidence.
