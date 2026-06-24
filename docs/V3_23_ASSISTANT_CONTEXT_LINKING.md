# v3.23 Assistant Context Linking And Dashboard Handoff

## Status

Implemented as a safe, read-only usability hardening pass.

## Purpose

v3.23 makes SOC Assistant citations useful inside the React dashboard. Assistant answers already cite alerts, logs, sources, detection runs, operation jobs, ML reports, and docs. This phase adds dashboard links for safe API-backed citations so analysts can move from an assistant answer to the related dashboard context without giving the assistant any ability to execute actions.

## What Changed

- Assistant citation rows now show a compact label, source, reference ID, and an `Open` link when the citation maps to a dashboard route.
- Supported dashboard handoffs:
  - `/api/alerts/{alert_id}` to `/alerts?alert=<id>`
  - `/api/logs/{log_id}` to `/logs?log=<id>`
  - `/api/sources/{source_id}` to `/?source=<id>`
  - `/api/detection/runs/{run_id}` to Overview Operations Health
  - `/api/jobs/{job_id}` to Overview Operations Health
  - `/api/ml/report` and `/api/ml/supervised/report` to `/ml`
- Documentation and code-file citations remain text references.
- Assistant supports `?source=<id>` context in addition to existing `?alert=<id>` context.
- Overview opens the source detail drawer when loaded with `?source=<id>`.
- Overview source detail, Overview Operations Health, and AI Governance include small `Ask Assistant` links for read-only context questions.

## Safety Controls

- No response action execution was added.
- No detection execution was added.
- No label, model, user, source, alert, or log mutation was added.
- External LLM use remains disabled by default.
- Raw log context remains disabled by default.
- IP redaction remains enabled by default.
- Assistant remains decision support only.
- Response automation remains disabled.

## Manual Test Flow

1. Start backend and frontend normally.
2. Open `http://127.0.0.1:5173/assistant`.
3. Ask `Why was alert 1 flagged?` or use a preset.
4. Confirm source references show compact citation rows.
5. Click an alert citation and confirm it opens `/alerts?alert=<id>`.
6. Return to Assistant and click a log/source/ML citation if available.
7. Confirm the assistant page still shows `Read Only`, `Decision Support Only`, `Response Automation Disabled`, and `Simulation Mode`.
8. Confirm no response action is created.

## Known Limitations

- Detection run and operation job links land in Overview Operations Health rather than a dedicated run-history detail page.
- Documentation citations are text references only.
- Source linking opens the Overview source detail drawer when the source ID is available.
- The assistant is deterministic local decision support, not an autonomous SOC agent or production copilot.

