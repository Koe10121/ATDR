# v3.25 SOC Assistant Investigation Brief Builder

## Status

Implemented as a read-only SOC Assistant usability upgrade.

## Purpose

v3.25 helps analysts turn existing ATDR evidence into a compact investigation brief for alerts, logs, sources, and computed case/group context. The brief is designed for analyst handoff, advisor review, or report preparation without creating notes, changing alert status, running detection, or executing response actions.

## What Changed

- Added deterministic investigation-brief routing in the assistant service.
- Added support for alert, log, source, and computed case/group brief questions.
- Added source-id parsing for questions such as `Create investigation brief for source 1`.
- Brief answers are organized into:
  - Summary
  - What happened
  - Why flagged or not flagged
  - Evidence to mention
  - Related context
  - Safe analyst next steps
  - Limitations
  - Citations
- React SOC Assistant now includes an `Investigation Brief` preset group.
- Contextual Assistant deep links now show a `Generate Brief` button when alert/log/source/case context is present.
- Assistant responses can be copied with a `Copy brief` action when supported by the browser.

## Safety Controls

- The assistant remains read-only.
- No response action execution was added.
- No detection execution was added.
- No label, model, alert, log, source, user, or database mutation was added.
- No note or report artifact is automatically saved.
- Raw log context remains disabled by default.
- Raw log line fields are stripped from assistant response details.
- External LLM use remains disabled by default.
- IP redaction remains enabled by default.
- ML remains decision support only.
- Response automation remains disabled.

## Manual Test Flow

1. Start backend and frontend normally.
2. Open `/assistant`.
3. Confirm the `Investigation Brief` preset group is visible.
4. Click `Alert Brief`.
5. Confirm the answer includes brief sections and citations.
6. Open `/assistant?alert=1`, `/assistant?log=1`, `/assistant?source=1`, or `/assistant?case=<case_id>`.
7. Click `Generate Brief`.
8. Confirm the question is context-specific and the response stays read-only.
9. Click `Copy brief` and confirm the copy status appears.
10. Confirm no response action, detection run, model run, or data mutation is created by the assistant.

## Known Limitations

- Briefs are deterministic summaries of current ATDR context, not human-approved incident reports.
- Computed case/group briefs are based on current grouping logic and do not create persisted incident records.
- Dedicated run/job detail pages remain future work.
- External LLM integration, raw-log sharing, action execution, model activation, and persistent notebook features remain future reviewed work.
