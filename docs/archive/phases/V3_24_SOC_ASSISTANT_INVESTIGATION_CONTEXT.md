# v3.24 SOC Assistant Investigation Context Upgrade

## Status

Implemented as a read-only assistant usability hardening pass.

## Purpose

v3.24 improves the SOC Assistant for day-to-day investigation flow. Analysts can now ask about a specific alert, related log, source, or computed case/group from the dashboard and receive a structured answer grounded in existing ATDR evidence.

## What Changed

- Assistant chat requests now accept optional `alert_id`, `log_id`, `source_id`, and `case_id` context.
- Alert answers include compact related-log summaries and citations to the linked logs.
- Log answers explain why a log was flagged or not flagged, list normalized signals, linked alerts, parser notes, source context, and safe next steps.
- Source answers include health, quality, parser notes, and recent source-linked alert references.
- Computed alert case/group answers summarize related alert count, related logs, attack types, source/destination context, ports/actions, and recommended analyst focus.
- Assistant citations now include `/api/alerts/cases` as a dashboard-safe Alerts-page handoff.
- React dashboard adds navigation-only Ask Assistant links from:
  - alert detail
  - alert related-log chips
  - Log Explorer log detail
  - active case grouping cards
- Assistant page shows alert/log/source/case context badges when opened through deep links.

## Safety Controls

- The assistant remains read-only.
- No response action execution was added.
- No detection execution was added.
- No label, model, source, alert, log, user, or data mutation was added.
- Raw log context remains disabled by default.
- Raw line excerpts are stripped from assistant context.
- External LLM use remains disabled by default.
- IP redaction remains enabled by default.
- ML remains decision support only.
- Response automation remains disabled.

## Manual Test Flow

1. Start backend and frontend normally.
2. Open Alerts and select an alert.
3. Click `Ask Assistant`.
4. Confirm `/assistant?alert=<id>` opens with an alert context badge.
5. Return to the alert and click `Ask Assistant` beside a related log.
6. Confirm `/assistant?alert=<id>&log=<id>` opens with alert and log context badges.
7. Open Investigation / Log Explorer, select a log, and click `Ask Assistant about this log`.
8. Confirm the answer explains why the log was flagged or not flagged.
9. Open an active case group and click `Ask Assistant about case`.
10. Confirm the answer says it is a computed grouping and no action was executed.

## Known Limitations

- Case/group summaries use computed alert grouping only; no persisted incident record is created.
- Dedicated run/job detail pages remain future work.
- Assistant output is deterministic local decision support, not an autonomous SOC agent.
- External LLM integration, raw-log sharing, action execution, and model activation remain future reviewed work.
