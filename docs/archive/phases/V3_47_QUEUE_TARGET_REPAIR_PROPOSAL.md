# v3.47 Queue Target Repair Proposal

## Status

v3.47 is complete as a diagnostic-only queue-target repair proposal. It does not write labels, activate models, write active model artifacts, enable automatic response, or change detection behavior.

## Purpose

v3.46 showed that the current queue target has useful numeric separators but high app/family ambiguity and time-split drift. v3.47 proposes conservative target repair rules for analysis:

- Preserve `needs_review` when rule, anomaly, scan, or strong evidence exists.
- Propose demoting low-signal web/utility rows from `needs_review` to `non_threat`.
- Propose promoting `non_threat` rows with strong evidence to `needs_review`.

These are proposal rules only. They are not human-reviewed labels and are not import-ready.

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Labels written: false
- Response automation allowed: false
- Real firewall blocking: false
- Proposal CSV import-ready: false

## Current Diagnostic Result

- Rows audited: 2672
- Current queue target distribution: `needs_review=1859`, `non_threat=813`
- Proposed queue target distribution: `needs_review=2252`, `non_threat=420`
- Proposed changed rows: 505 / 2672 (`18.9%`)
- Proposed promotions to `needs_review`: 449 strong-evidence `non_threat` rows
- Proposed demotions to `non_threat`: 56 low-signal web/utility or low-context service rows
- Pattern ambiguity: `0.4308` -> `0.3990`
- Traffic-family ambiguity: `0.8046` -> `0.7186`
- Max split drift: `0.2636` -> `0.2193`
- Assessment: `diagnostic_only`, 7 / 7 checks passed
- Proposal CSV: `ml_baseline_reviews/v3_47_queue_target_repair_proposals_20260623T095742Z.csv`
- Report: `ml_baseline_reviews/v3_47_queue_target_repair_proposal_20260623T095742Z.md`

The proposal improves ambiguity and split drift, but it shifts many strong-evidence rows into the review queue. The next phase should evaluate whether this repaired target trains a more stable diagnostic SOC queue model before any label import, activation, or promotion is considered.

## Expected Interpretation

The repair proposal reduced ambiguity and split drift, so the next phase can evaluate a diagnostic model against the proposed target. This is still not a human-reviewed label set, not an import-ready label file, and not a production model decision.
