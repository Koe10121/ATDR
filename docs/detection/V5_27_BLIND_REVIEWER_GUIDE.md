# v5.27 Independent Blind Reviewer Guide

## Purpose

This guide is for a qualified human reviewer evaluating the sealed native
PAN-OS blind pack. The reviewer supplies ground truth without seeing ATDR's
frozen rule, IsolationForest, supervised-shadow, or hybrid predictions.

This is an evidence-control procedure. It is not an assisted-labeling task.
Codex, Gemini, rules, heuristics, and models must not complete the human fields.

## Reviewer Package

The evidence custodian retains the sealed pack. The reviewer uses a separate,
ignored working copy created by the v5.28 helper. Provide the reviewer only:

- the v5.28 working copy containing the same protected structured evidence;
  and
- this reviewer guide.

Do not provide the v5.26 prediction lock, queue counts by row, model scores,
diagnostic reports, or any assisted review pack. The prediction lock remains
under separate local custody. Do not edit, rename, or overwrite the sealed
pack.

## Evidence Fields

The following fields are evidence for human interpretation and must not be
edited:

| Field group | Meaning |
| --- | --- |
| `review_token` | Opaque join token. It is not a log ID and must remain unchanged. |
| `evidence_role*` | Confirms that the row belongs to untouched blind validation. |
| `pattern`, `review_priority` | Sampling stratum and review order, not a predicted decision. |
| `event_time_utc`, `log_type`, `subtype` | Event chronology and PAN-OS record class. |
| `application`, `action`, `protocol`, ports, zones | Parsed network-session context. |
| bytes, packets, elapsed time | Session-volume and duration context. |
| application risk, threat severity, end reason | Vendor and session context; none alone proves maliciousness. |
| parser and schema fields | Data-quality context and missing-field state. |
| source aggregate fields | Privacy-safe behavior counts used to assess repetition and diversity. |
| `group_size` | Duplicate or near-duplicate family support. |
| raw/IP inclusion flags | Must remain false. Raw evidence and IP addresses are intentionally absent. |
| assisted/rule fields | Must remain empty for every blind row. |

## Human Fields

Complete these fields only after independently reviewing the structured row:

| Field | Required value |
| --- | --- |
| `human_decision` | One allowed class from the table below. |
| `human_attack_type` | A concise attack family for suspicious/malicious rows; use `none` or leave blank for non-threat rows. |
| `human_confidence` | Integer from 1 to 100 representing reviewer confidence. |
| `human_notes` | At least one clear sentence explaining the evidence and uncertainty. |
| `human_reviewer` | Real human reviewer name or institutional identifier. Do not use an AI/tool identity. |
| `human_reviewed_at` | Timezone-aware ISO 8601 timestamp, for example `2026-08-08T18:00:00+07:00`. |
| `human_reviewed` | Set to `true` only after the row is actually reviewed. |
| `human_must_confirm` | Change to `false` after the human confirms the decision. |
| `import_ready` | Keep `false`. This pack is for locked evaluation, not database import. |

## Decision Classes

| Decision | Use when |
| --- | --- |
| `benign` | Evidence is consistent with expected routine activity and contains no meaningful threat indicator. |
| `benign_unusual` | Activity is unusual but reasonably explained as non-threatening. |
| `needs_context` | Available structured evidence cannot support a defensible benign or threat decision. |
| `suspicious` | Evidence supports analyst investigation but does not justify a malicious determination. |
| `malicious` | Multiple strong signals or authoritative event context support intentional harmful activity. |

Unknown application, application risk, a single uncommon port, or a model-like
pattern is not sufficient by itself for `malicious`. Use `needs_context` when
asset ownership, authorization, intent, or surrounding evidence is missing.

## Private Working-Copy Workflow

The evidence custodian prepares the ignored working copy without opening it in
an assisted-labeling tool:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v528_blind_review_helper --prepare --pretty
```

The qualified reviewer then uses the one-row-at-a-time workflow:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v528_blind_review_helper --interactive --reviewer "<institutional-id>" --pretty
```

The helper saves atomically after each confirmed row and resumes at the next
unreviewed row. It never shows rule, model, IsolationForest, hybrid, Codex, or
Gemini suggestions. It keeps `import_ready=false` and never imports labels.

Safe progress can be checked without exposing predictions or calculating
accuracy:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v528_blind_review_helper --status --pretty
```

## Validation

Return only the reviewed working copy to the evidence custodian. The custodian
runs the locked evaluator against that copy:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v527_blind_review_evaluation --review-file ".\ml_baseline_reviews\v5_28_blind_human_review_working.csv" --pretty
```

The validator rejects:

- missing or false review flags;
- invalid decisions, confidence, timestamps, notes, or reviewer identity;
- duplicate or unknown review tokens;
- AI-, assisted-, rule-, heuristic-, or model-generated review provenance;
- prediction-exposed rows or modified lock identity;
- rows still marked as requiring human confirmation; and
- rows marked import-ready.

Metrics remain unavailable until at least 20 legitimate reviews and both
non-threat and review-queue ground-truth classes exist. The evaluator joins
accepted human decisions to the existing frozen predictions and never reruns
the model.

## Custody Rule

After evaluation, the sealed pack and its working copy are consumed. Neither
may be used to tune, select, calibrate, or repair a model. Any repaired
candidate requires a newly preregistered untouched blind pack.
