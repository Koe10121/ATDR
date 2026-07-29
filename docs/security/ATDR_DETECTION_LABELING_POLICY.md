# ATDR Detection Labeling Policy

Version: `v4.9`

## Purpose

This policy protects supervised-learning evidence integrity. Codex, Gemini, rules, anomaly scores, and existing models may help prioritize or suggest, but they cannot create human-reviewed truth.

## Label Classes

- `benign`: expected activity with adequate context.
- `benign_unusual`: unusual but plausibly legitimate activity with supporting context.
- `needs_context`: evidence is insufficient for a defensible disposition.
- `suspicious`: supported concern that requires investigation.
- `malicious`: strong multi-signal evidence supports a threat conclusion.

## Provenance Rules

| Provenance | May be trainable | May be called human-reviewed | Import behavior |
| --- | --- | --- | --- |
| Human manual/reviewed | yes, subject to latest-label and quality rules | yes | explicit authenticated import/review only |
| Rule-assisted suggestion | only under an explicitly approved weak-label experiment | no | never automatic |
| ML-assisted suggestion | only under an explicitly approved weak-label experiment | no | never automatic |
| Hybrid/LLM suggestion | no by default | no | never automatic |
| Provider benchmark ground truth | evaluation only unless separately governed | no | never inserted into operational labels automatically |
| Synthetic scenario expectation | regression testing only | no | not import-ready |

The `reviewed` flag does not erase `label_source`. Reports must preserve and disclose the original source distribution. v4.9 consumes the latest trainable row per normalized log with reviewed flag filtering while preserving original label provenance; it authors zero labels and marks zero AI-assisted labels as human-reviewed.

## Review Requirements

- Reviewers must use raw-evidence references, normalized fields, parser quality, rule matches, source/time context, and available business context.
- Ambiguous evidence remains `needs_context`.
- `malicious` requires strong multi-signal evidence; vendor risk or model confidence alone is insufficient.
- Existing protected manual/reviewed labels cannot be silently overwritten.
- Duplicate label history remains audit evidence, but only the latest eligible row per normalized log enters a training view.

## Leakage And Split Rules

- Exact raw fingerprints, normalized-log IDs, near-behavior fingerprints, feature fingerprints, source groups, and time overlap must be audited.
- Fit, calibration, threshold-selection, and final-test roles must be disjoint.
- Final-test and locked external labels cannot influence feature engineering, weights, thresholds, candidate selection, or calibration.
- Group/source-aware validation must be used where evidence supports it. A zone-held-out proxy must be named as a proxy when only one device exists.

## AI-Assisted Review Boundary

AI may create an `ASSISTED_PREVIEW` with suggested decision, confidence, reason, and review priority. It must set `human_must_confirm=true`, remain ignored/private, and must not fill or import a human decision automatically. Trust in an assistant does not convert its output into human ground truth.

## Safety

No label or model output can trigger automatic response, real firewall blocking, model activation, or production promotion. Any future exception requires a separate approved safety design and independent evidence.
