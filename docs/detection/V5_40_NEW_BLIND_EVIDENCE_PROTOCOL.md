# v5.40 New Blind Evidence Protocol

## Purpose

This protocol reserves genuinely new evidence for a future one-shot supervised
SOC queue decision. It replaces neither the consumed v5.39 set nor the v5.40
development pool. It is a design only; no pack has been collected.

## Independence Requirements

- Collect only records strictly after the frozen v5.40 development cutoff.
- Use at least two independent real source identities.
- Cover at least three distinct collection windows.
- Target 240 review rows.
- After genuine human review, require at least 100 benign-like, 50 suspicious,
  and 50 malicious rows.
- Exclude exact raw, near-behavior, feature, consumed v5.39-token, development
  time-boundary, and development source-boundary overlap.
- Contain duplicate families within one evidence stratum.

## Required Strata

1. Routine encrypted/QUIC 443 allowed traffic.
2. Incomplete application traffic on port 80.
3. Unknown UDP and TCP traffic.
4. Scan-like source/destination or port diversity.
5. Vendor THREAT records.
6. Routine allowed traffic.
7. Parser-limited evidence.

## Custody Workflow

1. Collect future evidence from approved real sources outside Git.
2. Seal custody, schema, source, time-window, and duplicate-family manifests
   before generating predictions.
3. Freeze at most one candidate configuration using development evidence only.
4. Store predictions separately and hide them from reviewers.
5. Collect genuine human decisions without AI, model, rule, or assisted labels.
6. Validate row counts, class support, overlap exclusions, and reviewer
   contracts before opening metrics.
7. Reveal labels once and run one fixed aggregate evaluation.
8. Require a separate explicit owner decision before any lifecycle change.

## Prohibited Uses

- Do not reuse v5.39 rows, decisions, predictions, errors, or metrics.
- Do not reuse v5.40 development rows.
- Do not place predictions or automatic labels in the reviewer pack.
- Do not call AI-assisted decisions human-reviewed.
- Do not import the pack into training before its final decision is consumed.
- Do not tune features, thresholds, calibration, or model selection after
  opening blind labels.
- Do not activate a model, change rule authority, or enable response based only
  on pack creation or review completion.

## Public Boundary

Tracked documentation may contain only aggregate counts, contract status, and
safe gate results. Raw logs, IP addresses, source names, private paths,
fingerprints, review tokens, predictions, reviewer identities, and decision
digests remain outside Git.

## Current State

`designed_not_collected`. Predictions in pack: false. Automatic labels in
pack: false. Human labels created by v5.40: zero. Import-ready: false.
