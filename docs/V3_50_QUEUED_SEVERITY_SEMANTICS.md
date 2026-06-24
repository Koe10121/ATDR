# v3.50 Queued Severity Target Semantics And Feature Support Audit

## Status

v3.50 audits why v3.49 downstream severity classification is unstable after the repaired queue target. It is diagnostic only.

## Purpose

v3.48 showed that repaired queue admission is stable. v3.49 showed that severity classification after queue admission is not stable. v3.50 checks whether the queued severity targets are semantically consistent and learnable before trying another model.

The audit checks:

- queued severity target distribution
- repaired-queue rows that still map to `non_threat`
- label/review support by severity class
- train/test support by split
- pattern, traffic-family, evidence-bucket, and source ambiguity
- numeric feature separability
- no-side-effect safety

## Result

- Rows audited: 2252
- Assessment: `diagnostic_only`
- Checks passed: `7 / 12`
- Recommendation: repair queued severity target semantics and evidence features before another downstream severity model pass.

Severity distribution among repaired-queue rows:

| Target | Rows |
| --- | ---: |
| unusual_needs_review | 916 |
| evidence_backed_suspicious | 498 |
| malicious_high_confidence | 389 |
| non_threat | 449 |

Important finding:

- `449` repaired-queue rows, or `19.94%`, are admitted to the queue while their downstream SOC target still maps to `non_threat`.
- This creates a target mismatch: the queue says "review this," while the severity layer is asked to learn a class that the v3.49 downstream severity decision path does not explicitly model as a queued severity output.

Main blockers:

- Queued non-threat target mismatch: `19.94%`, target `<=5%`
- Pattern ambiguity row share: `0.7278`, target `<=0.45`
- Traffic-family ambiguity row share: `1.0`, target `<=0.60`
- Evidence-bucket ambiguity row share: `0.9987`, target `<=0.65`
- Time-split severity-rate shift: `0.4461`, target `<=0.25`

Support is not the primary blocker:

- Minimum train support across splits: 171
- Minimum test support across splits: 67
- Minimum reviewed support by severity class: 389

Feature support exists but does not solve the semantic mismatch:

- 15 numeric features have minimum pairwise effect size `>=0.5`
- Strongest separators include `unknown_app_flag` and source allow-count features
- The labels/patterns remain too ambiguous for stable severity classification despite useful numeric signal

## Interpretation

The repaired queue target is still useful as an admission layer. The instability is now more clearly located in the downstream severity target definition.

ATDR should not activate a severity model yet. The next phase should decide how queued rows that are admitted for analyst review but still semantically look `non_threat` should be represented. Options include:

- add a queued low-risk review class, such as `queue_low_confidence_review`
- keep queue admission and severity ranking as separate outputs
- adjust repaired queue rules so queue admission does not promote rows that remain semantically `non_threat`
- refine severity target mapping so promoted rows become `unusual_needs_review` only when evidence supports analyst attention

## Safety

- Production promoted: false
- Model activated: false
- Model artifact written: false
- Labels written: false
- Response automation allowed: false
- Real firewall blocking: false

## Next Recommended Phase

v3.51 should repair the queue/severity target interface before another classifier pass. The best next focus is not manual review and not another threshold tweak; it is a target architecture decision for admitted-but-low-severity rows.
