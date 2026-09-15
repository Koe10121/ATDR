# ATDR Final Slide Asset Guide

## Asset Policy

- Keep working screenshots outside Git.
- Commit an image only after it is sanitized and explicitly approved.
- Do not capture `.env`, passwords, tokens, private paths, private logs,
  personal email, DB files, model artifacts, or review CSVs.
- Use official university branding only from an approved source.
- Do not redraw university, firewall-vendor, or partner logos.

## Recommended Asset Inventory

### 1. Dashboard Overview Screenshot

**Use on**

- Slide 1
- Slide 17

**Must show**

- Final Controlled Validation Candidate
- Decision Support Only
- Response Automation Disabled
- Not Production Promoted

### 2. Architecture Diagram

**Use on**

- Slide 5

**Create with**

Editable PowerPoint shapes and attached connectors.

**Required nodes**

- Sources
- Raw evidence
- Parser profiles
- Normalized logs
- Detection layers
- Alerts/cases
- Analyst
- Simulated response
- Audit

### 3. Source Health Screenshot

**Use on**

- Slide 6
- Slide 16

**Must show**

- `final-demo-firewall-live`
- healthy status
- parser profile
- parse success/failure
- recent run

### 4. Parser Profile Diagram

**Use on**

- Slide 7

**Create with**

Three editable lanes:

- Palo Alto
- Generic syslog
- Raw fallback

All lanes must preserve raw evidence.

### 5. Detection-Layer Diagram

**Use on**

- Slide 8

**Required signals**

- rules
- behavior windows
- IsolationForest anomaly
- supervised SOC triage
- hybrid risk
- analyst decision

Use a dashed line for advisory ML signals and no arrow from ML directly to
response.

### 6. AI Review Workflow Diagram

**Use on**

- Slide 9

**Required stages**

- assisted labels
- human review
- candidate training
- independent validation
- governance decision
- active-learning feedback

### 7. Alert And Why-Flagged Screenshot

**Use on**

- Slide 10
- Slide 16

**Must show**

- critical port-scan alert
- risk/severity
- `Why flagged?`
- evidence summary
- recommended next check

### 8. Deduplication Flow

**Use on**

- Slide 11

**Create with**

Ten event marks -> one alert -> one case.

Annotate:

- occurrence count
- related-log count
- raw evidence retained

### 9. Case Screenshot

**Use on**

- Slide 11
- Slide 16

**Must show**

- related alerts/logs
- source IP
- first/last seen
- top ports/actions
- analyst focus

### 10. Safety Boundary Diagram

**Use on**

- Slide 12

**Create with**

```text
Alert -> Analyst -> Confirmation -> Protected-IP Check
-> Simulated Record -> Audit
```

Add a red stop boundary labeled:

`Real firewall blocking disabled`

### 11. Validation Timeline

**Use on**

- Slide 13

**Required milestones**

- scenario validation
- generalization
- layered comparison
- E2E validation
- reviewed-label improvement
- independent validation
- fresh blind holdout
- controlled source acceptance

### 12. Final Metric Chart

**Use on**

- Slide 14

**Data**

- Precision: 0.8906
- Recall: 0.9459
- Threat F1: 0.9174
- Suspicious recall: 0.8556
- Malicious recall: 0.9000
- Benign-like FPR: 0.1303
- Controlled FPR target: 0.15

### 13. Confidence And Source-Acceptance Graphic

**Use on**

- Slide 15

**Confidence**

- ECE: 0.0757
- Brier: 0.0751
- Max gap: 0.1878

**Source acceptance**

- 28 raw
- 25 parsed
- 3 failures
- 2 alerts
- 2 cases
- 0 automatic responses

### 14. Four-Step Demo Strip

**Use on**

- Slide 16

**Sequence**

1. healthy source
2. normalized logs
3. alert / Why flagged
4. case / response safety

### 15. Readiness Lockup

**Use on**

- Slide 17
- Slide 20

**Exact text**

- Final Controlled Validation Candidate
- Decision Support Only
- Response Automation Disabled
- Not Production Promoted
- Real firewall blocking disabled

### 16. Limitation Matrix

**Use on**

- Slide 18

**Groups**

- real-source evidence
- infrastructure
- identity/security
- operational response

### 17. Future Roadmap

**Use on**

- Slide 19

**Stages**

1. controlled real-device pilot
2. shared-lab hardening
3. production governance and approved connector design

## Backup Evidence Assets

- Release-gate summary screenshot
- Performance-smoke summary screenshot
- IAM/RBAC matrix excerpt
- Database entity diagram
- Confusion matrix or class metrics
- Scenario catalog

## PowerPoint Asset Folder

Recommended local folder:

```text
<SCREENSHOT_OUTPUT_DIR>\
  01-overview\
  02-source\
  03-investigation\
  04-alert\
  05-case\
  06-response-audit\
  07-ai-governance\
  08-verification\
  selected\
```

Keep this folder outside the repository unless the images are sanitized and
explicitly approved for version control.

