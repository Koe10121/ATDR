# ATDR Final Presentation Design Guide

## Purpose

This guide converts `docs/FINAL_PRESENTATION_SLIDE_CONTENT.md` into a polished,
editable PowerPoint defense deck. The deck should look like an engineering
validation presentation, not a marketing pitch.

## Deck Format

- Slide size: 16:9 widescreen.
- Core slide count: 20.
- Optional backup slides: 4-6.
- Recommended presentation length: 10-12 minutes plus demonstration and Q&A.
- Use editable PowerPoint text, shapes, tables, and diagrams whenever possible.
- Use sanitized dashboard screenshots only.

## Required Status Language

Use these phrases exactly:

- `Final Controlled Validation Candidate`
- `Decision Support Only`
- `Response Automation Disabled`
- `Not Production Promoted`
- `Real firewall blocking disabled`

Do not use:

- production ready
- autonomous blocking
- guaranteed detection
- deployment approved
- real-world accuracy

## Visual Direction

### Overall Style

Use a balanced technical-defense style:

- dark ink title and section slides;
- light neutral evidence slides;
- cyan for detection and system flow;
- amber for analyst review and limitations;
- red only for blocked, denied, or risk states;
- green only for passed checks or healthy sources.

The visual system should feel precise, calm, and evidence-led. Avoid decorative
gradients, glowing effects, oversized rounded cards, and generic cybersecurity
stock imagery.

### Color Palette

| Role | Color | Suggested Hex |
| --- | --- | --- |
| Deep background | Ink | `#0B1220` |
| Secondary background | Graphite | `#151F2E` |
| Light background | Cool white | `#F5F7FA` |
| Primary text on light | Charcoal | `#172033` |
| Primary text on dark | White | `#F8FAFC` |
| Detection accent | Cyan | `#16B8D4` |
| Review/caution | Amber | `#F3B43F` |
| Passed/healthy | Green | `#2DBE7F` |
| Risk/denied | Red | `#E25555` |
| Neutral lines | Steel | `#A8B3C4` |

Do not let cyan or dark blue dominate every slide. Use white evidence slides,
amber review callouts, green validation marks, and red safety boundaries to
create visual rhythm.

### Typography

Recommended PowerPoint-safe fonts:

- Titles: Aptos Display Semibold or Segoe UI Semibold.
- Body: Aptos or Segoe UI.
- Code/commands: Cascadia Mono or Consolas.

Recommended sizes:

- Cover title: 30-38 pt.
- Claim title: 24-30 pt.
- Section kicker: 10-12 pt, uppercase.
- Body: 16-20 pt.
- Diagram labels: 13-16 pt.
- Metric values: 28-40 pt.
- Source/footer: 9-10 pt.

Use sentence case for titles. Avoid all-caps paragraphs.

## Slide Grammar

Every core slide should contain:

1. a small role kicker;
2. a claim-oriented title;
3. one dominant proof object;
4. no more than three supporting points;
5. a quiet evidence/source footer.

Example:

- Kicker: `VALIDATION`
- Claim: `The frozen candidate retained strong recall while bringing benign FPR below the controlled target.`
- Proof object: metric chart and threshold line.

## Layout Families

Use at least six layout families across the 20 slides:

1. Full-bleed title/section slide.
2. Architecture or workflow diagram.
3. Screenshot with annotated evidence rail.
4. Metric chart with interpretation callout.
5. Timeline with milestone evidence.
6. Two-column scope or risk comparison.
7. Safety boundary diagram.
8. Closing claim with status lockup.

Do not use the same layout for more than two consecutive slides. Limit
card-grid layouts to two slides in the core deck.

## Slide-By-Slide Design Plan

### Slide 1: Title

**Claim title**

`ATDR combines layered detection with analyst-controlled response.`

**Layout**

Dark cover with one sanitized Overview screenshot cropped as a right-side or
full-width background detail. Keep title and identity text outside a card.

**Visual weight**

Visual-heavy.

### Slide 2: Problem Background

**Claim title**

`Firewall evidence is abundant, but analyst attention is limited.`

**Layout**

Funnel diagram: raw logs -> candidate events -> alerts -> analyst cases.

**Visual weight**

Visual-heavy.

### Slide 3: Project Objectives

**Claim title**

`The design goal was trustworthy triage, not autonomous enforcement.`

**Layout**

One central analyst node with six surrounding objectives connected by clear
lines.

**Visual weight**

Balanced.

### Slide 4: Scope And Limitations

**Claim title**

`The validated scope ends at controlled lab decision support.`

**Layout**

Two columns: validated now and future production work. Use a strong vertical
boundary line.

**Visual weight**

Explanation-heavy.

### Slide 5: System Architecture

**Claim title**

`Every alert remains traceable from source evidence to analyst action.`

**Layout**

Left-to-right architecture:

```text
Sources -> Raw Evidence -> Parser -> Normalized Logs
        -> Detection Layers -> Alert/Case -> Analyst
        -> Simulated Response -> Audit
```

Use attached directional connectors. Put technologies below their relevant
layer rather than in a separate logo row.

**Visual weight**

Visual-heavy.

### Slide 6: Log Ingestion And Source Management

**Claim title**

`Source health makes ingestion quality visible before detection is trusted.`

**Layout**

Large Source Detail screenshot with a compact right-side explanation rail.

**Screenshot**

Healthy `final-demo-firewall-live` source.

**Visual weight**

Visual-heavy.

### Slide 7: Parser And Data Quality

**Claim title**

`Malformed input is preserved and reported instead of crashing the pipeline.`

**Layout**

Three parser lanes: Palo Alto, generic syslog, raw fallback. All converge on
raw preservation; structured outputs differ.

**Visual weight**

Visual-heavy.

### Slide 8: Detection Layers

**Claim title**

`Four complementary signals support one explainable triage decision.`

**Layout**

Stacked or converging diagram for rules, behavior windows, anomaly scoring, and
supervised triage. The analyst sits after hybrid risk, not below an automatic
action arrow.

**Visual weight**

Visual-heavy.

### Slide 9: AI And Human Review Workflow

**Claim title**

`Human review and independent validation constrain the supervised workflow.`

**Layout**

Circular workflow:

```text
Assisted labels -> Human review -> Candidate training
-> Independent validation -> Governance decision -> New review priorities
```

**Screenshot**

Optional small AI Governance crop showing reviewed/weak labels.

**Visual weight**

Balanced.

### Slide 10: Alert Explanation And Investigation

**Claim title**

`The analyst can see why the port-scan alert was raised.`

**Layout**

Alert detail screenshot occupying two thirds of the slide. Use three numbered
annotations: detection source, `Why flagged?`, related evidence.

**Screenshot**

Critical port-scan alert detail.

**Visual weight**

Visual-heavy.

### Slide 11: Alert Deduplication And Cases

**Claim title**

`Repeated evidence becomes one richer alert and one investigation context.`

**Layout**

Ten event marks -> one alert with occurrence count -> one case. Add the case
drawer screenshot on the right.

**Visual weight**

Visual-heavy.

### Slide 12: Simulated Response And Safety

**Claim title**

`Detection can recommend action, but only an authorized analyst can approve a simulation.`

**Layout**

Horizontal safety sequence:

```text
Alert -> Analyst note -> Confirmation -> Protected-IP check
-> Simulated record -> Audit
```

Place a red stop boundary before real firewall enforcement.

**Screenshot**

Response confirmation or protected-IP denial.

**Visual weight**

Balanced.

### Slide 13: Validation Journey

**Claim title**

`Each validation phase addressed a different failure mode.`

**Layout**

Timeline from v0.7 to v2.1b. Group phases into scenario coverage, AI quality,
independent validation, and final controlled acceptance.

**Visual weight**

Visual-heavy.

### Slide 14: Final Blind Holdout Results

**Claim title**

`The frozen candidate achieved 0.9174 threat F1 with benign FPR at 0.1303.`

**Layout**

One horizontal metric chart:

- precision 0.8906
- recall 0.9459
- F1 0.9174
- suspicious recall 0.8556
- malicious recall 0.9000

Show benign FPR separately against the `<= 0.15` controlled target.

**Visual weight**

Data-heavy.

### Slide 15: Confidence And Controlled Source Results

**Claim title**

`Calibration and source acceptance tested trust beyond classification metrics.`

**Layout**

Left: confidence metrics. Right: controlled-source pipeline with 28 raw,
25 parsed, 3 failures, 2 alerts, 2 cases, 0 automatic responses.

**Visual weight**

Data-heavy.

### Slide 16: Final Dashboard Demonstration

**Claim title**

`Ten synthetic scan events produce one explainable case without automatic response.`

**Layout**

Four-image sequence:

1. healthy source;
2. filtered logs;
3. alert/Why flagged;
4. case or audit.

**Visual weight**

Visual-heavy.

### Slide 17: Current Readiness

**Claim title**

`ATDR is ready for controlled academic demonstration, not production deployment.`

**Layout**

Large status lockup:

- Final Controlled Validation Candidate
- Decision Support Only
- Response Automation Disabled
- Not Production Promoted
- Real firewall blocking disabled

**Visual weight**

Explanation-heavy.

### Slide 18: Limitations

**Claim title**

`The remaining gaps are operational and real-world validation gaps.`

**Layout**

Risk matrix with four groups: data, infrastructure, security, and operations.

**Visual weight**

Explanation-heavy.

### Slide 19: Future Work

**Claim title**

`The next meaningful test is a controlled real-device pilot, not more tuning on the same scenarios.`

**Layout**

Three-stage roadmap:

1. real-source pilot;
2. shared-lab hardening;
3. production governance and approved connector design.

**Visual weight**

Balanced.

### Slide 20: Conclusion

**Claim title**

`ATDR demonstrates explainable AI-assisted triage while preserving human control.`

**Layout**

Dark closing slide with the end-to-end flow and final status. Avoid adding new
metrics here.

**Visual weight**

Visual-heavy.

## Screenshot Treatment

- Capture at 1440x900 or higher.
- Crop to the specific proof, not the entire browser window.
- Remove browser bookmarks, unrelated tabs, notifications, and usernames when
  unnecessary.
- Use a 1 px neutral border and a very soft shadow.
- Add no more than three numbered annotations per screenshot.
- Never blur the primary evidence needed for the slide.
- Do not show tokens, passwords, private file paths, `.env`, real log payloads,
  or personally identifying data.

## Diagram Guidance

Use PowerPoint-native shapes and connectors:

- rounded rectangles only for real system components;
- cylinders for databases;
- solid arrows for data flow;
- dashed arrows for optional/advisory signals;
- red stop line for disabled real enforcement;
- amber human-review diamond before response.

Every arrow must attach to the correct source and destination. Avoid decorative
arrows.

## Chart Guidance

- Use direct labels rather than legends when possible.
- Keep all metrics in decimal form or all in percentage form, not mixed.
- Include the controlled target when discussing FPR.
- Do not use 3D charts.
- Do not truncate axes to exaggerate differences.
- Add a small note: `Controlled synthetic/reviewed validation; not production accuracy.`

## Footer And Evidence Notes

Use a quiet footer:

```text
Source: ATDR controlled validation artifacts and repository documentation, v2.1b.
```

For metric slides:

```text
Fresh blind holdout: 700 rows, 7 sources, 16 scenario families. No threshold tuning on blind labels.
```

## Official Asset Policy

- Use the official university logo only if supplied from an approved source.
- Do not redraw or approximate the university logo.
- Do not invent partner, firewall vendor, or product marks.
- ATDR may be represented using text and the established dashboard palette.

## Final PowerPoint QA

- [ ] 20 core slides are present.
- [ ] No three consecutive slides share the same layout.
- [ ] Every slide has a claim and a proof object.
- [ ] All screenshots are sanitized and readable.
- [ ] Architecture connectors attach correctly.
- [ ] Metric values match the final validated status.
- [ ] Safety wording is exact.
- [ ] No text overflows.
- [ ] No source/footer is smaller than 9 pt.
- [ ] Slide 17 clearly prevents a production-readiness interpretation.
- [ ] The deck can be presented without reading paragraphs from the slide.

