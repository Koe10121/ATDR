# v3.73 Detection/ML Governance Dashboard Integration

## Status

Implemented as a read-only governance visibility layer.

## Purpose

v3.72 added a unified Detection/ML productization evaluator, but it was only available from the command line. v3.73 exposes the same safe status through authenticated backend API and a compact AI Governance dashboard panel.

## What Changed

- Added `GET /api/dashboard/detection-ml-productization`.
- The endpoint requires analyst/admin authentication.
- The endpoint runs the v3.72 evaluator in fast mode by default.
- The React AI Governance page now shows:
  - readiness decision
  - required check count
  - rule contract status
  - scenario check mode
  - supervised output policy status
  - safe training target status
  - lightweight label counts
  - response-action side-effect count
- Detailed checks are behind a collapsible section.

## Safety Behavior

- No labels are written.
- No models are activated or promoted.
- No model artifacts are written.
- No response actions are created.
- No real firewall blocking is enabled.
- Raw logs are not included.
- Scenario validation is skipped by default for normal dashboard load speed.

## Manual Check

1. Start backend and frontend normally.
2. Open AI Governance.
3. Confirm the Detection / ML Productization panel appears.
4. Confirm readiness, rule contract, output policy, training target, and safety status are visible.
5. Confirm no response automation or production promotion is shown.

## Commands

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_detection_ml_productization --pretty
```

Optional temporary-DB scenario mode:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.evaluate_detection_ml_productization --include-scenarios --scenario normal_allowed_traffic --scenario port_scan_like_traffic --pretty
```

## Remaining Work

- Continue improving detection/ML product behavior only after evidence shows a concrete gap.
- Keep model activation and response automation separate from dashboard visibility.
- Real-source and MFU IAM live validation remain separate productization tracks.
