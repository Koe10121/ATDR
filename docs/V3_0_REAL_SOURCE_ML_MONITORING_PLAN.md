# ATDR v3.0 Real-Source ML Monitoring Plan

The supervised model remains SOC triage decision support. v3.0 monitoring focuses on whether real-source data drifts away from controlled validation assumptions.

## Source Evidence

- Supervised detector and workflow: `atdr/app/detection/supervised_detector.py`, `atdr/app/detection/supervised_workflow.py`
- Feature generation: `atdr/app/ml/features.py`
- AI Governance API/UI: `atdr/app/routers/ml.py`, `frontend/src/pages/MLGovernance.tsx`
- Read-only monitoring script: `atdr/scripts/run_real_source_ml_monitoring.py`

## Monitoring Questions

- Are reviewed labels available for real-source rows?
- Are suspicious and malicious labels present across time windows?
- Are benign-like false positives increasing?
- Are source/app/action/port distributions drifting?
- Are parser failures affecting feature quality?
- Are confidence values calibrated on real-source reviewed labels?
- Are model outputs still useful for analyst queueing without creating noise?

## Suggested Command

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_real_source_ml_monitoring --pretty
```

For a specific source:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_real_source_ml_monitoring --source-name lab-firewall-real-1 --pretty
```

## Safety Boundary

Monitoring cannot activate a model, production-promote a model, enable automatic response, or enable real firewall blocking. Any future model change must use reviewed labels, separate validation, readiness gates, and analyst approval.
