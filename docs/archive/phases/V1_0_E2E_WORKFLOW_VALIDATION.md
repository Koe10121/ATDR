# ATDR v1.0 End-to-End Workflow Validation

ATDR v1.0 adds a controlled end-to-end validation runner that proves the lab SOC workflow from log ingestion through alert investigation and optional simulated response approval. This is still controlled lab validation. It is not production certification, does not run offensive tooling, and does not perform real firewall blocking.

## What The Runner Validates

The runner validates the full defensive workflow:

1. Import safe synthetic scenario logs.
2. Preserve raw evidence.
3. Normalize logs through the configured parser profile.
4. Track source health and source-level quality.
5. Run source-scoped detection.
6. Create explainable alerts.
7. Link alert evidence back to logs.
8. Build source-linked case summaries.
9. Verify **Why flagged?** explanation content.
10. Optionally exercise simulated response approval/denial.
11. Verify protected-IP denial and required justification.
12. Verify audit entries for response attempts.
13. Write JSON and Markdown reports under ignored `demo_exports/e2e_validation/`.

## Command

Default mode uses a temporary in-memory SQLite database and does not touch the current local dashboard database:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_e2e_workflow_validation --pretty
```

Run one scenario and exercise simulated response safety:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_e2e_workflow_validation --scenario port_scan_like_traffic --simulate-response --pretty
```

Only write validation rows to the current dashboard database when you intentionally want to inspect them in React:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_e2e_workflow_validation --scenario port_scan_like_traffic --source-name e2e-dashboard-check --write-to-current-db --simulate-response --pretty
```

## Safety Defaults

- Temporary database is the default.
- Current DB writes require `--write-to-current-db`.
- Response checks require `--simulate-response`.
- Response actions remain simulated and analyst-approved only.
- Protected internal/management IP response attempts are denied.
- Missing justification notes are denied.
- ML remains decision support only.
- Generated reports remain ignored by Git.

## Dashboard Verification

After a report is generated, Overview reads the latest safe report metadata through `/api/dashboard/validation-summary` and shows an **E2E Workflow** status card.

When validation is intentionally written to the current DB, verify:

- **Overview**: E2E Workflow card, Log Sources panel, Operations Health.
- **Alerts**: source-linked alert appears with evidence count and **Why flagged?**.
- **Investigation**: source filter can show the imported normalized logs and raw evidence.
- **Response & Audit**: simulated response wording is visible; denied and simulated attempts appear in audit when `--simulate-response` is used.
- **Admin / Settings**: External IAM remains disabled/not configured unless explicitly configured later.

## Expected Report Fields

The JSON report includes:

- `ok`
- `scenario_count`, `passed_count`, `failed_count`
- scenario-level ingestion, parser, source, detection, alert, case, evidence, response, audit, and timing summaries
- safety metadata showing automatic response and real firewall blocking are disabled
- limitations clarifying that the result is controlled lab validation only

## Current Limitations

- The runner uses safe synthetic/replay scenarios only.
- It does not validate real firewall/router forwarding.
- It does not validate real response enforcement.
- It does not claim production readiness or production accuracy.
- Full external OIDC login remains future work.
