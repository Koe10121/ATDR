# ATDR v1.7b Benchmark Review Import

v1.7 boundary review files use `benchmark_row_id`. They describe safe external or holdout benchmark rows, not database-backed firewall logs. They must not be imported into the main `ml_labels` table.

## Supported Workflow

1. Review `ml_baseline_reviews/v1_7_external_boundary_review_sample.csv`.
2. Complete `human_review_decision`, `human_review_attack_type`, `human_review_confidence`, and `human_review_note`.
3. Save the reviewed file.
4. Import it with the dedicated command:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.import_benchmark_review_csv `
  --input-csv "C:\path\to\v1_7_external_boundary_review_sample_REVIEWED.csv" `
  --benchmark-kind external_holdout `
  --pretty
```

The command validates the review values and writes an ignored JSON artifact under `demo_exports/benchmarks/`. It does not connect to the application database and does not create or update `ml_labels`.

The React AI Governance page also provides **Import Benchmark Review CSV**. The normal **Import Reviewed CSV** control remains for files containing `log_id` or `label_id`.

## Reviewed External Validation

Apply the reviewed labels during external validation:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_external_benchmark_validation `
  --holdout-from-current-data `
  --reviewed-benchmark-csv "C:\path\to\v1_7_external_boundary_review_sample_REVIEWED.csv" `
  --pretty
```

The validator:

- preserves the original holdout snapshot
- creates an ignored reviewed snapshot
- overrides expected labels using `human_review_decision`
- overrides attack type when `human_review_attack_type` is supplied
- preserves reviewer confidence and notes in review metadata and error examples
- reports before/after metrics
- keeps model activation and response automation disabled

The latest reviewed snapshot is then used by v1.7:

```powershell
.\.venv\Scripts\python.exe -m atdr.scripts.run_v17_external_generalization `
  --review-limit 300 `
  --pretty
```

## Safety

- Benchmark labels remain separate from real firewall-log labels.
- Generated artifacts remain ignored.
- No model is activated automatically.
- External benchmark results are development evidence, not production accuracy.
- Response actions remain simulated and analyst-approved.
