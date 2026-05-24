[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LogPath,

    [int]$Limit = 50000,
    [int]$BaselineLimit = 20000,
    [int]$ReviewQueueLimit = 1000,

    [switch]$SkipImport,
    [switch]$SkipDetection,
    [switch]$SkipIsolationForest,
    [switch]$TrainSupervised
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot
if ($env:PYTHONPATH) {
    $env:PYTHONPATH = "$RepoRoot;$env:PYTHONPATH"
} else {
    $env:PYTHONPATH = $RepoRoot
}

$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$Alembic = Join-Path $RepoRoot ".venv\Scripts\alembic.exe"
if (-not (Test-Path -LiteralPath $Python)) {
    $Python = "python"
}
if (-not (Test-Path -LiteralPath $Alembic)) {
    $Alembic = "alembic"
}

if (-not (Test-Path -LiteralPath $LogPath)) {
    throw "Log file not found: $LogPath"
}
$ResolvedLogPath = (Resolve-Path -LiteralPath $LogPath).Path

function Invoke-CheckedStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Command
    )

    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

Invoke-CheckedStep "Apply Alembic migrations" {
    & $Alembic upgrade head
}

Invoke-CheckedStep "Ensure demo users exist" {
    & $Python -m atdr.scripts.seed_users
}

if (-not $SkipImport) {
    Invoke-CheckedStep "Import Palo Alto logs" {
        & $Python -m atdr.scripts.import_logs $ResolvedLogPath --limit $Limit --actor ai_demo_pipeline
    }
}

if (-not $SkipDetection) {
    $DetectionCode = @'
import json
import sys

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.services.detection_service import run_detection

limit = int(sys.argv[1])
init_db()
with SessionLocal() as db:
    result = run_detection(db, limit=limit, use_ml=False, actor="ai_demo_pipeline")
print(json.dumps(result, indent=2, default=str))
'@
    Invoke-CheckedStep "Run rule-based detection" {
        $TempDir = Join-Path $RepoRoot ".tmp"
        New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
        $DetectionScript = Join-Path $TempDir "ai_demo_detection.py"
        Set-Content -LiteralPath $DetectionScript -Value $DetectionCode -Encoding UTF8
        & $Python $DetectionScript $Limit
    }
}

if (-not $SkipIsolationForest) {
    Invoke-CheckedStep "Train IsolationForest baseline model" {
        & $Python -m atdr.scripts.train_model --limit $BaselineLimit --baseline-only
    }

    Invoke-CheckedStep "Score logs with anomaly detection" {
        & $Python -m atdr.scripts.predict_anomaly --limit $Limit
    }
}

if ($TrainSupervised) {
    Invoke-CheckedStep "Train supervised model from analyst labels" {
        & $Python -m atdr.scripts.train_supervised_model --test-size 0.3 --min-samples 6 --actor ai_demo_pipeline
    }
}

$ValidationCode = @'
import json
import sys
from pathlib import Path

from sqlalchemy import func, select

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import Alert, MLLabel, NormalizedLog, RawLog
from atdr.app.detection.supervised_detector import supervised_model_report, supervised_report_markdown
from atdr.app.services.ml_label_service import build_label_review_queue, export_review_queue_csv

queue_limit = int(sys.argv[1])
output_dir = Path("ml_baseline_reviews")
output_dir.mkdir(parents=True, exist_ok=True)
queue_path = output_dir / "real_data_review_queue.csv"
report_path = output_dir / "supervised_model_report.md"

init_db()
with SessionLocal() as db:
    raw_logs = int(db.scalar(select(func.count(RawLog.id))) or 0)
    normalized_logs = int(db.scalar(select(func.count(NormalizedLog.id))) or 0)
    alerts = int(db.scalar(select(func.count(Alert.id))) or 0)
    anomalies = int(db.scalar(select(func.count(NormalizedLog.id)).where(NormalizedLog.is_anomaly.is_(True))) or 0)
    labeled_rows = int(db.scalar(select(func.count(MLLabel.id))) or 0)
    queue = build_label_review_queue(db, limit=queue_limit, include_labeled=False)
    queue_path.write_text(export_review_queue_csv(queue), encoding="utf-8")
    report = supervised_model_report(db)
    report_path.write_text(supervised_report_markdown(db), encoding="utf-8")

summary = {
    "raw_logs": raw_logs,
    "normalized_logs": normalized_logs,
    "alerts": alerts,
    "anomaly_count": anomalies,
    "anomaly_rate": round((anomalies / normalized_logs) * 100, 2) if normalized_logs else 0.0,
    "unlabeled_review_queue_items_exported": len(queue),
    "labeled_rows": labeled_rows,
    "supervised_model": {
        "artifact_exists": report["artifact_exists"],
        "label_count": report["label_count"],
        "latest_run_status": (report.get("latest_run") or {}).get("status"),
        "decision_support_only": report["decision_support_only"],
    },
    "review_queue_csv": str(queue_path),
    "supervised_report_markdown": str(report_path),
}
print(json.dumps(summary, indent=2, default=str))
'@

Invoke-CheckedStep "Generate review queue and validation summary" {
    $TempDir = Join-Path $RepoRoot ".tmp"
    New-Item -ItemType Directory -Force -Path $TempDir | Out-Null
    $ValidationScript = Join-Path $TempDir "ai_demo_validation.py"
    Set-Content -LiteralPath $ValidationScript -Value $ValidationCode -Encoding UTF8
    & $Python $ValidationScript $ReviewQueueLimit
}

Write-Host ""
Write-Host "AI demo pipeline completed. Open the React dashboard, then review ML Governance and Log Explorer." -ForegroundColor Green
