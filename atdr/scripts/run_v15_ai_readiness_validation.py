import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.app.benchmarks.readiness import readiness_gate_v4
from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import SessionLocal
from atdr.app.db.models import MLLabel
from atdr.app.detection.supervised_detector import _latest_labels
from atdr.scripts.build_internal_ai_readiness_benchmark import (
    DEFAULT_MANIFEST,
    DEFAULT_OUTPUT,
    build_internal_ai_readiness_benchmark,
)
from atdr.scripts.compare_layered_benchmark_reliability import (
    compare_layered_benchmark_reliability,
)
from atdr.scripts.prepare_benchmark_dataset import prepare_benchmark_dataset
from atdr.scripts.run_benchmark_ml_experiment import run_benchmark_ml_experiment


BENCHMARK_OUTPUT_DIR = PROJECT_ROOT / "demo_exports" / "benchmarks"
FINAL_OUTPUT_DIR = PROJECT_ROOT / "ml_baseline_reviews"
V14C_REPORT = FINAL_OUTPUT_DIR / "v1_4c_malicious_recall_recovery.json"
CONTROLLED_VALIDATIONS = {
    "v0_7_detection": (
        PROJECT_ROOT / "demo_exports" / "detection_validation",
        "detection_validation_*.json",
    ),
    "v0_8_generalization": (
        PROJECT_ROOT / "demo_exports" / "detection_generalization",
        "detection_generalization_*.json",
    ),
    "v0_9_layered": (
        PROJECT_ROOT / "demo_exports" / "layered_detection",
        "layered_detection_*.json",
    ),
    "v1_0_e2e": (
        PROJECT_ROOT / "demo_exports" / "e2e_validation",
        "e2e_workflow_validation_*.json",
    ),
    "v1_1_reliability": (
        PROJECT_ROOT / "demo_exports" / "detection_reliability",
        "detection_reliability_baseline_*.json",
    ),
}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _latest_validation_status() -> dict[str, Any]:
    rows = []
    for name, (directory, pattern) in CONTROLLED_VALIDATIONS.items():
        candidates = sorted(
            directory.glob(pattern),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        path = candidates[0] if candidates else None
        payload = _load_json(path) if path else {}
        passed = bool(payload.get("ok"))
        rows.append(
            {
                "name": name,
                "available": path is not None,
                "passed": passed,
                "report_name": path.name if path else None,
            }
        )
    return {
        "passed": all(row["available"] and row["passed"] for row in rows),
        "checks": rows,
    }


def _current_label_summary() -> dict[str, Any]:
    with SessionLocal() as db:
        labels: list[MLLabel] = _latest_labels(db)
    reviewed = [label for label in labels if label.reviewed]
    return {
        "latest_label_rows": len(labels),
        "reviewed_label_count": len(reviewed),
        "reviewed_label_distribution": dict(
            sorted(Counter(label.label for label in reviewed).items())
        ),
    }


def _best_triage_candidate(report: dict[str, Any]) -> dict[str, Any]:
    candidates = [
        item
        for item in report.get("candidates") or []
        if item.get("status") == "evaluated"
        and {"suspicious", "malicious"}.issubset(
            set(((item.get("metrics") or {}).get("per_class") or {}).keys())
        )
    ]
    return max(
        candidates,
        key=lambda item: (
            float((item.get("metrics") or {}).get("threat_positive_f1") or 0),
            -float(
                (item.get("metrics") or {}).get(
                    "benign_false_positive_rate", 1
                )
            ),
            float((item.get("metrics") or {}).get("macro_f1") or 0),
        ),
        default={},
    )


def _current_profile_comparison(v14c: dict[str, Any]) -> list[dict[str, Any]]:
    keep = {
        "malicious_recall_recovery",
        "balanced_low_noise",
        "calibrated_low_noise",
        "high_confidence_triage",
    }
    return [
        {
            "name": item.get("name"),
            "configuration": item.get("configuration"),
            "diagnostic_only": item.get("diagnostic_only"),
            "summary": item.get("summary") or {},
        }
        for item in v14c.get("profiles") or []
        if item.get("name") in keep
    ]


def _render_final_report(report: dict[str, Any]) -> str:
    benchmark = report["benchmark"]
    metrics = report["best_benchmark_candidate"].get("metrics") or {}
    readiness = report["readiness_gate_v4"]
    current = report.get("current_v14c") or {}
    lines = [
        "# ATDR v1.5 Final AI Readiness Report",
        "",
        f"- Generated: {report['generated_at']}",
        f"- Reviewed labels: {report['training_data']['reviewed_label_count']}",
        f"- Benchmark labels: {benchmark['row_count']}",
        f"- Benchmark target met: {benchmark['target_met']}",
        f"- Best benchmark candidate: {report['best_benchmark_candidate'].get('candidate_name')}",
        f"- Readiness v4: {readiness['decision']}",
        "- Production promoted: false",
        "- Model activated: false",
        "- Response automation allowed: false",
        "",
        "## Benchmark Composition",
        "",
        f"- Labels: {benchmark['label_distribution']}",
        f"- Attack types: {benchmark['attack_type_distribution']}",
        f"- Sources: {benchmark['source_distribution']}",
        f"- Scenarios: {benchmark['scenario_count']}",
        "",
        "## Best Benchmark Candidate Metrics",
        "",
        f"- Threat-positive precision: {metrics.get('threat_positive_precision')}",
        f"- Threat-positive recall: {metrics.get('threat_positive_recall')}",
        f"- Threat-positive F1: {metrics.get('threat_positive_f1')}",
        f"- Benign-like false-positive rate: {metrics.get('benign_false_positive_rate')}",
        f"- Suspicious recall: {((metrics.get('per_class') or {}).get('suspicious') or {}).get('recall')}",
        f"- Malicious recall: {((metrics.get('per_class') or {}).get('malicious') or {}).get('recall')}",
        f"- Macro F1: {metrics.get('macro_f1')}",
        f"- Weighted F1: {metrics.get('weighted_f1')}",
        "",
        "## Current Local Reviewed-Label Candidate",
        "",
        f"- Best profile: {current.get('best_profile')}",
        f"- Metrics: {current.get('best_metrics')}",
        f"- Calibration: {(current.get('selected_calibration') or {}).get('status')}",
        "",
        "## Layered Detection Modes",
        "",
        "| Mode | Precision | Recall | F1 | Benign FPR | Suspicious Recall | Malicious Recall | FP | FN | Runtime |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in report["layered_detection"]["mode_results"]:
        item_metrics = item.get("metrics") or {}
        lines.append(
            f"| {item['mode']} | {item_metrics.get('precision')} | "
            f"{item_metrics.get('recall')} | {item_metrics.get('f1')} | "
            f"{item_metrics.get('benign_false_positive_rate')} | "
            f"{item_metrics.get('suspicious_recall')} | "
            f"{item_metrics.get('malicious_recall')} | "
            f"{item_metrics.get('false_positives')} | "
            f"{item_metrics.get('false_negatives')} | "
            f"{item.get('runtime_seconds')} |"
        )
    lines.extend(
        [
            "",
            "## Strengths",
            "",
            "- The benchmark includes normal, near-boundary, suspicious, malicious, and limited-context traffic.",
            "- Benchmark evaluation is isolated in temporary SQLite databases.",
            "- The current low-noise local profile and the benchmark candidates remain separately reported.",
            "- Controlled validation and response-safety evidence remain part of the readiness gate.",
            "",
            "## Limitations",
            "",
            "- This is a deterministic synthetic internal benchmark, not independent production traffic.",
            "- Benchmark metrics must not be presented as deployment accuracy.",
            "- Exact suspicious versus malicious separation remains less reliable than threat-positive triage.",
            "- Real router/firewall forwarding, long-duration drift, and independent external benchmark validation remain future work.",
            "",
            "## Decision",
            "",
            readiness["message"],
            "",
            "ATDR ML remains SOC triage decision support. Every response action remains simulated and analyst-approved.",
        ]
    )
    return "\n".join(lines)


def run_v15_ai_readiness_validation(
    *,
    manifest_path: Path = DEFAULT_MANIFEST,
    benchmark_csv_path: Path = DEFAULT_OUTPUT,
    output_dir: Path = BENCHMARK_OUTPUT_DIR,
    final_output_dir: Path = FINAL_OUTPUT_DIR,
    test_size: float = 0.3,
) -> dict[str, Any]:
    generated_at = datetime.now(timezone.utc).isoformat()
    benchmark = build_internal_ai_readiness_benchmark(
        manifest_path=manifest_path,
        output_path=benchmark_csv_path,
    )
    snapshot = prepare_benchmark_dataset(
        input_csv=benchmark_csv_path,
        sample_strategy="balanced",
        output_dir=output_dir,
    )
    snapshot_path = Path(snapshot["snapshot_path"])
    layered = compare_layered_benchmark_reliability(
        prepared_snapshot=snapshot_path,
        output_dir=output_dir,
    )
    ml_report = run_benchmark_ml_experiment(
        snapshot_path=snapshot_path,
        split="random",
        test_size=test_size,
        output_dir=final_output_dir / "benchmark_ml_experiments",
    )
    best_candidate = _best_triage_candidate(ml_report)
    if not best_candidate:
        raise RuntimeError("No evaluated three-class or hierarchical benchmark candidate.")
    v14c = _load_json(V14C_REPORT)
    calibration_status = str(
        (v14c.get("selected_calibration") or {}).get("status") or "missing"
    )
    controlled = _latest_validation_status()
    readiness = readiness_gate_v4(
        benchmark_label_count=int(benchmark["row_count"]),
        benchmark_label_distribution=benchmark["label_distribution"],
        benchmark_metrics=best_candidate.get("metrics") or {},
        calibration_status=calibration_status,
        controlled_validations_passed=bool(controlled["passed"]),
        response_automation_allowed=False,
    )
    report = {
        "ok": True,
        "status": "completed",
        "generated_at": generated_at,
        "training_data": _current_label_summary(),
        "benchmark": benchmark,
        "prepared_snapshot": {
            "snapshot_id": snapshot.get("snapshot_id"),
            "snapshot_path": snapshot.get("snapshot_path"),
            "row_count": snapshot.get("rows_selected"),
            "profile": snapshot.get("profile"),
        },
        "layered_detection": layered,
        "benchmark_ml_experiment": ml_report,
        "best_benchmark_candidate": best_candidate,
        "current_v14c": {
            "best_profile": v14c.get("best_profile"),
            "best_metrics": v14c.get("best_metrics") or {},
            "selected_calibration": v14c.get("selected_calibration") or {},
            "profile_comparison": _current_profile_comparison(v14c),
        },
        "controlled_validations": controlled,
        "readiness_gate_v4": readiness,
        "production_promoted": False,
        "model_activated": False,
        "model_artifact_written": False,
        "response_automation_allowed": False,
        "real_firewall_blocking_enabled": False,
    }
    stamp = _stamp()
    output_dir.mkdir(parents=True, exist_ok=True)
    final_output_dir.mkdir(parents=True, exist_ok=True)
    benchmark_path = output_dir / f"final_ai_readiness_benchmark_{stamp}.json"
    final_path = final_output_dir / f"final_ai_readiness_report_{stamp}.json"
    markdown = _render_final_report(report)
    benchmark_path.write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )
    benchmark_path.with_suffix(".md").write_text(markdown, encoding="utf-8")
    final_path.write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )
    final_path.with_suffix(".md").write_text(markdown, encoding="utf-8")
    report["paths"] = {
        "benchmark_json": str(benchmark_path),
        "benchmark_markdown": str(benchmark_path.with_suffix(".md")),
        "final_json": str(final_path),
        "final_markdown": str(final_path.with_suffix(".md")),
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run safe v1.5 internal benchmark and final AI readiness validation "
            "without activating a model."
        )
    )
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--benchmark-csv", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--test-size", type=float, default=0.3)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_v15_ai_readiness_validation(
        manifest_path=Path(args.manifest),
        benchmark_csv_path=Path(args.benchmark_csv),
        test_size=args.test_size,
    )
    print(json.dumps(result, indent=2 if args.pretty else None, default=str))
    raise SystemExit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
