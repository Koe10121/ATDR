import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from atdr.scripts.detection_reliability_common import json_default, write_report_files
from atdr.scripts.run_detection_benchmark import BENCHMARK_OUTPUT_DIR, DETECTION_MODES, run_detection_benchmark


def _mode_interpretation(mode: str, report: dict[str, Any]) -> str:
    metrics = report.get("metrics") or {}
    false_negatives = int(metrics.get("false_negatives") or 0)
    false_positives = int(metrics.get("false_positives") or 0)
    if mode == "rules_only":
        return "Rules are strongest for known patterns with clear signatures."
    if mode == "anomaly_only":
        return "Anomaly-only remains diagnostic and depends on the current IsolationForest artifact."
    if mode == "supervised_only":
        return "Supervised-only remains decision support and depends on current candidate model quality."
    if false_negatives == 0 and false_positives == 0:
        return "Hybrid kept controlled benchmark misses and false positives at zero for this run."
    return f"Hybrid needs review: FP={false_positives}, FN={false_negatives}."


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR Layered Benchmark Comparison",
        "",
        f"- Generated at: {report['generated_at']}",
        f"- Dataset: {report['dataset_name']}",
        "- Response mode: simulated analyst-approved only",
        "- Production readiness claim: none",
        "",
        "## Mode Comparison",
        "",
        "| Mode | Precision | Recall | F1 | FP | FN | Alert Volume | Runtime | Interpretation |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in report["mode_results"]:
        metrics = row.get("metrics") or {}
        lines.append(
            f"| {row['mode']} | {metrics.get('precision')} | {metrics.get('recall')} | {metrics.get('f1')} | "
            f"{metrics.get('false_positives')} | {metrics.get('false_negatives')} | {row.get('alert_volume')} | "
            f"{row.get('runtime_seconds')} | {row.get('interpretation')} |"
        )
    lines.extend(
        [
            "",
            "## Recommended Production-Like Strategy",
            "",
            "- Keep rule-first detection for known firewall-log patterns.",
            "- Use anomaly and supervised ML as SOC triage signals, not automatic response triggers.",
            "- Use hybrid scoring to prioritize review queues after benchmark and real-source validation improve.",
            "- Do not mix benchmark metrics with local firewall-log metrics by default.",
            "",
            "## Safety",
            "",
            "- No automatic response actions are created by benchmark comparison.",
            "- Real firewall blocking remains disabled.",
            "- This report does not certify production readiness.",
        ]
    )
    return "\n".join(lines)


def compare_layered_benchmark_reliability(
    *,
    csv_path: Path | None = None,
    prepared_snapshot: Path | None = None,
    mapping_config: Path | None = None,
    limit: int | None = None,
    output_dir: Path = BENCHMARK_OUTPUT_DIR,
) -> dict[str, Any]:
    if csv_path is None and prepared_snapshot is None:
        raise ValueError("csv_path or prepared_snapshot is required.")
    results = []
    for mode in DETECTION_MODES:
        item = run_detection_benchmark(
            csv_path=csv_path,
            prepared_snapshot=prepared_snapshot,
            mapping_config_path=mapping_config,
            limit=limit,
            detection_mode=mode,
            use_temp_db=True,
            write_output=False,
            output_dir=output_dir,
        )
        results.append(
            {
                "mode": mode,
                "ok": item["ok"],
                "metrics": item["metrics"],
                "alert_volume": item["alert_volume"],
                "runtime_seconds": item["runtime_seconds"],
                "per_attack_metrics": item["metrics"].get("per_attack_metrics", {}),
                "interpretation": _mode_interpretation(mode, item),
            }
        )
    report = {
        "ok": all(item["ok"] for item in results),
        "generated_at": datetime.now(timezone.utc),
        "validation_scope": "layered benchmark comparison",
        "dataset_name": (prepared_snapshot or csv_path or Path("benchmark")).name,
        "mode_results": results,
        "safety": {
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "production_readiness_claim": False,
        },
    }
    report["paths"] = write_report_files(
        report,
        output_dir=output_dir,
        stem_prefix="layered_benchmark_comparison",
        markdown=render_markdown(report),
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare rule, anomaly, supervised, and hybrid detection on benchmark data.")
    parser.add_argument("--csv-path", default=None)
    parser.add_argument("--prepared-snapshot", default=None)
    parser.add_argument("--mapping-config", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = compare_layered_benchmark_reliability(
        csv_path=Path(args.csv_path) if args.csv_path else None,
        prepared_snapshot=Path(args.prepared_snapshot) if args.prepared_snapshot else None,
        mapping_config=Path(args.mapping_config) if args.mapping_config else None,
        limit=args.limit,
        output_dir=Path(args.output_dir) if args.output_dir else BENCHMARK_OUTPUT_DIR,
    )
    print(json.dumps(report, default=json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
