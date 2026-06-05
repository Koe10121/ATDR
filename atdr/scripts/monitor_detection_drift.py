import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import func, select

from atdr.app.db.database import SessionLocal
from atdr.app.db.models import Alert, LogSource, NormalizedLog, RawLog
from atdr.scripts.detection_reliability_common import RELIABILITY_OUTPUT_DIR, json_default, write_report_files


def _top(values: list[Any], limit: int = 10) -> dict[str, int]:
    counter = Counter(str(value or "unknown") for value in values)
    return dict(counter.most_common(limit))


def _distribution_shift(current: dict[str, int], baseline: dict[str, int]) -> dict[str, float]:
    current_total = sum(current.values()) or 1
    baseline_total = sum(baseline.values()) or 1
    keys = set(current) | set(baseline)
    return {
        key: round((current.get(key, 0) / current_total) - (baseline.get(key, 0) / baseline_total), 4)
        for key in sorted(keys)
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ATDR Detection Drift Report",
        "",
        f"- Generated at: {report['generated_at']}",
        f"- Recent rows sampled: {report['recent_rows']}",
        f"- Baseline rows sampled: {report['baseline_rows']}",
        f"- Warnings: {len(report['warnings'])}",
        "",
        "## Warnings",
        "",
    ]
    for warning in report["warnings"] or ["None."]:
        lines.append(f"- {warning}")
    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- This is lightweight drift groundwork for lab use.",
            "- It compares recent database rows to older local rows and does not claim production monitoring coverage.",
        ]
    )
    return "\n".join(lines)


def monitor_detection_drift(
    *,
    recent_limit: int = 1000,
    baseline_limit: int = 5000,
    write_output: bool = True,
    output_dir: Path = RELIABILITY_OUTPUT_DIR,
) -> dict[str, Any]:
    with SessionLocal() as db:
        recent_logs = list(db.scalars(select(NormalizedLog).order_by(NormalizedLog.id.desc()).limit(recent_limit)))
        min_recent_id = min((log.id for log in recent_logs), default=0)
        baseline_logs = list(
            db.scalars(
                select(NormalizedLog)
                .where(NormalizedLog.id < min_recent_id)
                .order_by(NormalizedLog.id.desc())
                .limit(baseline_limit)
            )
        )
        total_alerts = int(db.scalar(select(func.count(Alert.id))) or 0)
        total_normalized = int(db.scalar(select(func.count(NormalizedLog.id))) or 0)
        total_raw = int(db.scalar(select(func.count(RawLog.id))) or 0)
        sources = list(db.scalars(select(LogSource).limit(200)))

    recent_app = _top([log.app for log in recent_logs])
    baseline_app = _top([log.app for log in baseline_logs])
    recent_action = _top([log.action for log in recent_logs])
    baseline_action = _top([log.action for log in baseline_logs])
    recent_ports = _top([log.dst_port for log in recent_logs])
    baseline_ports = _top([log.dst_port for log in baseline_logs])
    anomaly_scores = [float(log.anomaly_score) for log in recent_logs if log.anomaly_score is not None]
    unknown_app_count = sum(1 for log in recent_logs if (log.app or "").lower() in {"unknown-tcp", "unknown-udp", "incomplete", ""})
    parse_failures = sum(source.parse_failure_count for source in sources)
    parse_successes = sum(source.parse_success_count for source in sources)
    warnings: list[str] = []
    unknown_rate = round(unknown_app_count / max(1, len(recent_logs)), 4)
    parse_failure_rate = round(parse_failures / max(1, parse_failures + parse_successes), 4)
    alert_rate = round(total_alerts / max(1, total_normalized), 4)
    if unknown_rate > 0.25:
        warnings.append(f"Recent unknown/incomplete app rate is high at {unknown_rate:.2%}.")
    if parse_failure_rate > 0.05:
        warnings.append(f"Source parse failure rate is {parse_failure_rate:.2%}; review parser profiles.")
    if alert_rate > 0.2:
        warnings.append(f"Overall alert rate is high at {alert_rate:.2%}; review dedup/suppression calibration.")

    report = {
        "ok": True,
        "generated_at": datetime.now(timezone.utc),
        "validation_scope": "lightweight detection drift monitoring groundwork",
        "read_only": True,
        "total_raw_logs": total_raw,
        "total_normalized_logs": total_normalized,
        "total_alerts": total_alerts,
        "recent_rows": len(recent_logs),
        "baseline_rows": len(baseline_logs),
        "current_app_distribution": recent_app,
        "baseline_app_distribution": baseline_app,
        "app_distribution_shift": _distribution_shift(recent_app, baseline_app),
        "current_action_distribution": recent_action,
        "baseline_action_distribution": baseline_action,
        "action_distribution_shift": _distribution_shift(recent_action, baseline_action),
        "current_port_distribution": recent_ports,
        "baseline_port_distribution": baseline_ports,
        "port_distribution_shift": _distribution_shift(recent_ports, baseline_ports),
        "top_source_ips": _top([log.src_ip for log in recent_logs]),
        "top_destination_ips": _top([log.dst_ip for log in recent_logs]),
        "unknown_app_rate": unknown_rate,
        "parse_failure_rate": parse_failure_rate,
        "alert_rate": alert_rate,
        "anomaly_score_distribution": {
            "count": len(anomaly_scores),
            "min": round(min(anomaly_scores), 4) if anomaly_scores else None,
            "max": round(max(anomaly_scores), 4) if anomaly_scores else None,
            "avg": round(sum(anomaly_scores) / len(anomaly_scores), 4) if anomaly_scores else None,
        },
        "warnings": warnings,
        "safety": {
            "automatic_response_enabled": False,
            "real_firewall_blocking_enabled": False,
            "production_readiness_claim": False,
        },
    }
    if write_output:
        report["paths"] = write_report_files(
            report,
            output_dir=output_dir,
            stem_prefix="drift_report",
            markdown=render_markdown(report),
        )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a lightweight ATDR detection drift report.")
    parser.add_argument("--recent-limit", type=int, default=1000)
    parser.add_argument("--baseline-limit", type=int, default=5000)
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = monitor_detection_drift(
        recent_limit=args.recent_limit,
        baseline_limit=args.baseline_limit,
        write_output=not args.no_report,
        output_dir=Path(args.output_dir) if args.output_dir else RELIABILITY_OUTPUT_DIR,
    )
    print(json.dumps(report, default=json_default, indent=2 if args.pretty else None))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
