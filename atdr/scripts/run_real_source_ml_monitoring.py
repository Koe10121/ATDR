import argparse
import json
import time
from datetime import datetime
from typing import Any

from sqlalchemy import func, select

from atdr.app.db.database import SessionLocal
from atdr.app.db.models import LogSource, MLLabel, NormalizedLog, RawLog


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def run_real_source_ml_monitoring(*, source_name: str | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    with SessionLocal() as db:
        source_ids: list[int] | None = None
        if source_name:
            source = db.scalar(select(LogSource).where(LogSource.name == source_name).limit(1))
            source_ids = [source.id] if source else []

        log_statement = select(NormalizedLog.id)
        if source_ids is not None:
            if not source_ids:
                log_statement = log_statement.where(False)
            else:
                log_statement = log_statement.join(RawLog).where(RawLog.source_id.in_(source_ids))
        log_ids = [int(row) for row in db.scalars(log_statement.limit(5000))]
        label_statement = select(MLLabel.label, func.count(MLLabel.id)).group_by(MLLabel.label)
        reviewed_statement = select(MLLabel.label, func.count(MLLabel.id)).where(MLLabel.reviewed.is_(True)).group_by(MLLabel.label)
        if source_ids is not None and log_ids:
            label_statement = label_statement.where(MLLabel.log_id.in_(log_ids))
            reviewed_statement = reviewed_statement.where(MLLabel.log_id.in_(log_ids))
        elif source_ids is not None:
            label_statement = label_statement.where(False)
            reviewed_statement = reviewed_statement.where(False)

        label_distribution = {str(label): int(count) for label, count in db.execute(label_statement)}
        reviewed_distribution = {str(label): int(count) for label, count in db.execute(reviewed_statement)}
        source_rows = list(db.scalars(select(LogSource).order_by(LogSource.name).limit(100)))
        source_summary = [
            {
                "source_id": source.id,
                "name": source.name,
                "source_type": source.source_type,
                "parser_profile": source.parser_profile,
                "logs_received_count": source.logs_received_count,
                "parse_success_count": source.parse_success_count,
                "parse_failure_count": source.parse_failure_count,
                "last_log_received_at": source.last_log_received_at,
            }
            for source in source_rows
            if source_name is None or source.name == source_name
        ]
        warnings: list[str] = []
        reviewed_total = sum(reviewed_distribution.values())
        if reviewed_total < 300:
            warnings.append("Reviewed real-source label coverage is still low for deployment claims.")
        if not any(label in reviewed_distribution for label in ("suspicious", "malicious")):
            warnings.append("Reviewed threat-positive real-source labels are missing or low.")
        return {
            "ok": True,
            "status": "read_only_monitoring_report",
            "source_name": source_name,
            "source_count": len(source_summary),
            "sampled_log_count": len(log_ids),
            "label_distribution": label_distribution,
            "reviewed_label_distribution": reviewed_distribution,
            "reviewed_label_count": reviewed_total,
            "source_summary": source_summary,
            "warnings": warnings,
            "model_activated": False,
            "production_promoted": False,
            "response_automation_allowed": False,
            "real_firewall_blocking_enabled": False,
            "runtime_seconds": round(time.perf_counter() - started, 4),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only real-source ML monitoring summary.")
    parser.add_argument("--source-name", default=None)
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    result = run_real_source_ml_monitoring(source_name=args.source_name)
    print(json.dumps(result, indent=2 if args.pretty else None, default=_json_default))
    raise SystemExit(0)


if __name__ == "__main__":
    main()
