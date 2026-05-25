from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session, joinedload

from atdr.app.db.models import MLLabel, NormalizedLog


TRAINABLE_LABELS = {"benign", "benign_unusual", "suspicious", "malicious", "needs_context"}
IMPORTANT_CLASSES = ("suspicious", "malicious")
MIN_CLASS_SUPPORT = 5
REVIEWED_LABEL_TARGET = 300
MALICIOUS_TRAINING_MINIMUM = 20
MALICIOUS_TRAINING_BETTER_TARGET = 50


DEFAULT_CLASS_TEMPORAL_COVERAGE_PATH = Path("ml_baseline_reviews/class_temporal_coverage_report.md")


def _latest_trainable_labels(db: Session) -> list[MLLabel]:
    labels = list(
        db.scalars(
            select(MLLabel)
            .options(joinedload(MLLabel.log))
            .join(MLLabel.log)
            .where(MLLabel.label.in_(TRAINABLE_LABELS))
            .order_by(MLLabel.log_id, desc(MLLabel.created_at), desc(MLLabel.id))
        )
    )
    latest: dict[int, MLLabel] = {}
    for label in labels:
        latest.setdefault(label.log_id, label)
    return [label for label in latest.values() if label.log is not None]


def _log_timestamp(log: NormalizedLog | None) -> datetime | None:
    if log is None:
        return None
    return log.generated_time or log.receive_time or log.start_time


def _normalize_timestamp(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _split_labels(labels: list[MLLabel], *, test_size: float) -> tuple[list[MLLabel], list[MLLabel], datetime | None, list[str]]:
    warnings: list[str] = []
    if len(labels) < 2:
        return labels, [], None, ["Not enough labeled rows to compute a time split."]
    rows = [(label, _normalize_timestamp(_log_timestamp(label.log))) for label in labels]
    missing = sum(1 for _label, timestamp in rows if timestamp is None)
    if missing:
        warnings.append(f"{missing} labeled rows are missing timestamps; log id ordering was used as fallback.")
    ordered = sorted(
        rows,
        key=lambda item: (
            item[1] is None,
            item[1] or datetime.min.replace(tzinfo=timezone.utc),
            item[0].log_id,
        ),
    )
    test_count = max(1, int(round(len(ordered) * test_size + 0.499999)))
    test_count = min(test_count, len(ordered) - 1)
    train = [label for label, _timestamp in ordered[:-test_count]]
    test = [label for label, _timestamp in ordered[-test_count:]]
    first_test_timestamp = _normalize_timestamp(_log_timestamp(test[0].log)) if test else None
    return train, test, first_test_timestamp, warnings


def classify_log_time_window(log: NormalizedLog | None, coverage: dict[str, Any] | None = None) -> str:
    timestamp = _normalize_timestamp(_log_timestamp(log))
    if timestamp is None:
        return "unknown_timestamp"
    boundary_text = (coverage or {}).get("first_test_timestamp")
    if not boundary_text:
        return "training_window"
    try:
        boundary = datetime.fromisoformat(str(boundary_text))
    except ValueError:
        return "unknown_timestamp"
    boundary = _normalize_timestamp(boundary)
    if boundary is None:
        return "unknown_timestamp"
    return "test_window" if timestamp >= boundary else "training_window"


def build_class_temporal_coverage(db: Session, *, test_size: float = 0.3) -> dict[str, Any]:
    labels = _latest_trainable_labels(db)
    train_labels, test_labels, first_test_timestamp, warnings = _split_labels(labels, test_size=test_size)
    train_counts = Counter(label.label for label in train_labels)
    test_counts = Counter(label.label for label in test_labels)
    reviewed_counts = Counter(label.label for label in labels if label.reviewed)
    reviewed_train_counts = Counter(label.label for label in train_labels if label.reviewed)
    reviewed_test_counts = Counter(label.label for label in test_labels if label.reviewed)
    class_rows: dict[str, dict[str, Any]] = {}
    all_classes = sorted(set(TRAINABLE_LABELS) | set(train_counts) | set(test_counts) | set(reviewed_counts))
    for label_name in all_classes:
        class_labels = [label for label in labels if label.label == label_name]
        timestamps = sorted(ts for ts in (_normalize_timestamp(_log_timestamp(label.log)) for label in class_labels) if ts is not None)
        train_count = int(train_counts.get(label_name, 0))
        test_count = int(test_counts.get(label_name, 0))
        if test_count and not train_count:
            warnings.append(f"{label_name} exists in the test window but not in the training window.")
        if train_count and not test_count:
            warnings.append(f"{label_name} exists in the training window but not in the test window.")
        if label_name in IMPORTANT_CLASSES and train_count < MIN_CLASS_SUPPORT:
            warnings.append(f"{label_name} training-window support is below {MIN_CLASS_SUPPORT}.")
        class_rows[label_name] = {
            "label": label_name,
            "total": len(class_labels),
            "reviewed_total": int(reviewed_counts.get(label_name, 0)),
            "train_count": train_count,
            "test_count": test_count,
            "reviewed_train_count": int(reviewed_train_counts.get(label_name, 0)),
            "reviewed_test_count": int(reviewed_test_counts.get(label_name, 0)),
            "exists_in_train": train_count > 0,
            "exists_in_test": test_count > 0,
            "earliest_timestamp": timestamps[0].isoformat() if timestamps else None,
            "latest_timestamp": timestamps[-1].isoformat() if timestamps else None,
        }
    reviewed_total = sum(reviewed_counts.values())
    if reviewed_total < REVIEWED_LABEL_TARGET:
        warnings.append(f"Reviewed label count {reviewed_total} is below the recommended target {REVIEWED_LABEL_TARGET}.")
    malicious_train_count = int(train_counts.get("malicious", 0))
    if malicious_train_count < MALICIOUS_TRAINING_MINIMUM:
        warnings.append(
            f"Malicious training-window support {malicious_train_count} is below the minimum useful target {MALICIOUS_TRAINING_MINIMUM}."
        )
    return {
        "test_size": test_size,
        "total_labels": len(labels),
        "training_rows": len(train_labels),
        "test_rows": len(test_labels),
        "first_test_timestamp": first_test_timestamp.isoformat() if first_test_timestamp else None,
        "reviewed_label_target": REVIEWED_LABEL_TARGET,
        "malicious_training_minimum": MALICIOUS_TRAINING_MINIMUM,
        "malicious_training_better_target": MALICIOUS_TRAINING_BETTER_TARGET,
        "reviewed_label_count": reviewed_total,
        "reviewed_malicious_count": int(reviewed_counts.get("malicious", 0)),
        "reviewed_suspicious_count": int(reviewed_counts.get("suspicious", 0)),
        "malicious_train_count": int(train_counts.get("malicious", 0)),
        "malicious_test_count": int(test_counts.get("malicious", 0)),
        "suspicious_train_count": int(train_counts.get("suspicious", 0)),
        "suspicious_test_count": int(test_counts.get("suspicious", 0)),
        "class_coverage": class_rows,
        "warnings": list(dict.fromkeys(warnings)),
    }


def render_class_temporal_coverage_markdown(report: dict[str, Any]) -> str:
    rows = report.get("class_coverage") or {}
    table = [
        "| Class | Total | Reviewed | Train | Test | Reviewed Train | Reviewed Test | Earliest | Latest |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    for label_name, row in rows.items():
        table.append(
            "| {label} | {total} | {reviewed_total} | {train_count} | {test_count} | {reviewed_train_count} | "
            "{reviewed_test_count} | {earliest} | {latest} |".format(
                label=label_name,
                total=row.get("total", 0),
                reviewed_total=row.get("reviewed_total", 0),
                train_count=row.get("train_count", 0),
                test_count=row.get("test_count", 0),
                reviewed_train_count=row.get("reviewed_train_count", 0),
                reviewed_test_count=row.get("reviewed_test_count", 0),
                earliest=row.get("earliest_timestamp") or "-",
                latest=row.get("latest_timestamp") or "-",
            )
        )
    warnings = "\n".join(f"- {warning}" for warning in report.get("warnings", [])) or "- No temporal coverage warnings."
    return f"""# ATDR Class Temporal Coverage Report

## Summary

- Total labels: {report.get("total_labels", 0)}
- Training-window rows: {report.get("training_rows", 0)}
- Test-window rows: {report.get("test_rows", 0)}
- First test timestamp: {report.get("first_test_timestamp") or "not_available"}
- Reviewed labels: {report.get("reviewed_label_count", 0)}
- Recommended reviewed target: {report.get("reviewed_label_target", REVIEWED_LABEL_TARGET)}
- Malicious training minimum: {report.get("malicious_training_minimum", MALICIOUS_TRAINING_MINIMUM)}
- Malicious training better target: {report.get("malicious_training_better_target", MALICIOUS_TRAINING_BETTER_TARGET)}
- Reviewed malicious labels: {report.get("reviewed_malicious_count", 0)}
- Reviewed suspicious labels: {report.get("reviewed_suspicious_count", 0)}
- Malicious train/test: {report.get("malicious_train_count", 0)} / {report.get("malicious_test_count", 0)}
- Suspicious train/test: {report.get("suspicious_train_count", 0)} / {report.get("suspicious_test_count", 0)}

## Class Coverage

{chr(10).join(table)}

## Warnings

{warnings}

## Interpretation

This report checks whether important labels appear in both older training traffic and newer test traffic. If a class exists only in the test window, time-split recall for that class is not learnable yet. Add human-reviewed examples from the training window before claiming validation strength.
"""


def write_class_temporal_coverage_report(
    db: Session,
    *,
    output_path: str | Path = DEFAULT_CLASS_TEMPORAL_COVERAGE_PATH,
    test_size: float = 0.3,
) -> dict[str, Any]:
    report = build_class_temporal_coverage(db, test_size=test_size)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_class_temporal_coverage_markdown(report), encoding="utf-8")
    return {"status": "exported", "path": str(path), **report}
