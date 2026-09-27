"""Detection scoreboard: how well the current rules agree with human labels.

The scoreboard never trusts alerts already stored in the database, because
they came from older rules and older runs. Instead it copies the configured
SQLite database to a scratch file with SQLite's online backup (a read of the
source), clears the alerts in the copy, re-runs the production detection code
over every log, and compares the resulting alerts with human-reviewed labels.

Labels are split by source IP with a fixed hash, so all traffic from one
source lands on the same side. Rule changes are tuned on "dev" and the "test"
side is reported but never tuned against. Precision and recall here are
measured on labeled logs, which over-represent suspicious traffic, so they
describe agreement with our reviewers, not accuracy on all traffic.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, delete, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from atdr.app.core.config import PROJECT_ROOT, get_settings
from atdr.app.db.models import Alert, AlertEvidence, AlertNote, MLLabel, NormalizedLog, ResponseAction
from atdr.app.services.detection_service import run_detection

THREAT_LABELS = frozenset({"malicious", "suspicious"})
HARMLESS_LABELS = frozenset({"benign", "benign_unusual"})
SPLIT_SALT = "atdr-detection-scoreboard-v1"
TEST_BUCKETS = 3  # out of 10 hash buckets, so about 30% of sources are held out
BATCH_SIZE = 5000
REPORT_DIR = PROJECT_ROOT / ".tmp" / "detection_scoreboard"


class ScoreboardError(RuntimeError):
    pass


def split_for_source(src_ip: str | None) -> str:
    """Assign every log from one source to the same side, stably across runs."""

    digest = hashlib.sha256(f"{SPLIT_SALT}:{src_ip or ''}".encode("utf-8")).digest()
    return "test" if digest[0] % 10 < TEST_BUCKETS else "dev"


def confusion(pairs: list[tuple[bool, bool]]) -> dict[str, Any]:
    """Metrics from (is_threat, alerted) pairs."""

    tp = sum(1 for threat, alerted in pairs if threat and alerted)
    fp = sum(1 for threat, alerted in pairs if not threat and alerted)
    fn = sum(1 for threat, alerted in pairs if threat and not alerted)
    tn = sum(1 for threat, alerted in pairs if not threat and not alerted)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    false_alarm_rate = fp / (fp + tn) if fp + tn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None and recall is not None and precision + recall
        else None
    )
    return {
        "labeled_logs": len(pairs),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": _round(precision),
        "recall": _round(recall),
        "false_alarm_rate": _round(false_alarm_rate),
        "f1": _round(f1),
    }


def configured_sqlite_path() -> Path:
    url = make_url(get_settings().database_url)
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        raise ScoreboardError("The detection scoreboard needs a file-based SQLite database.")
    path = Path(url.database)
    return path if path.is_absolute() else (Path.cwd() / path)


def run_detection_scoreboard(
    *,
    source: Path | None = None,
    work_dir: Path | None = None,
    report_dir: Path | None = None,
    keep_copy: bool = False,
    batch_size: int = BATCH_SIZE,
) -> dict[str, Any]:
    source = (source or configured_sqlite_path()).resolve()
    if not source.exists():
        raise ScoreboardError(f"Database file not found: {source.name}")
    work_dir = (work_dir or REPORT_DIR / "work").resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    copy_path = work_dir / f"scoreboard-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%f')}.db"

    started = time.perf_counter()
    snapshot_database(source, copy_path)
    engine = create_engine(f"sqlite:///{copy_path.as_posix()}", future=True)
    try:
        with sessionmaker(bind=engine, future=True)() as db:
            _reset_detection_state(db)
            run = run_all_detection(db, batch_size=batch_size)
            report = build_scoreboard(db)
        report["run"] = {**run, "seconds": round(time.perf_counter() - started, 1)}
        report["source_database"] = source.name
    finally:
        engine.dispose()
        if not keep_copy:
            copy_path.unlink(missing_ok=True)

    report_path = write_report(report, report_dir or REPORT_DIR)
    report["report_path"] = str(report_path)
    return report


def snapshot_database(source: Path, target: Path) -> None:
    """Copy a live SQLite database with the online backup API (reads only)."""

    if source.resolve() == target.resolve():
        raise ScoreboardError("Refusing to write the scoreboard copy over the source database.")
    reader = sqlite3.connect(f"file:{source.as_posix()}?mode=ro", uri=True)
    writer = sqlite3.connect(target)
    try:
        reader.backup(writer)
    finally:
        writer.close()
        reader.close()


def _reset_detection_state(db: Session) -> None:
    db.execute(delete(AlertEvidence))
    db.execute(delete(AlertNote))
    db.execute(update(ResponseAction).values(alert_id=None))
    db.execute(delete(Alert))
    db.execute(update(NormalizedLog).values(last_detection_run_id=None))
    db.commit()


def run_all_detection(db: Session, *, batch_size: int = BATCH_SIZE) -> dict[str, int]:
    batches = 0
    checked = 0
    while True:
        result = run_detection(
            db,
            limit=batch_size,
            use_ml=False,
            actor="detection_scoreboard",
            only_unchecked=True,
        )
        batches += 1
        checked += int(result.get("evaluated") or 0)
        if not result.get("remaining_unchecked") or not result.get("evaluated"):
            return {"logs_checked": checked, "batches": batches, "batch_size": batch_size}


def build_scoreboard(db: Session) -> dict[str, Any]:
    """Compare the alerts currently in `db` with its human-reviewed labels."""

    alerted: dict[int, dict[str, Any]] = {}
    rules_by_log: dict[int, set[str]] = defaultdict(set)
    alerts = list(db.scalars(select(Alert)))
    for log_id, alert_type, severity, score, matched in db.execute(
        select(
            AlertEvidence.normalized_log_id,
            Alert.alert_type,
            Alert.severity,
            Alert.threat_score,
            Alert.matched_rules_json,
        ).join(Alert, Alert.id == AlertEvidence.alert_id)
    ):
        best = alerted.get(log_id)
        if best is None or score > best["score"]:
            alerted[log_id] = {"alert_type": alert_type, "severity": severity, "score": score}
        rules_by_log[log_id].update(
            str(item.get("code")) for item in (matched or []) if isinstance(item, dict) and item.get("code")
        )

    latest: dict[int, tuple[str, str, str, str | None]] = {}
    for log_id, label, attack_type, label_source, src_ip in db.execute(
        select(MLLabel.log_id, MLLabel.label, MLLabel.attack_type, MLLabel.label_source, NormalizedLog.src_ip)
        .join(NormalizedLog, NormalizedLog.id == MLLabel.log_id)
        .where(MLLabel.reviewed.is_(True))
        .order_by(MLLabel.id)
    ):
        latest[int(log_id)] = (label, attack_type, label_source, src_ip)

    rows = []
    excluded = Counter()
    for log_id, (label, attack_type, label_source, src_ip) in latest.items():
        if label not in THREAT_LABELS and label not in HARMLESS_LABELS:
            excluded[label] += 1
            continue
        rows.append(
            {
                "threat": label in THREAT_LABELS,
                "alerted": log_id in alerted,
                "split": split_for_source(src_ip),
                "manual": label_source == "manual",
                "attack_type": attack_type,
                "alert_type": (alerted.get(log_id) or {}).get("alert_type"),
                "rules": rules_by_log.get(log_id, set()),
            }
        )

    def pairs(items: list[dict[str, Any]]) -> list[tuple[bool, bool]]:
        return [(row["threat"], row["alerted"]) for row in items]

    by_alert_type: dict[str, Counter] = defaultdict(Counter)
    by_rule: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        if row["alert_type"]:
            by_alert_type[row["alert_type"]]["threat" if row["threat"] else "harmless"] += 1
        for code in row["rules"]:
            by_rule[code]["threat" if row["threat"] else "harmless"] += 1

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "labels": {
            "used": len(rows),
            "threat": sum(1 for row in rows if row["threat"]),
            "harmless": sum(1 for row in rows if not row["threat"]),
            "excluded": dict(excluded),
        },
        "split": {
            "method": "sha256(salt:source_ip) group split",
            "salt": SPLIT_SALT,
            "test_share": TEST_BUCKETS / 10,
            "dev_logs": sum(1 for row in rows if row["split"] == "dev"),
            "test_logs": sum(1 for row in rows if row["split"] == "test"),
        },
        "overall": {
            "all": confusion(pairs(rows)),
            "manual_labels": confusion(pairs([row for row in rows if row["manual"]])),
            "dev": confusion(pairs([row for row in rows if row["split"] == "dev"])),
            "test": confusion(pairs([row for row in rows if row["split"] == "test"])),
        },
        "by_alert_type": _precision_table(by_alert_type),
        "by_rule": _precision_table(by_rule),
        "missed_threats_by_attack_type": dict(
            Counter(row["attack_type"] for row in rows if row["threat"] and not row["alerted"]).most_common()
        ),
        "alerts": {
            "total": len(alerts),
            "by_severity": dict(Counter(alert.severity for alert in alerts).most_common()),
            "by_type": dict(Counter(alert.alert_type for alert in alerts).most_common()),
        },
    }


def write_report(report: dict[str, Any], report_dir: Path) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = report_dir / f"scoreboard-{stamp}.json"
    text = json.dumps(report, indent=2, default=str)
    path.write_text(text, encoding="utf-8")
    (report_dir / "latest.json").write_text(text, encoding="utf-8")
    return path


def _precision_table(counts: dict[str, Counter]) -> dict[str, dict[str, Any]]:
    table = {}
    for key, counter in sorted(counts.items(), key=lambda item: -sum(item[1].values())):
        total = counter["threat"] + counter["harmless"]
        table[key] = {
            "labeled_logs": total,
            "threat": counter["threat"],
            "harmless": counter["harmless"],
            "precision": _round(counter["threat"] / total if total else None),
        }
    return table


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 4)
