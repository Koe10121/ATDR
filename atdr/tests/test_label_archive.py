"""Labels made before their log was imported describe other records: they are archived in full, not used."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select

from atdr.app.db.models import AuditLog, MLLabel, MLLabelArchive, NormalizedLog, RawLog
from atdr.app.services.label_archive_service import archive_misattached_labels, misattached_labels
from atdr.tests.test_detection_grouping import _session

IMPORTED = datetime(2026, 5, 27, 3, 0)


def _log(db, index: int) -> int:
    raw = RawLog(raw_line=f"record {index}", imported_at=IMPORTED)
    db.add(raw)
    db.flush()
    log = NormalizedLog(raw_log_id=raw.id, src_ip=f"10.9.1.{index}", parsed_json={})
    db.add(log)
    db.flush()
    return int(log.id)


def _label(db, log_id: int, made: datetime, note: str) -> int:
    label = MLLabel(log_id=log_id, label="suspicious", attack_type="port_scan", confidence=3, reviewer="team",
                    review_note=note, label_source="manual", reviewed=True, created_at=made)
    db.add(label)
    db.flush()
    return int(label.id)


def test_labels_made_before_their_log_existed_are_archived_in_full():
    db = _session()
    first, second = _log(db, 1), _log(db, 2)
    stale = _label(db, first, datetime(2026, 5, 25, 8, 0), "external ICMP toward a protected host")
    current = _label(db, second, datetime(2026, 5, 31, 9, 0), "outbound scan")
    db.commit()

    assert [label.id for label in misattached_labels(db)] == [stale]
    plan = archive_misattached_labels(db, actor="koe")
    assert (plan["labels"], plan["reviewed"], plan["applied"]) == (1, 1, False)
    assert db.scalar(select(func.count(MLLabel.id))) == 2, "a dry run changes nothing"

    applied = archive_misattached_labels(db, actor="koe", apply=True)

    assert applied["applied"] is True
    assert [label.id for label in db.scalars(select(MLLabel))] == [current]
    archived = db.scalar(select(MLLabelArchive))
    assert (archived.original_label_id, archived.log_id, archived.label, archived.review_note) == (
        stale, first, "suspicious", "external ICMP toward a protected host")
    assert archived.label_created_at.replace(tzinfo=None) == datetime(2026, 5, 25, 8, 0)
    assert "re-imported" in archived.reason and archived.archived_by == "koe"
    assert db.scalar(select(AuditLog).where(AuditLog.action == "ml_labels_archived")).target_value == "1 labels"
    assert archive_misattached_labels(db, actor="koe", apply=True)["labels"] == 0, "running it again finds nothing"
