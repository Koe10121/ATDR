"""Take labels out of use when they no longer describe the log they point at, keeping each one in full.

The logs were wiped and imported again on 27 May. Labels made before that kept their log ids, and the
new import gave those ids to other firewall records, so the 23-25 May labels sit on logs they were
not made for: their notes contradict their logs 51-98% of the time, later labels' notes 0-4%. A label
made before its log was imported cannot be about that log.

Archived labels move to ``ml_label_archive`` with the reason and who did it, and leave every count,
the model's training data and the log pages. Nothing is deleted without its archive row.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from atdr.app.db.models import AuditLog, MLLabel, MLLabelArchive, NormalizedLog, RawLog

REASON = (
    "Made before its log was imported: the logs were re-imported and this label's log id now belongs to a "
    "different firewall record, so the label does not describe the log it points at."
)
CHUNK = 900


def misattached_labels(db: Session) -> list[MLLabel]:
    """Labels created before the log they point at was imported."""

    return list(db.scalars(
        select(MLLabel)
        .join(NormalizedLog, NormalizedLog.id == MLLabel.log_id)
        .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
        .where(MLLabel.created_at < RawLog.imported_at)
        .order_by(MLLabel.id)
    ))


def _summary(labels: list[MLLabel]) -> dict[str, Any]:
    made = sorted(label.created_at for label in labels if label.created_at is not None)
    return {
        "labels": len(labels),
        "reviewed": sum(1 for label in labels if label.reviewed),
        "by_source": dict(Counter(label.label_source for label in labels).most_common()),
        "by_label": dict(Counter(label.label for label in labels).most_common()),
        "made_from": made[0].isoformat() if made else None,
        "made_to": made[-1].isoformat() if made else None,
    }


def archive_misattached_labels(db: Session, *, actor: str, apply: bool = False) -> dict[str, Any]:
    labels = misattached_labels(db)
    summary = {**_summary(labels), "applied": False}
    if not apply or not labels:
        return summary
    for label in labels:
        db.add(MLLabelArchive(
            original_label_id=label.id, log_id=label.log_id, label=label.label, attack_type=label.attack_type,
            confidence=label.confidence, reviewer=label.reviewer, review_note=label.review_note,
            label_source=label.label_source, reviewed=label.reviewed, label_created_at=label.created_at,
            reason=REASON, archived_by=actor,
        ))
    db.flush()
    ids = [label.id for label in labels]
    for start in range(0, len(ids), CHUNK):
        db.execute(delete(MLLabel).where(MLLabel.id.in_(ids[start:start + CHUNK])))
    summary["applied"] = True
    db.add(AuditLog(actor=actor, action="ml_labels_archived", target_type="ml_labels", target_value=f"{len(ids)} labels",
                    details={**summary, "reason": REASON}))
    db.commit()
    return summary
