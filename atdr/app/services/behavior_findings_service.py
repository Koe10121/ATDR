"""What the MFU behaviour model sees in the stored logs, for the dashboard.

Read-only: the model runs over one 5-minute window of stored logs and never
creates or changes an alert. Each finding says what the model thinks is going
on (attack type, confidence and plain reasons), whether the rules alerted on
the same activity, the MITRE ATT&CK technique, and the response steps from
ATDR's playbooks. Every attack type stays advisory until it passes the quality
bar in docs/detection/ML_QUALITY_BAR.md.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
from sqlalchemy import Integer, cast, func, select
from sqlalchemy.orm import Session

from atdr.app.db.models import Alert, AlertEvidence, NormalizedLog, RawLog
from atdr.app.detection.attack_mapping import attack_mapping_for_type, infer_attack_type_from_rules
from atdr.app.detection.playbooks import PLAYBOOK_GUIDANCE
from atdr.app.detection.rules import P2P_SUBCATEGORY, P2P_TECHNOLOGY
from atdr.app.ml.behavior_features import LOG_COLUMNS, is_background_probe, window_features
from atdr.app.ml.behavior_model import MODEL_PATH, BehaviorModel
from atdr.app.services.assistant_data_query import ATTACK_LABELS

WINDOW = timedelta(minutes=5)
# The default window is the latest one with real traffic, not a handful of demo or test logs.
MIN_DEFAULT_WINDOW_LOGS = 1000
_MODEL_CACHE: dict[str, Any] = {}
_FINDINGS_CACHE: dict[tuple, dict[str, Any]] = {}


def load_model(path: Path = MODEL_PATH) -> BehaviorModel | None:
    if not path.exists():
        return None
    stamp = path.stat().st_mtime
    if _MODEL_CACHE.get("stamp") != stamp:
        _MODEL_CACHE.update(stamp=stamp, model=BehaviorModel.load(path))
    return _MODEL_CACHE["model"]


def model_status(model: BehaviorModel | None) -> dict[str, Any]:
    if model is None:
        return {"available": False, "detail": "No behaviour model is trained on this machine. Run python -m atdr.scripts.train_behavior_model."}
    card = model.card
    return {
        "available": True,
        "trained_from": card.get("trained_from"),
        "trained_to": card.get("trained_to"),
        "version": card.get("version"),
        "trained_at": card.get("trained_at"),
        "trained_on": card.get("trained_on"),
        "code_commit": card.get("code_commit"),
        "threshold": round(model.threshold, 4),
        "alerting_types": [],
        "detail": "Advisory: no attack type is switched on yet, so the model creates no alerts.",
    }


def _window_logs(db: Session, start: datetime, end: datetime, *, src_ip: str | None = None) -> pd.DataFrame:
    """Stored logs in [start, end), one row per distinct raw line (re-imported copies are not new traffic)."""

    first_ids = (
        select(func.min(NormalizedLog.id))
        .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
        .where(NormalizedLog.generated_time >= start, NormalizedLog.generated_time < end)
        .group_by(RawLog.raw_line_hash)
    )
    columns = [NormalizedLog.id if name == "log_id" else getattr(NormalizedLog, name) for name in LOG_COLUMNS]
    statement = select(*columns).where(NormalizedLog.id.in_(first_ids))
    if src_ip is not None:
        statement = statement.where(NormalizedLog.src_ip == src_ip)
    frame = pd.DataFrame(db.execute(statement).all(), columns=LOG_COLUMNS)
    frame["generated_time"] = pd.to_datetime(frame["generated_time"])
    return frame


def _window_pairs(db: Session, start: datetime, end: datetime) -> pd.DataFrame:
    """Who talked to which destination in [start, end): the context for one source's features."""

    rows = db.execute(
        select(NormalizedLog.dst_ip, NormalizedLog.src_ip)
        .where(NormalizedLog.generated_time >= start, NormalizedLog.generated_time < end,
               NormalizedLog.src_ip.is_not(None), NormalizedLog.dst_ip.is_not(None))
        .distinct()
    ).all()
    pairs = pd.DataFrame(rows, columns=["dst_ip", "src_ip"])
    pairs.insert(0, "window", pd.Timestamp(start))
    return pairs


def available_windows(db: Session, *, limit: int = 24) -> list[dict[str, Any]]:
    """The most recent 5-minute windows that hold logs, newest first, with their log counts."""

    minute = cast(func.strftime("%M", NormalizedLog.generated_time), Integer)
    bucket = func.printf("%s%02d", func.strftime("%Y-%m-%d %H:", NormalizedLog.generated_time), (minute // 5) * 5)
    rows = db.execute(
        select(bucket.label("bucket"), func.count(NormalizedLog.id))
        .where(NormalizedLog.generated_time.is_not(None))
        .group_by("bucket")
        .order_by(bucket.desc())
        .limit(limit)
    ).all()
    return [{"start": datetime.strptime(value, "%Y-%m-%d %H:%M").isoformat(), "logs": int(count)} for value, count in rows]


def latest_window_start(db: Session) -> datetime | None:
    windows = available_windows(db, limit=200)
    busy = [window for window in windows if window["logs"] >= MIN_DEFAULT_WINDOW_LOGS]
    chosen = (busy or windows)[:1]
    return datetime.fromisoformat(chosen[0]["start"]) if chosen else None


def _response(attack_type: str) -> dict[str, Any]:
    mapping = attack_mapping_for_type(attack_type)
    guidance = PLAYBOOK_GUIDANCE.get(attack_type)
    return {
        "mitre": {key: mapping.get(key) for key in ("tactic", "technique", "technique_id")},
        "objective": guidance.objective if guidance else None,
        "containment": list(guidance.containment) if guidance else [],
        "false_positive_when": guidance.false_positive_when if guidance else None,
        "escalate_when": guidance.escalate_when if guidance else None,
    }


def _in_training(model: BehaviorModel, start: datetime, end: datetime) -> bool:
    trained_from, trained_to = model.card.get("trained_from"), model.card.get("trained_to")
    if not trained_from or not trained_to:
        return False
    return start < datetime.fromisoformat(trained_to) and end > datetime.fromisoformat(trained_from)


def window_findings(db: Session, window_start: datetime | None = None, *, model: BehaviorModel | None = None, limit: int = 50) -> dict[str, Any]:
    model = model or load_model()
    start = window_start or latest_window_start(db)
    if model is None or start is None:
        return {"model": model_status(model), "window": None, "windows": available_windows(db), "findings": [], "summary": None}
    end = start + WINDOW
    cache_key = (start.isoformat(), id(model), db.scalar(select(func.max(NormalizedLog.id))), limit)
    if cache_key in _FINDINGS_CACHE:
        return _FINDINGS_CACHE[cache_key]

    logs = _window_logs(db, start, end)
    if logs.empty:
        return {"model": model_status(model), "window": {"start": start.isoformat(), "end": end.isoformat()},
                "windows": available_windows(db), "findings": [], "summary": None}
    features, evidence = window_features(logs)
    prediction = model.predict(features)
    alerts_by_log: dict[int, set[int]] = {}
    window_ids = logs["log_id"].tolist()
    for chunk in range(0, len(window_ids), 900):
        for alert_id, log_id in db.execute(
            select(AlertEvidence.alert_id, AlertEvidence.normalized_log_id).where(
                AlertEvidence.normalized_log_id.in_(window_ids[chunk:chunk + 900])
            )
        ):
            alerts_by_log.setdefault(int(log_id), set()).add(int(alert_id))

    flagged = prediction[prediction["flagged"]].sort_values("attack_probability", ascending=False)
    findings = []
    for index, row in flagged.head(limit).iterrows():
        src_ip, window = index
        attack_type = str(row["attack_type"])
        alert_ids = sorted({alert for log_id in evidence.loc[index] for alert in alerts_by_log.get(int(log_id), ())})
        findings.append({
            "source": src_ip,
            "window_start": pd.Timestamp(window).isoformat(),
            "attack_type": attack_type,
            "attack_label": ATTACK_LABELS.get(attack_type, attack_type),
            "confidence": round(float(row["attack_probability"]), 4),
            "connections": int(features.at[index, "n_logs"]),
            "reasons": model.explain(features.loc[index], attack_type),
            "found_by": "rules_and_model" if alert_ids else "model_only",
            "alert_ids": alert_ids[:10],
            "status": "advisory",
            "response": _response(attack_type),
        })

    p2p_logs = logs[
        logs["app_technology"].fillna("").str.lower().eq(P2P_TECHNOLOGY)
        & logs["app_subcategory"].fillna("").str.lower().eq(P2P_SUBCATEGORY)
    ]
    p2p_apps = Counter(str(app) for app in p2p_logs["app"].dropna())
    background = prediction["background_probe"]
    probe_sources = [index[0] for index in prediction.index[background]]
    probe_logs = logs[logs["src_ip"].isin(probe_sources)]
    ports = Counter(int(port) for port in probe_logs["dst_port"].dropna())
    result = {
        "model": model_status(model),
        "window": {"start": start.isoformat(), "end": end.isoformat(), "in_training_data": _in_training(model, start, end)},
        "windows": available_windows(db),
        "findings": findings,
        "summary": {
            "sources_checked": int(len(features)),
            "flagged": int(len(flagged)),
            "model_only": int(sum(1 for finding in findings if finding["found_by"] == "model_only")),
            "by_type": dict(Counter(flagged["attack_type"].astype(str))),
            "background_probing": {
                "sources": len(probe_sources),
                "connections": int(len(probe_logs)),
                "mfu_hosts_touched": int(probe_logs["dst_ip"].nunique()),
                "top_ports": [{"port": port, "connections": count} for port, count in ports.most_common(5)],
            },
            "p2p_policy": {
                "sources": int(p2p_logs["src_ip"].nunique()),
                "connections": int(len(p2p_logs)),
                "peers": int(p2p_logs["dst_ip"].nunique()),
                "bytes": int(p2p_logs["bytes_sent"].fillna(0).sum() + p2p_logs["bytes_received"].fillna(0).sum()),
                "apps": [{"app": app, "connections": count} for app, count in p2p_apps.most_common(5)],
            },
        },
    }
    if len(_FINDINGS_CACHE) > 32:
        _FINDINGS_CACHE.clear()
    _FINDINGS_CACHE[cache_key] = result
    return result


def alert_opinion(db: Session, alert_id: int, *, model: BehaviorModel | None = None) -> dict[str, Any] | None:
    """The model's view of the source behind one alert, in the 5-minute window(s) of its evidence."""

    model = model or load_model()
    alert = db.get(Alert, alert_id)
    if model is None or alert is None or not alert.src_ip:
        return None
    times = db.scalars(
        select(NormalizedLog.generated_time)
        .join(AlertEvidence, AlertEvidence.normalized_log_id == NormalizedLog.id)
        .where(AlertEvidence.alert_id == alert_id, NormalizedLog.generated_time.is_not(None))
    ).all()
    windows = sorted({pd.Timestamp(value).floor("5min").to_pydatetime() for value in times})[:3]
    best = None
    for start in windows:
        logs = _window_logs(db, start, start + WINDOW, src_ip=alert.src_ip)
        if logs.empty:
            continue
        features, _evidence = window_features(logs, context_pairs=_window_pairs(db, start, start + WINDOW))
        prediction = model.predict(features)
        index = (alert.src_ip, pd.Timestamp(start))
        if index not in prediction.index:
            continue
        row = prediction.loc[index]
        if best is None or row["attack_probability"] > best[1]["attack_probability"]:
            best = (index, row, features.loc[index])
    if best is None:
        return None
    index, row, feature_row = best
    attack_type = str(row["attack_type"])
    rules_type = infer_attack_type_from_rules(alert.matched_rules_json or [])
    return {
        "alert_id": alert_id,
        "window_start": pd.Timestamp(index[1]).isoformat(),
        "attack_type": attack_type,
        "attack_label": ATTACK_LABELS.get(attack_type, attack_type),
        "confidence": round(float(row["attack_probability"]), 4),
        "flagged": bool(row["flagged"]),
        "background_probe": bool(row["background_probe"]),
        "p2p_policy": bool(row["p2p_policy"]),
        "wrong_direction": bool(row["wrong_direction"]),
        "agrees_with_rules": bool(row["flagged"]) and attack_type == rules_type,
        "rules_attack_type": rules_type,
        "reasons": model.explain(feature_row, attack_type) if row["flagged"] else [],
        "status": "advisory",
        "model": model_status(model),
    }
