"""Blind detection check: an honest accuracy estimate on MFU traffic nobody tuned on.

The detection scoreboard compares the rules with labels the team made while
the rules were being tuned, often after seeing ATDR's verdict, so it is
optimistic. This check avoids both problems:

1. ``build_holdout_database`` imports a later slice of the MFU log file into a
   separate, fresh SQLite database with the same parser and storage code as a
   normal import. The live database is never touched.
2. The current rules run over that database (``run_all_detection``).
3. ``draw_blind_sample`` takes a stratified random sample of logs from one test
   window: logs the rules alerted on, logs they did not alert on but that look
   notable from raw fields alone, and all other logs. The labeling rows carry
   plain traffic facts and context only, never ATDR's verdict, and are shuffled
   so the stratum cannot be guessed from the order. The verdicts go into a
   separate key.
4. ``score_blind_check`` turns the team's labels into precision, recall and
   false-alarm rate for the whole window, weighting each stratum by its size,
   with bootstrap confidence intervals.
"""

from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from itertools import islice
from pathlib import Path
from typing import Any, Callable, Iterable

from sqlalchemy import create_engine, func, inspect, select
from sqlalchemy.orm import Session, sessionmaker

from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AlertEvidence, NormalizedLog, RawLog
from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
from atdr.app.services.detection_scoreboard_service import reset_detection_state, run_all_detection
from atdr.app.services.log_service import persist_parsed_log
from atdr.app.services.source_service import get_or_create_source

STRATA = ("alerted", "notable", "other")
DEFAULT_SAMPLE_SIZES = {"alerted": 60, "notable": 45, "other": 45}
DEFAULT_SEED = 20260927
CONTEXT_RADIUS = timedelta(seconds=150)
DENY_ACTION_PREFIXES = ("deny", "drop", "reset", "block")
UNKNOWN_APPS = frozenset({"unknown-tcp", "unknown-udp", "unknown-p2p", "incomplete", "insufficient-data", "not-applicable"})
DECISIONS = {
    "threat": "threat",
    "t": "threat",
    "real threat": "threat",
    "normal": "harmless",
    "n": "harmless",
    "normal but unusual": "harmless",
    "unusual": "harmless",
    "u": "harmless",
    "unsure": None,
    "?": None,
}


class BlindCheckError(RuntimeError):
    pass


# ------------------------------------------------------------------ holdout


def build_holdout_database(
    log_file: Path,
    target: Path,
    *,
    first_line: int,
    last_line: int,
    parser_profile: str = "palo_alto",
    chunk: int = 5000,
) -> dict[str, int]:
    """Import lines first_line..last_line (1-based, inclusive) into a new database."""

    if target.exists():
        raise BlindCheckError(f"{target.name} already exists; delete it to rebuild the holdout.")
    target.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{target.as_posix()}", future=True)
    Base.metadata.create_all(engine)
    imported = failed = 0
    try:
        with sessionmaker(bind=engine, future=True)() as db:
            source = get_or_create_source(db, name="mfu-holdout", source_type="file_import", parser_profile=parser_profile)
            db.commit()
            with log_file.open("r", encoding="utf-8", errors="replace", newline="") as stream:
                for line in islice(stream, first_line - 1, last_line):
                    if not line.strip():
                        continue
                    parsed = parse_log_line_for_profile(line, source.parser_profile)
                    persist_parsed_log(db, parsed, source_id=source.id)
                    imported += 1
                    failed += int(bool(parsed.error))
                    if imported % chunk == 0:
                        db.commit()
            db.commit()
    finally:
        engine.dispose()
    return {"imported": imported, "parse_failures": failed, "first_line": first_line, "last_line": last_line}


def sync_scratch_schema(engine) -> list[str]:
    """Bring a scratch database built with create_all up to the current models.

    Holdout and training databases are made from the models, not migrations, so a later model
    change (a new table, a new nullable column) would otherwise break detection on them.
    """

    Base.metadata.create_all(engine)
    added = []
    existing_tables = set(inspect(engine).get_table_names())
    with engine.begin() as connection:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            present = {column["name"] for column in inspect(connection).get_columns(table.name)}
            for column in table.columns:
                if column.name in present:
                    continue
                if not column.nullable and column.server_default is None:
                    raise ValueError(f"{table.name}.{column.name} is required and cannot be added to existing rows.")
                column_type = column.type.compile(dialect=engine.dialect)
                connection.exec_driver_sql(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {column_type}')
                added.append(f"{table.name}.{column.name}")
    return added


def detect_holdout(target: Path, *, rerun: bool = False) -> dict[str, int]:
    """Run the rules over every unchecked log. With ``rerun``, clear earlier alerts first so every log
    is judged by the rules as they are now (a database checked under an older catalog keeps its old
    alerts otherwise)."""

    engine = create_engine(f"sqlite:///{target.as_posix()}", future=True)
    try:
        sync_scratch_schema(engine)
        with sessionmaker(bind=engine, future=True)() as db:
            if rerun:
                reset_detection_state(db)
            return run_all_detection(db)
    finally:
        engine.dispose()


# ------------------------------------------------------------------ sample


@dataclass(frozen=True, slots=True)
class Candidate:
    log_id: int
    stratum: str


def is_notable(action: str | None, app: str | None, app_risk: int | None, log_type: str | None) -> bool:
    """Looks worth a second glance from raw firewall fields alone (no rule output)."""

    return (
        str(action or "").lower().startswith(DENY_ACTION_PREFIXES)
        or (app_risk or 0) >= 4
        or str(app or "").lower() in UNKNOWN_APPS
        or str(log_type or "").upper() == "THREAT"
    )


def _window_candidates(db: Session, start: datetime, end: datetime) -> list[Candidate]:
    alerted = set(db.scalars(select(AlertEvidence.normalized_log_id).distinct()))
    # One row per distinct raw line: a line imported twice is still one event.
    first_ids = (
        select(func.min(NormalizedLog.id))
        .join(RawLog, RawLog.id == NormalizedLog.raw_log_id)
        .where(NormalizedLog.generated_time >= start, NormalizedLog.generated_time < end)
        .group_by(RawLog.raw_line_hash)
    )
    rows = db.execute(
        select(NormalizedLog.id, NormalizedLog.action, NormalizedLog.app, NormalizedLog.app_risk, NormalizedLog.log_type)
        .where(NormalizedLog.id.in_(first_ids))
    )
    candidates = []
    for log_id, action, app, app_risk, log_type in rows:
        if log_id in alerted:
            stratum = "alerted"
        elif is_notable(action, app, app_risk, log_type):
            stratum = "notable"
        else:
            stratum = "other"
        candidates.append(Candidate(int(log_id), stratum))
    return candidates


def _verdict(db: Session, log_id: int) -> dict[str, Any]:
    alerts = list(
        db.execute(
            select(Alert.id, Alert.alert_type, Alert.severity, Alert.threat_score, Alert.matched_rules_json)
            .join(AlertEvidence, AlertEvidence.alert_id == Alert.id)
            .where(AlertEvidence.normalized_log_id == log_id)
        )
    )
    return {
        "alerted": bool(alerts),
        "alert_types": sorted({row.alert_type for row in alerts}),
        "max_score": max((row.threat_score for row in alerts), default=None),
        "rules": sorted({
            str(item.get("code")) for row in alerts for item in (row.matched_rules_json or [])
            if isinstance(item, dict) and item.get("code")
        }),
    }


def _context(db: Session, log: NormalizedLog) -> dict[str, Any]:
    """Plain traffic facts around one log, computed from raw fields only."""

    if log.generated_time is None:
        return {}
    around = (
        NormalizedLog.generated_time >= log.generated_time - CONTEXT_RADIUS,
        NormalizedLog.generated_time <= log.generated_time + CONTEXT_RADIUS,
    )
    same_source = [
        *around,
        NormalizedLog.src_ip == log.src_ip,
    ]
    stats = db.execute(
        select(
            func.count(NormalizedLog.id),
            func.count(func.distinct(NormalizedLog.dst_ip)),
            func.count(func.distinct(NormalizedLog.dst_port)),
            func.sum(NormalizedLog.bytes),
        ).where(*same_source)
    ).one()
    denied = db.scalar(
        select(func.count(NormalizedLog.id)).where(
            *same_source,
            func.lower(NormalizedLog.action).like("deny%") | func.lower(NormalizedLog.action).like("drop%")
            | func.lower(NormalizedLog.action).like("reset%"),
        )
    )
    apps = Counter(
        dict(
            db.execute(
                select(NormalizedLog.app, func.count(NormalizedLog.id))
                .where(*same_source)
                .group_by(NormalizedLog.app)
            ).all()
        )
    )
    to_same_service = db.scalar(
        select(func.count(func.distinct(NormalizedLog.src_ip))).where(
            *around, NormalizedLog.dst_ip == log.dst_ip, NormalizedLog.dst_port == log.dst_port
        )
    )
    return {
        "source_logs_5min": int(stats[0] or 0),
        "source_distinct_destinations": int(stats[1] or 0),
        "source_distinct_ports": int(stats[2] or 0),
        "source_denied_or_reset": int(denied or 0),
        "source_total_bytes": int(stats[3] or 0),
        "source_top_apps": ", ".join(f"{app or 'unknown'} ({count})" for app, count in apps.most_common(3)),
        "sources_to_same_destination_port": int(to_same_service or 0),
    }


def _blind_row(db: Session, sample_id: str, log: NormalizedLog) -> dict[str, Any]:
    parsed = log.parsed_json or {}
    threat = " / ".join(
        str(parsed[key]) for key in ("parsed_threat_name", "parsed_threat_severity", "parsed_threat_direction") if parsed.get(key)
    )
    return {
        "sample_id": sample_id,
        "time": log.generated_time.strftime("%H:%M:%S") if log.generated_time else "",
        "log_type": " ".join(part for part in (log.log_type, log.subtype) if part),
        "action": log.action,
        "source": f"{log.src_ip}:{log.src_port}" if log.src_port is not None else log.src_ip,
        "source_zone": log.src_zone,
        "source_country": log.src_country,
        "destination": f"{log.dst_ip}:{log.dst_port}" if log.dst_port is not None else log.dst_ip,
        "destination_zone": log.dst_zone,
        "destination_country": log.dst_country,
        "protocol": log.protocol,
        "app": log.app,
        "app_category": " / ".join(part for part in (log.app_category, log.app_subcategory) if part),
        "app_risk": log.app_risk,
        "bytes_sent": log.bytes_sent,
        "bytes_received": log.bytes_received,
        "packets": log.packets,
        "elapsed_seconds": log.elapsed_time,
        "session_end_reason": log.session_end_reason,
        "firewall_rule": log.rule_name,
        "firewall_threat": threat,
        **_context(db, log),
    }


def draw_blind_sample(
    target: Path,
    *,
    window_start: datetime,
    window_end: datetime,
    sizes: dict[str, int] | None = None,
    seed: int = DEFAULT_SEED,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return (blind labeling rows, key). Only the key holds ATDR's verdicts."""

    sizes = {**DEFAULT_SAMPLE_SIZES, **(sizes or {})}
    rng = random.Random(seed)
    engine = create_engine(f"sqlite:///{target.as_posix()}", future=True)
    try:
        with sessionmaker(bind=engine, future=True)() as db:
            candidates = _window_candidates(db, window_start, window_end)
            by_stratum: dict[str, list[int]] = defaultdict(list)
            for candidate in candidates:
                by_stratum[candidate.stratum].append(candidate.log_id)
            chosen: list[tuple[str, int]] = []
            for stratum in STRATA:
                ids = sorted(by_stratum[stratum])
                take = min(sizes[stratum], len(ids))
                chosen.extend((stratum, log_id) for log_id in rng.sample(ids, take))
            rng.shuffle(chosen)
            rows, entries = [], []
            for index, (stratum, log_id) in enumerate(chosen, start=1):
                sample_id = f"B{index:03d}"
                log = db.get(NormalizedLog, log_id)
                rows.append(_blind_row(db, sample_id, log))
                entries.append({"sample_id": sample_id, "log_id": log_id, "stratum": stratum, **_verdict(db, log_id)})
    finally:
        engine.dispose()
    key = {
        "window": {"start": window_start.isoformat(sep=" "), "end": window_end.isoformat(sep=" ")},
        "seed": seed,
        "population": {stratum: len(by_stratum[stratum]) for stratum in STRATA},
        "sampled": dict(Counter(entry["stratum"] for entry in entries)),
        "samples": entries,
    }
    return rows, key


# ------------------------------------------------------------------ score


def normalise_decision(value: Any) -> str | None:
    text = " ".join(str(value or "").strip().lower().split())
    if text not in DECISIONS:
        raise BlindCheckError(f"Unknown decision {value!r}; use Threat, Normal, Normal but unusual or Unsure.")
    return DECISIONS[text]


def _estimate(outcomes: dict[str, list[tuple[bool, bool]]], population: dict[str, int]) -> dict[str, float | None]:
    """Window-wide rates from (threat, flagged) pairs, each stratum scaled to its population."""

    caught = missed = false_alarms = quiet = 0.0
    for stratum in STRATA:
        pairs = outcomes.get(stratum) or []
        if not pairs:
            if population.get(stratum):
                return {"precision": None, "recall": None, "false_alarm_rate": None, "f1": None}
            continue
        scale = population[stratum] / len(pairs)
        caught += scale * sum(1 for threat, flagged in pairs if threat and flagged)
        missed += scale * sum(1 for threat, flagged in pairs if threat and not flagged)
        false_alarms += scale * sum(1 for threat, flagged in pairs if flagged and not threat)
        quiet += scale * sum(1 for threat, flagged in pairs if not threat and not flagged)
    precision = caught / (caught + false_alarms) if caught + false_alarms else None
    recall = caught / (caught + missed) if caught + missed else None
    false_alarm = false_alarms / (false_alarms + quiet) if false_alarms + quiet else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else None
    return {"precision": precision, "recall": recall, "false_alarm_rate": false_alarm, "f1": f1}


def _interval(values: Iterable[float | None]) -> list[float] | None:
    kept = sorted(value for value in values if value is not None)
    if len(kept) < 20:
        return None
    return [round(kept[int(0.025 * (len(kept) - 1))], 4), round(kept[int(0.975 * (len(kept) - 1))], 4)]


def score_blind_check(
    key: dict[str, Any],
    decisions: dict[str, Any],
    *,
    flagged: Callable[[dict[str, Any]], bool] | None = None,
    resamples: int = 2000,
    seed: int = 7,
) -> dict[str, Any]:
    """Estimate precision, recall and false-alarm rate for the whole test window.

    ``flagged`` decides which sampled logs count as detected; by default the
    rules' alerts. Pass another test to score the model, or rules or model.
    """

    is_flagged = flagged or (lambda entry: bool(entry["alerted"]))
    outcomes: dict[str, list[tuple[bool, bool]]] = defaultdict(list)
    unsure = missing = 0
    sample_rows = []
    for entry in key["samples"]:
        raw = decisions.get(entry["sample_id"])
        if raw in (None, ""):
            missing += 1
            continue
        decision = normalise_decision(raw)
        if decision is None:
            unsure += 1
            continue
        outcomes[entry["stratum"]].append((decision == "threat", is_flagged(entry)))
        sample_rows.append((entry, decision == "threat"))
    population = key["population"]
    point = _estimate(outcomes, population)

    rng = random.Random(seed)
    draws: dict[str, list[float | None]] = defaultdict(list)
    for _ in range(resamples):
        resampled = {stratum: [rng.choice(labels) for _ in labels] for stratum, labels in outcomes.items()}
        for metric, value in _estimate(resampled, population).items():
            draws[metric].append(value)

    by_stratum = {
        stratum: {
            "population": population.get(stratum, 0),
            "labeled": len(outcomes.get(stratum) or []),
            "threat": sum(1 for threat, _flagged in outcomes.get(stratum) or [] if threat),
        }
        for stratum in STRATA
    }
    missed = Counter()
    wrong = Counter()
    for entry, threat in sample_rows:
        if threat and not is_flagged(entry):
            missed[entry["stratum"]] += 1
        if is_flagged(entry) and not threat:
            for alert_type in entry["alert_types"] or ["unknown"]:
                wrong[alert_type] += 1
    return {
        "window": key["window"],
        "labels": {"used": len(sample_rows), "unsure": unsure, "missing": missing},
        "by_stratum": by_stratum,
        "estimate": {metric: None if value is None else round(value, 4) for metric, value in point.items()},
        "interval_95": {metric: _interval(values) for metric, values in draws.items()},
        "false_alarms_by_alert_type": dict(wrong.most_common()),
        "missed_threats_by_stratum": dict(missed),
        "method": (
            "Stratified random sample labeled without ATDR's verdict; each stratum's threat share is scaled to its "
            f"population; 95% intervals from {resamples} bootstrap resamples within strata. 'Unsure' labels are left out."
        ),
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
