"""The blind check must hide ATDR's verdict, sample fairly, and weight strata correctly."""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.core.log_fingerprint import raw_line_fingerprint
from atdr.app.db.database import Base
from atdr.app.db.models import Alert, AlertEvidence, NormalizedLog, RawLog
from atdr.app.services.blind_check_service import (
    BlindCheckError,
    build_holdout_database,
    draw_blind_sample,
    normalise_decision,
    score_blind_check,
)

START = datetime(2026, 5, 20, 13, 50)


def _key(population, samples):
    return {"window": {"start": "s", "end": "e"}, "population": population, "samples": samples}


def test_each_stratum_is_scaled_by_its_population():
    samples, decisions = [], {}
    for stratum, threats, total in [("alerted", 8, 10), ("notable", 1, 10), ("other", 0, 10)]:
        for index in range(total):
            sample_id = f"{stratum}-{index}"
            samples.append({"sample_id": sample_id, "stratum": stratum, "alerted": stratum == "alerted", "alert_types": ["possible_port_scan"]})
            decisions[sample_id] = "Threat" if index < threats else ("Normal but unusual" if index % 2 else "Normal")
    samples.append({"sample_id": "x", "stratum": "other", "alerted": False, "alert_types": []})
    decisions["x"] = "Unsure"
    report = score_blind_check(_key({"alerted": 100, "notable": 1000, "other": 10000}, samples), decisions, resamples=200)

    # Threats: 100*0.8 + 1000*0.1 + 0 = 180, of which 80 were alerted.
    assert report["estimate"]["precision"] == 0.8
    assert report["estimate"]["recall"] == round(80 / 180, 4)
    assert report["estimate"]["false_alarm_rate"] == round(20 / (20 + 900 + 10000), 4)
    assert report["labels"] == {"used": 30, "unsure": 1, "missing": 0}
    assert report["false_alarms_by_alert_type"] == {"possible_port_scan": 2}
    assert report["missed_threats_by_stratum"] == {"notable": 1}
    low, high = report["interval_95"]["precision"]
    assert low <= 0.8 <= high


def test_unknown_decisions_are_rejected():
    assert normalise_decision("  normal BUT unusual ") == "harmless"
    assert normalise_decision("?") is None
    with pytest.raises(BlindCheckError):
        normalise_decision("maybe")


def _holdout(tmp_path):
    path = tmp_path / "holdout.db"
    engine = create_engine(f"sqlite:///{path.as_posix()}", future=True)
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine, future=True)() as db:
        def log(line, *, minute, action="allow", app="ssl", risk=2, src="10.0.0.5", port=443):
            raw = RawLog(raw_line=line, raw_line_hash=raw_line_fingerprint(line))
            db.add(raw)
            db.flush()
            row = NormalizedLog(
                raw_log_id=raw.id, generated_time=START + timedelta(minutes=minute), log_type="TRAFFIC",
                action=action, app=app, app_risk=risk, src_ip=src, dst_ip="10.9.9.9", dst_port=port, bytes=100,
                parsed_json={},
            )
            db.add(row)
            db.flush()
            return row

        scans = [log(f"scan {port}", minute=1, action="deny", app="incomplete", src="203.0.113.7", port=port) for port in range(20, 26)]
        for index in range(6):
            log(f"deny {index}", minute=2, action="deny")
        for index in range(8):
            log(f"normal {index}", minute=3)
        log("normal 0", minute=3)  # the same raw line imported twice
        log("before the window", minute=-1)
        log("after the window", minute=6)
        alert = Alert(title="scan", alert_type="possible_port_scan", threat_score=90, severity="Critical", status="open",
                      explanation="x", matched_rules_json=[{"code": "possible_port_scan"}], recommended_response="-")
        db.add(alert)
        db.flush()
        for row in scans:
            db.add(AlertEvidence(alert_id=alert.id, normalized_log_id=row.id))
        db.commit()
    engine.dispose()
    return path


def test_the_sample_is_blind_shuffled_deduplicated_and_reproducible(tmp_path):
    holdout = _holdout(tmp_path)
    sizes = {"alerted": 3, "notable": 3, "other": 3}
    rows, key = draw_blind_sample(holdout, window_start=START, window_end=START + timedelta(minutes=5), sizes=sizes, seed=11)

    assert key["population"] == {"alerted": 6, "notable": 6, "other": 8}
    assert key["sampled"] == {"alerted": 3, "notable": 3, "other": 3}
    text = json.dumps(rows)
    for hidden in ("possible_port_scan", "alerted", "stratum", "threat_score", "severity", "Critical"):
        assert hidden not in text
    assert [row["sample_id"] for row in rows] == [f"B{index:03d}" for index in range(1, 10)]
    strata = [entry["stratum"] for entry in key["samples"]]
    assert strata != sorted(strata, key=["alerted", "notable", "other"].index)
    assert all(entry["alerted"] == (entry["stratum"] == "alerted") for entry in key["samples"])
    scan_row = next(row for row, entry in zip(rows, key["samples"]) if entry["stratum"] == "alerted")
    assert scan_row["source_distinct_ports"] == 6 and scan_row["source_denied_or_reset"] == 6

    again, same_key = draw_blind_sample(holdout, window_start=START, window_end=START + timedelta(minutes=5), sizes=sizes, seed=11)
    assert again == rows and same_key == key


def test_the_holdout_is_a_new_database_that_is_never_overwritten(tmp_path):
    sample = PROJECT_ROOT / "data" / "samples" / "paloalto-demo.txt"
    target = tmp_path / "holdout.db"
    assert build_holdout_database(sample, target, first_line=1, last_line=2)["imported"] == 2
    with pytest.raises(BlindCheckError):
        build_holdout_database(sample, target, first_line=1, last_line=2)
