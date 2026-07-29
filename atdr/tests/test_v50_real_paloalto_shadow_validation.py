from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import Base
from atdr.app.db.models import NormalizedLog, RawLog, ResponseAction
from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
from atdr.app.services.log_service import persist_parsed_log
from atdr.app.services.private_log_preflight_service import (
    preflight_private_paloalto_file,
)
from atdr.app.services.source_service import create_source, source_quality
from atdr.app.services.v50_shadow_validation_service import (
    _write_review_sample,
    run_v50_real_paloalto_shadow_validation,
)


SAFE_SCENARIO = PROJECT_ROOT / "data" / "samples" / "scenarios" / "port_scan_like_traffic.txt"


def _copy_safe_scenario(path: Path) -> list[str]:
    lines = [
        line.rstrip("\r\n")
        for line in SAFE_SCENARIO.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return lines


def test_private_preflight_reports_only_aggregate_overlap(tmp_path):
    evidence_path = tmp_path / "private-firewall.log"
    lines = _copy_safe_scenario(evidence_path)
    database_path = tmp_path / "current.sqlite3"
    engine = create_engine(f"sqlite:///{database_path}", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        source = create_source(
            db,
            name="safe-current-source",
            source_type="firewall",
            parser_profile="palo_alto",
        )
        for line in lines:
            persist_parsed_log(
                db,
                parse_log_line_for_profile(line, "palo_alto"),
                source_id=source.id,
            )
        db.commit()
    engine.dispose()

    result = preflight_private_paloalto_file(
        evidence_path,
        current_database_url=f"sqlite:///{database_path}",
    )

    serialized = json.dumps(result, default=str)
    assert result["ok"] is True
    assert result["format"] == "palo_alto_syslog_csv"
    assert result["nonblank_lines"] == len(lines)
    assert result["current_database_overlap"]["already_imported_by_fingerprint"] is True
    assert result["current_database_overlap"]["file_row_overlap_percent"] == 100.0
    assert result["path_returned"] is False
    assert result["raw_evidence_returned"] is False
    assert str(evidence_path) not in serialized
    assert lines[0] not in serialized
    assert re.search(r"\b[a-f0-9]{64}\b", serialized) is None


def test_source_quality_raw_fallback_is_redacted_and_not_an_error_example(
    tmp_path,
):
    engine = create_engine(f"sqlite:///{tmp_path / 'quality.sqlite3'}", future=True)
    Base.metadata.create_all(engine)
    private_line = "2026-07-01T12:00:00Z private-fw 192.0.2.10 secret-host-value"
    with Session(engine) as db:
        source = create_source(
            db,
            name="raw-source",
            source_type="firewall",
            parser_profile="raw_fallback",
        )
        persist_parsed_log(
            db,
            parse_log_line_for_profile(private_line, "raw_fallback"),
            source_id=source.id,
        )
        db.commit()
        quality = source_quality(db, source.id)

    serialized = json.dumps(quality, default=str)
    assert private_line not in serialized
    assert "192.0.2.10" not in serialized
    assert quality["parse_failure_examples"] == []
    engine.dispose()


def test_shadow_validation_uses_disposable_db_and_creates_no_response(tmp_path):
    evidence_path = tmp_path / "shadow-input.log"
    lines = _copy_safe_scenario(evidence_path)
    current_database_path = tmp_path / "current.sqlite3"
    current_engine = create_engine(f"sqlite:///{current_database_path}", future=True)
    Base.metadata.create_all(current_engine)
    current_engine.dispose()

    result = run_v50_real_paloalto_shadow_validation(
        evidence_path=evidence_path,
        use_temp_db=True,
        current_database_url=f"sqlite:///{current_database_path}",
        chunk_size=3,
        ml_sample_limit=10,
        write_review_sample=False,
        write_reports=False,
        run_ml=False,
        run_assistant_audit=True,
    )

    assert result["ok"] is True
    assert result["shadow_ingestion"]["raw_logs"] == len(lines)
    assert result["shadow_ingestion"]["normalized_logs"] == len(lines)
    assert result["shadow_ingestion"]["resumable_worker_path_used"] is True
    assert result["parser_quality"]["normalized_rows"] == len(lines)
    assert result["rule_detection"]["source_scoped"] is True
    assert result["rule_detection"]["created_alerts"] >= 1
    assert result["alert_noise"]["computed_cases"] >= 1
    deduplication = result["alert_noise"]["deduplication"]
    assert deduplication["occurrences_collapsed"] >= 1
    assert deduplication["grouped_related_logs_beyond_first"] >= 1
    assert deduplication["occurrence_to_alert_ratio"] > 1
    assert result["assistant_and_explanations"]["explanation_complete"] is True
    assert result["assistant_and_explanations"]["raw_log_context_included"] is False
    assert result["assistant_and_explanations"]["operational_mutations_created"] is False
    assert result["response_actions_created"] == 0
    assert result["current_database_modified"] is False
    assert result["model_activated"] is False
    assert result["model_promoted"] is False

    current_engine = create_engine(f"sqlite:///{current_database_path}", future=True)
    with Session(current_engine) as db:
        assert int(db.scalar(select(func.count(RawLog.id))) or 0) == 0
        assert int(db.scalar(select(func.count(ResponseAction.id))) or 0) == 0
    current_engine.dispose()


def test_review_sample_is_redacted_unreviewed_and_not_import_ready(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'review.sqlite3'}", future=True)
    Base.metadata.create_all(engine)
    line = next(
        item
        for item in SAFE_SCENARIO.read_text(encoding="utf-8").splitlines()
        if item.strip()
    )
    output_path = tmp_path / "review.csv"
    with Session(engine) as db:
        source = create_source(
            db,
            name="review-source",
            source_type="firewall",
            parser_profile="palo_alto",
        )
        normalized = persist_parsed_log(
            db,
            parse_log_line_for_profile(line, "palo_alto"),
            source_id=source.id,
        )
        assert normalized is not None
        original_src_ip = normalized.src_ip
        original_dst_ip = normalized.dst_ip
        db.commit()
        result = _write_review_sample(
            db,
            [
                {
                    "log_id": normalized.id,
                    "rule_score": 55.0,
                    "rule_codes": ["possible_port_scan"],
                    "rule_queue": True,
                    "isolation_is_anomaly": False,
                    "isolation_score": 0.2,
                    "supervised_predicted_label": "benign",
                    "supervised_threat_probability": 0.1,
                    "supervised_confidence": 0.8,
                    "supervised_queue": False,
                    "hybrid_score": 48.0,
                    "hybrid_queue": False,
                }
            ],
            output_path=output_path,
        )

    with output_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert result["status"] == "generated_ai_assisted_unreviewed"
    assert len(rows) == 1
    assert rows[0]["label_source"] == "ai_assisted"
    assert rows[0]["reviewed"] == "false"
    assert rows[0]["human_review_decision"] == ""
    assert rows[0]["human_must_confirm"] == "true"
    assert rows[0]["import_ready"] == "false"
    assert rows[0]["source_alias"].startswith("src-")
    assert rows[0]["destination_alias"].startswith("dst-")
    output_text = output_path.read_text(encoding="utf-8")
    assert original_src_ip not in output_text
    assert original_dst_ip not in output_text
    engine.dispose()


def test_shadow_validation_requires_explicit_temp_database(tmp_path):
    evidence_path = tmp_path / "input.log"
    _copy_safe_scenario(evidence_path)
    result = run_v50_real_paloalto_shadow_validation(
        evidence_path=evidence_path,
        use_temp_db=False,
    )
    assert result["ok"] is False
    assert result["status"] == "explicit_temp_database_required"
    assert result["current_database_modified"] is False
