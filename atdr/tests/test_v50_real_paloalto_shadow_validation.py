from __future__ import annotations

import json
import re
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from atdr.app.core.config import PROJECT_ROOT
from atdr.app.db.database import Base
from atdr.app.parsers.paloalto_parser import parse_log_line_for_profile
from atdr.app.services.log_service import persist_parsed_log
from atdr.app.services.private_log_preflight_service import (
    preflight_private_paloalto_file,
)
from atdr.app.services.source_service import create_source, source_quality


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






