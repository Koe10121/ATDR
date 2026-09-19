from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.db.models import User
from atdr.app.detection import v562_supervised_qualification_campaign as v562_campaign
from atdr.app.detection import v563_fresh_evidence_expansion as v563_detection
from atdr.app.services import supervised_review_worksheet_service as worksheet_service
from atdr.app.services import v562_supervised_qualification_review_service as v562_review
from atdr.app.services import v563_supervised_expansion_review_service as v563_review
from atdr.app.services import v565_extended_expansion_review_service as v565_review
from atdr.app.services import v567_signal_concentrated_expansion_review_service as v567_review
from atdr.app.services.user_service import create_user
from atdr.app.detection import v565_extended_evidence_expansion as v565_detection
from atdr.app.detection import v567_signal_concentrated_evidence_expansion as v567_detection
from atdr.tests.test_v563_fresh_evidence_expansion import _prepare_v562, _prepare_v563
from atdr.tests.test_v565_extended_evidence_expansion import _prepare_v565
from atdr.tests.test_v567_signal_concentrated_evidence_expansion import _prepare_v567


@pytest.fixture()
def db_session() -> Generator[Session, None, None]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, future=True)
    with testing_session() as db:
        yield db
    engine.dispose()


@pytest.fixture()
def reviewer(db_session: Session) -> User:
    return create_user(
        db_session,
        username="worksheet-reviewer",
        password="analyst123",
        role="analyst",
        full_name="Worksheet Reviewer",
    )


def _rationale() -> str:
    return "Independent assessment of the displayed network evidence only."


@pytest.fixture()
def v562_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    paths = _prepare_v562(tmp_path / "v562")
    monkeypatch.setattr(v562_review, "_paths", lambda: paths)
    return paths


@pytest.fixture()
def v563_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    v562_dir = tmp_path / "v562"
    v563_dir = tmp_path / "v563"
    _prepare_v562(v562_dir)
    paths = _prepare_v563(v562_dir, v563_dir)
    monkeypatch.setattr(v563_review, "_paths", lambda: paths)
    monkeypatch.setattr(
        v563_review,
        "_validate_protocol",
        lambda output_dir: v563_detection.validate_expansion_protocol(
            output_dir, v562_output_dir=v562_dir, expected_original_rows=6
        ),
    )
    monkeypatch.setattr(
        v563_review,
        "_campaign_status",
        lambda output_dir: v563_detection.get_public_v563_status(
            output_dir, v562_output_dir=v562_dir
        ),
    )
    return paths


def test_export_v562_worksheet_lists_pending_rows_with_blank_decision_columns(
    v562_workspace, reviewer: User
) -> None:
    v562_review.start_qualification_review(reviewer)
    result = worksheet_service.export_worksheet(user=reviewer, workspace="v562")
    assert result["row_count"] == 6
    assert result["warnings"] == []
    for row in result["rows"]:
        assert row["workspace"] == "v562"
        assert row["batch_id"] == ""
        assert row["decision"] == ""
        assert row["confirm"] == ""
        assert row["application"] in {"ssl", "unknown-udp"}


def test_export_v562_worksheet_excludes_reviewed_rows_unless_requested(
    v562_workspace, reviewer: User
) -> None:
    v562_review.start_qualification_review(reviewer)
    v562_review.save_qualification_review_item(
        reviewer,
        row_index=0,
        expected_revision=0,
        decision="benign",
        attack_type="",
        confidence=90,
        rationale=_rationale(),
    )
    pending_only = worksheet_service.export_worksheet(user=reviewer, workspace="v562")
    assert pending_only["row_count"] == 5
    assert all(row["row_index"] != 0 for row in pending_only["rows"])

    including_reviewed = worksheet_service.export_worksheet(
        user=reviewer, workspace="v562", include_reviewed=True
    )
    assert including_reviewed["row_count"] == 6


def test_import_worksheet_requires_confirm_token_before_submitting(
    v562_workspace, reviewer: User
) -> None:
    v562_review.start_qualification_review(reviewer)
    rows = [
        {
            "workspace": "v562",
            "batch_id": "",
            "row_index": "0",
            "decision": "benign",
            "attack_type": "",
            "confidence": "90",
            "rationale": _rationale(),
            "confirm": "",
        }
    ]
    result = worksheet_service.import_worksheet(user=reviewer, rows=rows)
    assert result["submitted"] == 0
    assert result["awaiting_confirmation"] == 1
    status = v562_review.get_qualification_review_status(reviewer)
    assert status["reviewed"] == 0


def test_import_worksheet_submits_confirmed_rows_and_ignores_blank_ones(
    v562_workspace, reviewer: User
) -> None:
    v562_review.start_qualification_review(reviewer)
    rows = [
        {
            "workspace": "v562",
            "batch_id": "",
            "row_index": "0",
            "decision": "benign",
            "attack_type": "",
            "confidence": "90",
            "rationale": _rationale(),
            "confirm": "yes",
        },
        {
            "workspace": "v562",
            "batch_id": "",
            "row_index": "1",
            "decision": "",
            "attack_type": "",
            "confidence": "",
            "rationale": "",
            "confirm": "",
        },
    ]
    result = worksheet_service.import_worksheet(user=reviewer, rows=rows)
    assert result["ok"] is True
    assert result["submitted"] == 1
    assert result["skipped_already_reviewed"] == 0
    assert result["awaiting_confirmation"] == 0
    status = v562_review.get_qualification_review_status(reviewer)
    assert status["reviewed"] == 1


def test_import_worksheet_skips_reviewed_rows_unless_overwrite_requested(
    v562_workspace, reviewer: User
) -> None:
    v562_review.start_qualification_review(reviewer)
    v562_review.save_qualification_review_item(
        reviewer,
        row_index=0,
        expected_revision=0,
        decision="benign",
        attack_type="",
        confidence=90,
        rationale=_rationale(),
    )
    row = {
        "workspace": "v562",
        "batch_id": "",
        "row_index": "0",
        "decision": "malicious",
        "attack_type": "beaconing",
        "confidence": "70",
        "rationale": "Corrected independent assessment after re-inspection.",
        "confirm": "yes",
    }
    default_result = worksheet_service.import_worksheet(user=reviewer, rows=[row])
    assert default_result["submitted"] == 0
    assert default_result["skipped_already_reviewed"] == 1

    overwrite_result = worksheet_service.import_worksheet(
        user=reviewer, rows=[row], overwrite_existing=True
    )
    assert overwrite_result["submitted"] == 1
    item = v562_review.get_qualification_review_item(reviewer, row_index=0)
    assert item["existing_review"]["decision"] == "malicious"


def test_import_worksheet_reports_failed_rows_without_aborting_the_batch(
    v562_workspace, reviewer: User
) -> None:
    v562_review.start_qualification_review(reviewer)
    rows = [
        {
            "workspace": "v562",
            "batch_id": "",
            "row_index": "0",
            "decision": "not_a_real_decision",
            "attack_type": "",
            "confidence": "90",
            "rationale": _rationale(),
            "confirm": "yes",
        },
        {
            "workspace": "v562",
            "batch_id": "",
            "row_index": "1",
            "decision": "malicious",
            "attack_type": "",
            "confidence": "90",
            "rationale": _rationale(),
            "confirm": "yes",
        },
        {
            "workspace": "v562",
            "batch_id": "",
            "row_index": "2",
            "decision": "benign",
            "attack_type": "",
            "confidence": "90",
            "rationale": _rationale(),
            "confirm": "yes",
        },
    ]
    result = worksheet_service.import_worksheet(user=reviewer, rows=rows)
    assert result["ok"] is False
    assert result["failed"] == 2
    assert result["submitted"] == 1
    status = v562_review.get_qualification_review_status(reviewer)
    assert status["reviewed"] == 1


def test_export_and_import_v563_worksheet_respects_batch_ownership(
    v563_workspace, reviewer: User
) -> None:
    unstarted = worksheet_service.export_worksheet(user=reviewer, workspace="v563")
    assert unstarted["row_count"] == 0
    assert unstarted["warnings"]

    started = worksheet_service.export_worksheet(
        user=reviewer, workspace="v563", auto_start_batches=True
    )
    assert started["row_count"] == 6
    batch_ids = {row["batch_id"] for row in started["rows"]}
    assert batch_ids == {"batch-01", "batch-02"}

    picked = {row["batch_id"]: row for row in started["rows"]}
    rows = [
        {
            "workspace": "v563",
            "batch_id": batch_id,
            "row_index": str(item["row_index"]),
            "decision": "benign",
            "attack_type": "",
            "confidence": "85",
            "rationale": _rationale(),
            "confirm": "yes",
        }
        for batch_id, item in picked.items()
    ]
    result = worksheet_service.import_worksheet(user=reviewer, rows=rows)
    assert result["submitted"] == 2

    status = v563_review.get_expansion_review_status(reviewer)
    reviewed_by_batch = {batch["batch_id"]: batch["reviewed"] for batch in status["batches"]}
    assert reviewed_by_batch == {"batch-01": 1, "batch-02": 1}


def test_resolve_reviewer_auto_detects_v562_workspace_owner(
    v562_workspace, reviewer: User, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(v562_campaign, "_workspace_paths", lambda *_a, **_k: v562_workspace)
    v562_review.start_qualification_review(reviewer)
    resolved = worksheet_service.resolve_reviewer(db_session)
    assert resolved.id == reviewer.id


@pytest.fixture()
def v565_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    v562_dir = tmp_path / "v562"
    v563_dir = tmp_path / "v563"
    v565_dir = tmp_path / "v565"
    _prepare_v562(v562_dir)
    _prepare_v563(v562_dir, v563_dir)
    paths = _prepare_v565(v562_dir, v563_dir, v565_dir)
    monkeypatch.setattr(v565_review, "_paths", lambda: paths)
    monkeypatch.setattr(
        v565_review,
        "_validate_protocol",
        lambda output_dir: v565_detection.validate_extended_protocol(
            output_dir, v563_output_dir=v563_dir, v562_output_dir=v562_dir
        ),
    )
    monkeypatch.setattr(
        v565_review,
        "_campaign_status",
        lambda output_dir: v565_detection.get_public_v565_status(
            output_dir, v563_output_dir=v563_dir, v562_output_dir=v562_dir
        ),
    )
    return paths


def test_export_and_import_v565_worksheet_respects_batch_ownership(
    v565_workspace, reviewer: User
) -> None:
    started = worksheet_service.export_worksheet(
        user=reviewer, workspace="v565", auto_start_batches=True
    )
    assert started["row_count"] == 4
    assert all(row["workspace"] == "v565" for row in started["rows"])

    rows = [
        {
            "workspace": "v565",
            "batch_id": row["batch_id"],
            "row_index": str(row["row_index"]),
            "decision": "benign",
            "attack_type": "",
            "confidence": "88",
            "rationale": _rationale(),
            "confirm": "yes",
        }
        for row in started["rows"][:2]
    ]
    result = worksheet_service.import_worksheet(user=reviewer, rows=rows)
    assert result["submitted"] == 2

    status = v565_review.get_extended_expansion_review_status(reviewer)
    assert status["reviewed"] == 2


@pytest.fixture()
def v567_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    v562_dir = tmp_path / "v562"
    v563_dir = tmp_path / "v563"
    v565_dir = tmp_path / "v565"
    v567_dir = tmp_path / "v567"
    _prepare_v562(v562_dir)
    _prepare_v563(v562_dir, v563_dir)
    _prepare_v565(v562_dir, v563_dir, v565_dir)
    paths = _prepare_v567(v562_dir, v563_dir, v565_dir, v567_dir)
    monkeypatch.setattr(v567_review, "_paths", lambda: paths)
    monkeypatch.setattr(
        v567_review,
        "_validate_protocol",
        lambda output_dir: v567_detection.validate_signal_protocol(
            output_dir, v565_output_dir=v565_dir, v563_output_dir=v563_dir, v562_output_dir=v562_dir
        ),
    )
    monkeypatch.setattr(
        v567_review,
        "_campaign_status",
        lambda output_dir: v567_detection.get_public_v567_status(
            output_dir, v565_output_dir=v565_dir, v563_output_dir=v563_dir, v562_output_dir=v562_dir
        ),
    )
    return paths


def test_export_and_import_v567_worksheet_respects_batch_ownership(
    v567_workspace, reviewer: User
) -> None:
    started = worksheet_service.export_worksheet(
        user=reviewer, workspace="v567", auto_start_batches=True
    )
    assert started["row_count"] == 4
    assert all(row["workspace"] == "v567" for row in started["rows"])

    rows = [
        {
            "workspace": "v567",
            "batch_id": row["batch_id"],
            "row_index": str(row["row_index"]),
            "decision": "benign",
            "attack_type": "",
            "confidence": "88",
            "rationale": _rationale(),
            "confirm": "yes",
        }
        for row in started["rows"][:2]
    ]
    result = worksheet_service.import_worksheet(user=reviewer, rows=rows)
    assert result["submitted"] == 2

    status = v567_review.get_signal_concentrated_expansion_review_status(reviewer)
    assert status["reviewed"] == 2
