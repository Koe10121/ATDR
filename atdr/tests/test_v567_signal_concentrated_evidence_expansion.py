from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from atdr.app.db.database import Base
from atdr.app.detection import v562_supervised_qualification_campaign as v562
from atdr.app.detection import v563_fresh_evidence_expansion as v563
from atdr.app.detection import v565_extended_evidence_expansion as v565
from atdr.app.detection import v567_signal_concentrated_evidence_expansion as v567
from atdr.app.services import v567_signal_concentrated_expansion_review_service as v567_review
from atdr.app.services.user_service import create_user
from atdr.tests.test_v563_fresh_evidence_expansion import _prepare_v562, _prepare_v563
from atdr.tests.test_v565_extended_evidence_expansion import _prepare_v565


def _candidate(
    index: int,
    *,
    role_rank: int,
    family: str,
    app_risk: int = 2,
    log_type: str = "TRAFFIC",
) -> dict[str, object]:
    return {
        "id": index,
        "role_rank": role_rank,
        "_candidate_family": family,
        "event_time": f"2026-09-{(index % 28) + 1:02d}T00:00:00+00:00",
        "log_type": log_type,
        "subtype": "end",
        "app": "ssl",
        "action": "allow",
        "protocol": "tcp",
        "src_port": 45000 + index,
        "dst_port": 443,
        "src_zone": "trust",
        "dst_zone": "untrust",
        "bytes": 1200,
        "packets": 10,
        "elapsed_time": 2,
        "app_risk": app_risk,
        "session_end_reason": "aged-out",
        "parser_warning_count": 0,
        "required_missing_count": 0,
        "schema_bucket": "traffic_full",
        "group_size": 1,
        "source_event_count": 2,
        "source_deny_count": 0,
        "source_unique_destinations": 1,
        "source_unique_ports": 1,
        "source_unknown_app_count": 0,
        "source_high_risk_app_count": 0,
        "destination_repeat_count": 1,
        "threat_severity": "none",
    }


def test_coverage_round_robin_order_gives_high_yield_groups_larger_share() -> None:
    high_yield_group = next(iter(v567.HIGH_YIELD_COVERAGE_GROUPS))
    order = v567._coverage_round_robin_order({high_yield_group, "boundary_context"})
    assert order.count(high_yield_group) == v567.COVERAGE_GROUP_ROUND_ROBIN_WEIGHT
    assert order.count("boundary_context") == 1


def test_high_yield_groups_no_longer_include_vendor_security_context() -> None:
    # v5.65 weighted vendor_security_context 3x on the strength of the
    # original 1,000-row sample, but it produced zero new threat-positive
    # rows across the 500-row v5.65 round. v5.67 must not repeat that.
    assert "vendor_security_context" not in v567.HIGH_YIELD_COVERAGE_GROUPS
    assert v567.HIGH_YIELD_COVERAGE_GROUPS == frozenset(
        {"unknown_transport_context", "incomplete_transport_context", "high_activity_context"}
    )


def test_signal_selection_excludes_evaluation_role_and_dedupes_families() -> None:
    rows = [
        _candidate(index, role_rank=index % 3, family=f"fresh-{index}")
        for index in range(1, 12)
    ]
    rows.append(_candidate(20, role_rank=3, family="future-evaluation"))
    rows.append(_candidate(21, role_rank=0, family="fresh-2"))

    selected, summary, families = v567.select_signal_concentrated_review_candidates(
        rows,
        consumed_review_tokens=set(),
        limit=9,
        batch_size=3,
        combined_role_counts={"development_fit": 150, "calibration": 60, "threshold_selection": 45},
    )

    assert len(selected) == 9
    assert len(families) == 9
    assert summary["duplicate_families_contained"] is True
    assert summary["future_evaluation_rows_selected"] == 0
    assert summary["exclusion_reasons"].get("sealed_future_evaluation_role") == 1
    assert summary["exclusion_reasons"].get("duplicate_family") == 1
    assert all(row["evidence_role"] in v562.DEVELOPMENT_ROLE_NAMES for row in selected)
    assert all(row["predictions_exposed"] is False for row in selected)
    assert summary["predictions_used_for_selection"] is False
    assert summary["coverage_group_weighting_informed_by_prior_human_review"] is True


def test_signal_selection_excludes_rows_already_consumed_by_v562_v563_or_v565() -> None:
    consumed_via_v562 = _candidate(1, role_rank=0, family="already-v562")
    consumed_via_v563 = _candidate(2, role_rank=1, family="already-v563")
    consumed_via_v565 = _candidate(3, role_rank=2, family="already-v565")
    fresh = [
        _candidate(index, role_rank=index % 3, family=f"fresh-{index}")
        for index in range(4, 10)
    ]

    v562_token = str(
        v562._candidate_projection(consumed_via_v562, family="already-v562")["review_token"]
    )
    v563_token = str(
        v563._supplemental_projection(consumed_via_v563, family="already-v563")["review_token"]
    )
    v565_token = str(
        v565._extended_projection(consumed_via_v565, family="already-v565")["review_token"]
    )

    selected, summary, _families = v567.select_signal_concentrated_review_candidates(
        [consumed_via_v562, consumed_via_v563, consumed_via_v565, *fresh],
        consumed_review_tokens={v562_token, v563_token, v565_token},
        limit=4,
        batch_size=4,
        combined_role_counts={"development_fit": 150, "calibration": 60, "threshold_selection": 45},
    )

    selected_tokens = {row["review_token"] for row in selected}
    assert v562_token not in selected_tokens
    assert v563_token not in selected_tokens
    assert v565_token not in selected_tokens
    assert summary["exclusion_reasons"].get("already_selected_v562_v563_or_v565_evidence") == 3
    assert summary["original_pack_overlap_count"] == 3


def _prepare_v567(
    v562_dir: Path,
    v563_dir: Path,
    v565_dir: Path,
    v567_dir: Path,
) -> dict[str, Path]:
    boundary = v567._v565_boundary_snapshot(
        v565_dir, v563_output_dir=v563_dir, v562_output_dir=v562_dir, expected_combined_rows=16
    )
    role_rank_by_name = {name: rank for rank, name in v562.ROLE_NAMES.items()}
    roles = ["development_fit", "development_fit", "calibration", "threshold_selection"]
    candidates = [
        v567._signal_projection(
            _candidate(index, role_rank=role_rank_by_name[role], family=f"v567-fresh-{index}"),
            family=f"v567-fresh-{index}",
        )
        for index, role in enumerate(roles)
    ]
    selection = {"role_counts": {}, "fresh_rows_available": len(candidates)}
    for index, candidate in enumerate(candidates):
        candidate["review_batch_id"] = f"batch-{(index // 2) + 1:02d}"
    v567._prepare_workspace(
        candidates,
        selection=selection,
        selected_families={f"v567-fresh-{index}" for index in range(len(candidates))},
        consumed_families=set(),
        v565_snapshot=boundary,
        source_digest=boundary["source_digest"],
        primary_source_tokens={"primary-device-token"},
        profile={"rows_processed": 600},
        roles={"distinct_time_windows": 3},
        output_dir=v567_dir,
        v565_output_dir=v565_dir,
        v563_output_dir=v563_dir,
        v562_output_dir=v562_dir,
    )
    return v567._paths(v567_dir)


def test_v567_append_only_protocol_builds_on_locked_v562_v563_v565_pack(tmp_path: Path) -> None:
    v562_dir = tmp_path / "v562"
    v563_dir = tmp_path / "v563"
    v565_dir = tmp_path / "v565"
    v567_dir = tmp_path / "v567"
    _prepare_v562(v562_dir)
    _prepare_v563(v562_dir, v563_dir)
    _prepare_v565(v562_dir, v563_dir, v565_dir)
    _prepare_v567(v562_dir, v563_dir, v565_dir, v567_dir)

    protocol = v567.validate_signal_protocol(
        v567_dir,
        v565_output_dir=v565_dir,
        v563_output_dir=v563_dir,
        v562_output_dir=v562_dir,
        expected_combined_rows=16,
    )

    assert protocol["append_only"] is True
    assert protocol["signal_selected_rows"] == 4
    assert protocol["total_comparable_capacity"] == 20
    assert protocol["v565_reference"]["combined_rows"] == 16
    assert protocol["coverage_group_weighting"]["informed_by_prior_human_review"] is True


def test_v567_status_reports_combined_gates_across_all_four_tiers(tmp_path: Path) -> None:
    v562_dir = tmp_path / "v562"
    v563_dir = tmp_path / "v563"
    v565_dir = tmp_path / "v565"
    v567_dir = tmp_path / "v567"
    _prepare_v562(v562_dir)
    _prepare_v563(v562_dir, v563_dir)
    _prepare_v565(v562_dir, v563_dir, v565_dir)
    _prepare_v567(v562_dir, v563_dir, v565_dir, v567_dir)

    status = v567.get_public_v567_status(
        v567_dir, v565_output_dir=v565_dir, v563_output_dir=v563_dir, v562_output_dir=v562_dir
    )

    assert status["status"] == "ready_for_signal_review"
    assert status["review"]["combined_total"] == 20
    assert status["qualification_gates"]["independent_comparable_rows"]["threshold"] == 1000


def test_v567_review_service_start_save_and_status_round_trip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
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
        "_campaign_status",
        lambda output_dir: v567.get_public_v567_status(
            output_dir, v565_output_dir=v565_dir, v563_output_dir=v563_dir, v562_output_dir=v562_dir
        ),
    )
    monkeypatch.setattr(
        v567_review,
        "_validate_protocol",
        lambda output_dir: v567.validate_signal_protocol(
            output_dir, v565_output_dir=v565_dir, v563_output_dir=v563_dir, v562_output_dir=v562_dir
        ),
    )

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, future=True)
    with testing_session() as db:
        reviewer = create_user(
            db, username="signal-reviewer", password="analyst123", role="analyst", full_name="Signal Reviewer"
        )

        started = v567_review.start_signal_concentrated_expansion_review_batch(
            reviewer, batch_id="batch-01"
        )
        assert started["ok"] is True
        first_item = started["next_item"]
        assert first_item is not None

        saved = v567_review.save_signal_concentrated_expansion_review_item(
            reviewer,
            batch_id="batch-01",
            row_index=first_item["row_index"],
            expected_revision=first_item["revision"],
            decision="benign",
            attack_type="",
            confidence=90,
            rationale="Independent assessment of the displayed evidence only.",
        )
        assert saved["ok"] is True

        status = v567_review.get_signal_concentrated_expansion_review_status(reviewer)
        assert status["reviewed"] == 1
    engine.dispose()
