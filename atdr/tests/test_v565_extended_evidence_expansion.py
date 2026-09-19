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
from atdr.app.services import v565_extended_expansion_review_service as v565_review
from atdr.app.services.user_service import create_user
from atdr.tests.test_v563_fresh_evidence_expansion import _prepare_v562, _prepare_v563


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
    high_yield_group = next(iter(v565.HIGH_YIELD_COVERAGE_GROUPS))
    order = v565._coverage_round_robin_order({high_yield_group, "boundary_context"})
    assert order.count(high_yield_group) == v565.COVERAGE_GROUP_ROUND_ROBIN_WEIGHT
    assert order.count("boundary_context") == 1


def test_extended_selection_excludes_evaluation_role_and_dedupes_families() -> None:
    rows = [
        _candidate(index, role_rank=index % 3, family=f"fresh-{index}")
        for index in range(1, 12)
    ]
    rows.append(_candidate(20, role_rank=3, family="future-evaluation"))
    rows.append(_candidate(21, role_rank=0, family="fresh-2"))

    selected, summary, families = v565.select_extended_review_candidates(
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


def test_extended_selection_excludes_rows_already_consumed_by_v562_or_v563() -> None:
    consumed_via_v562 = _candidate(1, role_rank=0, family="already-v562")
    consumed_via_v563 = _candidate(2, role_rank=1, family="already-v563")
    fresh = [
        _candidate(index, role_rank=index % 3, family=f"fresh-{index}")
        for index in range(3, 9)
    ]

    v562_token = str(
        v562._candidate_projection(consumed_via_v562, family="already-v562")["review_token"]
    )
    v563_token = str(
        v563._supplemental_projection(consumed_via_v563, family="already-v563")["review_token"]
    )

    selected, summary, _families = v565.select_extended_review_candidates(
        [consumed_via_v562, consumed_via_v563, *fresh],
        consumed_review_tokens={v562_token, v563_token},
        limit=4,
        batch_size=4,
        combined_role_counts={"development_fit": 150, "calibration": 60, "threshold_selection": 45},
    )

    selected_families = {row["review_token"] for row in selected}
    assert v562_token not in selected_families
    assert v563_token not in selected_families
    assert summary["exclusion_reasons"].get("already_selected_v562_or_v563_evidence") == 2
    assert summary["original_pack_overlap_count"] == 2


def _prepare_v565(
    v562_dir: Path,
    v563_dir: Path,
    v565_dir: Path,
    *,
    rows_per_role: int = 2,
) -> dict[str, Path]:
    boundary = v565._v563_boundary_snapshot(
        v563_dir, v562_output_dir=v562_dir, expected_combined_rows=12
    )
    role_rank_by_name = {name: rank for rank, name in v562.ROLE_NAMES.items()}
    roles = ["development_fit", "development_fit", "calibration", "threshold_selection"]
    candidates = [
        v565._extended_projection(
            _candidate(index, role_rank=role_rank_by_name[role], family=f"v565-fresh-{index}"),
            family=f"v565-fresh-{index}",
        )
        for index, role in enumerate(roles)
    ]
    selection = {"role_counts": {}, "fresh_rows_available": len(candidates)}
    for index, candidate in enumerate(candidates):
        candidate["review_batch_id"] = f"batch-{(index // 2) + 1:02d}"
    v565._prepare_workspace(
        candidates,
        selection=selection,
        selected_families={f"v565-fresh-{index}" for index in range(len(candidates))},
        consumed_families=set(),
        v563_snapshot=boundary,
        source_digest=boundary["source_digest"],
        primary_source_tokens={"primary-device-token"},
        profile={"rows_processed": 600},
        roles={"distinct_time_windows": 3},
        output_dir=v565_dir,
        v563_output_dir=v563_dir,
        v562_output_dir=v562_dir,
    )
    return v565._paths(v565_dir)


def test_v565_append_only_protocol_builds_on_locked_v562_v563_pack(tmp_path: Path) -> None:
    v562_dir = tmp_path / "v562"
    v563_dir = tmp_path / "v563"
    v565_dir = tmp_path / "v565"
    _prepare_v562(v562_dir)
    _prepare_v563(v562_dir, v563_dir)
    _prepare_v565(v562_dir, v563_dir, v565_dir)

    protocol = v565.validate_extended_protocol(
        v565_dir, v563_output_dir=v563_dir, v562_output_dir=v562_dir, expected_combined_rows=12
    )

    assert protocol["append_only"] is True
    assert protocol["extended_selected_rows"] == 4
    assert protocol["total_comparable_capacity"] == 16
    assert protocol["v563_reference"]["combined_rows"] == 12
    assert protocol["coverage_group_weighting"]["informed_by_prior_human_review"] is True


def test_v565_status_reports_combined_gates_across_all_three_tiers(tmp_path: Path) -> None:
    v562_dir = tmp_path / "v562"
    v563_dir = tmp_path / "v563"
    v565_dir = tmp_path / "v565"
    _prepare_v562(v562_dir)
    _prepare_v563(v562_dir, v563_dir)
    _prepare_v565(v562_dir, v563_dir, v565_dir)

    status = v565.get_public_v565_status(
        v565_dir, v563_output_dir=v563_dir, v562_output_dir=v562_dir
    )

    assert status["status"] == "ready_for_extended_review"
    assert status["review"]["combined_total"] == 16
    assert status["qualification_gates"]["independent_comparable_rows"]["threshold"] == 1000


def test_v565_review_service_start_save_and_status_round_trip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    v562_dir = tmp_path / "v562"
    v563_dir = tmp_path / "v563"
    v565_dir = tmp_path / "v565"
    _prepare_v562(v562_dir)
    _prepare_v563(v562_dir, v563_dir)
    paths = _prepare_v565(v562_dir, v563_dir, v565_dir)
    monkeypatch.setattr(v565_review, "_paths", lambda: paths)
    monkeypatch.setattr(
        v565_review,
        "_campaign_status",
        lambda output_dir: v565.get_public_v565_status(
            output_dir, v563_output_dir=v563_dir, v562_output_dir=v562_dir
        ),
    )
    monkeypatch.setattr(
        v565_review,
        "_validate_protocol",
        lambda output_dir: v565.validate_extended_protocol(
            output_dir, v563_output_dir=v563_dir, v562_output_dir=v562_dir
        ),
    )

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, future=True)
    with testing_session() as db:
        reviewer = create_user(
            db, username="extended-reviewer", password="analyst123", role="analyst", full_name="Extended Reviewer"
        )

        started = v565_review.start_extended_expansion_review_batch(reviewer, batch_id="batch-01")
        assert started["ok"] is True
        first_item = started["next_item"]
        assert first_item is not None

        saved = v565_review.save_extended_expansion_review_item(
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

        status = v565_review.get_extended_expansion_review_status(reviewer)
        assert status["reviewed"] == 1
    engine.dispose()
