from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from atdr.app.db.database import Base
from atdr.app.db.models import LogSource, MLLabel, MLModelRun, NormalizedLog, RawLog, ResponseAction
from atdr.app.detection import v521_native_panos_evidence as v521
from atdr.app.detection.v530_supervised_evidence_closure import (
    FIXED_PROMOTION_GATES,
    run_v530_supervised_evidence_closure,
)


def _write_contracts(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "v5_19_blind_evaluation_state.json").write_text(
        json.dumps(
            {
                "predictions_frozen_before_labels": True,
                "labels_used_for_tuning": False,
                "post_reveal_candidate_changes": False,
            }
        ),
        encoding="utf-8",
    )
    (directory / "v5_20_schema_aware_abstention_latest.json").write_text(
        json.dumps({"v519_terminal_lock": {"locked": True}}),
        encoding="utf-8",
    )
    (directory / v521.V521_RESULT_LATEST).write_text(
        json.dumps(
            {
                "source_evidence": {
                    "rows_processed": 120,
                    "parser_successes": 120,
                    "parser_failures": 0,
                    "near_duplicate_rows": 5,
                },
                "evidence_roles": {
                    "development_fit": {"rows": 60},
                    "calibration": {"rows": 20},
                    "threshold": {"rows": 20},
                    "untouched_future_validation": {"rows": 20},
                    "quarantine": {"rows": 0},
                },
                "distinct_time_windows": 4,
                "duplicate_families_contained": True,
                "exact_family_cross_role_count": 0,
                "near_family_cross_role_count": 0,
                "review_packs": {"blind_rows": 20, "human_reviewed_rows_created": 0},
                "evidence_sufficiency": {"second_real_device_available": False},
            }
        ),
        encoding="utf-8",
    )
    (directory / "v5_22_supervised_model_rebuild_latest.json").write_text(
        json.dumps(
            {
                "sampling": {"future_role_sampled": False},
                "supervised_development_comparison": {
                    "locked_v53_labels_used_for_selection": False,
                    "future_validation_labels_used_for_selection": False,
                },
                "frozen_shadow_candidate": {
                    "name": "diagnostic_candidate",
                    "model_type": "extra_trees",
                    "target_mode": "hierarchical_two_stage",
                    "threshold": 0.4,
                    "calibration_method": "sigmoid",
                    "summary": {"evaluated_views": 4, "passing_views": 1},
                    "blind_labels_used_for_selection": False,
                    "active_artifact_written": False,
                    "eligible_for_activation": False,
                },
            }
        ),
        encoding="utf-8",
    )
    (directory / "v5_26_native_blind_qualification_latest.json").write_text(
        json.dumps(
            {
                "prediction_frozen_before_label_access": True,
                "prediction_phase": {"rows": 20},
                "label_audit": {
                    "rows_in_pack": 20,
                    "genuine_human_labels": 0,
                    "minimum_required": 20,
                    "enough_for_metrics": False,
                    "assisted_or_weak_labels_counted_as_human": 0,
                },
                "blind_evaluation": {"status": "insufficient_independent_human_labels"},
            }
        ),
        encoding="utf-8",
    )
    (directory / "v5_27_blind_review_evaluation_latest.json").write_text(
        json.dumps(
            {
                "review_intake": {
                    "valid_reviewed_rows": 0,
                    "minimum_reviewed_rows": 20,
                    "enough_for_metrics": False,
                    "blindness_compromised": False,
                    "predictions_rerun": False,
                }
            }
        ),
        encoding="utf-8",
    )
    (directory / "v5_19_independent_labeled_validation_adapter_recovery_20260101T000000Z.md").write_text(
        "\n".join(
            [
                "- Status: `label_adapter_recovery_diagnostic_complete`",
                "- Comparable rows: `885`",
                "- Excluded ambiguous rows: `19115`",
                "- Threat-positive precision: `0.4819`",
                "- Threat-positive recall: `1.0`",
                "- Threat-positive F1: `0.6504`",
                "- Benign-like FPR: `0.9978`",
                "- Calibration: `weak`",
                "- Binary transfer gate: `False`",
            ]
        ),
        encoding="utf-8",
    )


def _seed_labels(db: Session, *, count: int = 24) -> None:
    sources = [
        LogSource(name="source-a", source_type="test", parser_profile="palo_alto"),
        LogSource(name="source-b", source_type="test", parser_profile="palo_alto"),
    ]
    db.add_all(sources)
    db.flush()
    started = datetime(2026, 1, 1, tzinfo=UTC)
    for index in range(count):
        malicious = index % 2 == 1
        raw = RawLog(
            source_id=sources[index % 2].id,
            raw_line=f"safe synthetic row {index}",
            syslog_timestamp=started + timedelta(hours=index * 4),
        )
        log = NormalizedLog(
            raw_log=raw,
            generated_time=started + timedelta(hours=index * 4),
            log_type="TRAFFIC",
            subtype="end",
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            src_port=40_000 + index,
            dst_port=22 if malicious else 443,
            protocol="tcp",
            action="deny" if malicious else "allow",
            app="ssh" if malicious else "ssl",
            parsed_json={},
        )
        db.add(log)
        db.flush()
        db.add(
            MLLabel(
                log_id=log.id,
                label="malicious" if malicious else "benign",
                attack_type="brute_force" if malicious else "none",
                confidence=95,
                reviewer="human-reviewer",
                label_source="manual",
                reviewed=True,
            )
        )
    assisted_raw = RawLog(source_id=sources[0].id, raw_line="safe assisted row")
    assisted_log = NormalizedLog(
        raw_log=assisted_raw,
        generated_time=started,
        log_type="TRAFFIC",
        src_ip="192.0.2.11",
        dst_ip="198.51.100.21",
        dst_port=80,
        protocol="tcp",
        action="allow",
        app="incomplete",
        parsed_json={},
    )
    db.add(assisted_log)
    db.flush()
    db.add(
        MLLabel(
            log_id=assisted_log.id,
            label="suspicious",
            attack_type="unknown_anomaly",
            confidence=70,
            reviewer="assisted-review",
            label_source="assisted_rule",
            reviewed=True,
        )
    )
    db.commit()


def _mock_scorer(_db: Session, logs: list[NormalizedLog]) -> dict[str, object]:
    return {
        "ok": True,
        "status": "scored",
        "rows": [
            {
                "queue_decision": "needs_review" if log.dst_port == 22 else "benign_like",
                "queue_probability": 0.92 if log.dst_port == 22 else 0.08,
                "abstained": False,
            }
            for log in logs
        ],
    }


def test_v530_inventory_keeps_assisted_labels_out_of_human_evidence(tmp_path: Path) -> None:
    _write_contracts(tmp_path)
    engine = create_engine("sqlite://", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        _seed_labels(db)
        report = run_v530_supervised_evidence_closure(
            db,
            output_dir=tmp_path,
            write_reports=False,
            scorer=_mock_scorer,
        )
    inventory = report["evidence_inventory"]
    assert inventory["latest_trainable_rows"] == 25
    assert inventory["genuine_human_reviewed_rows"] == 24
    assert inventory["assisted_or_weak_rows"] == 1
    assert inventory["assisted_rows_with_reviewed_flag"] == 1
    assert inventory["assisted_rows_counted_as_genuine_human"] == 0
    assert inventory["one_latest_trainable_label_per_log"] is True


def test_v530_read_only_diagnostics_preserve_groups_and_safety(tmp_path: Path) -> None:
    _write_contracts(tmp_path)
    engine = create_engine("sqlite://", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        _seed_labels(db)
        before_models = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
        before_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
        report = run_v530_supervised_evidence_closure(
            db,
            output_dir=tmp_path,
            write_reports=False,
            scorer=_mock_scorer,
        )
        after_models = int(db.scalar(select(func.count(MLModelRun.id))) or 0)
        after_responses = int(db.scalar(select(func.count(ResponseAction.id))) or 0)
    diagnostics = report["registered_shadow_diagnostics"]
    grouped = next(row for row in diagnostics["splits"] if row["name"] == "grouped_source_holdout")
    assert diagnostics["available"] is True
    assert diagnostics["source_identity_count"] == 2
    assert grouped["status"] == "evaluated_diagnostic_only"
    assert diagnostics["promotion_evidence"] is False
    assert report["evidence_lock_audit"]["status"] == "passed"
    assert report["promotion_readiness"]["decision"] == "shadow_observation"
    assert report["promotion_readiness"]["quality_metrics_withheld"] is True
    assert report["review_pack"]["generated"] is False
    assert report["safety"]["database_state_unchanged"] is True
    assert before_models == after_models == 0
    assert before_responses == after_responses == 0


def test_v530_fixed_gates_fail_closed_without_independent_native_labels(tmp_path: Path) -> None:
    _write_contracts(tmp_path)
    engine = create_engine("sqlite://", future=True)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        _seed_labels(db)
        report = run_v530_supervised_evidence_closure(
            db,
            output_dir=tmp_path,
            write_reports=False,
            scorer=_mock_scorer,
        )
    readiness = report["promotion_readiness"]
    assert FIXED_PROMOTION_GATES["minimum_independent_human_blind_labels"] == 20
    assert readiness["evidence_checks"]["minimum_independent_human_blind_labels"] is False
    assert readiness["evidence_checks"]["minimum_independent_comparable_rows"] is False
    assert readiness["eligible_for_activation"] is False
    assert readiness["production_promoted"] is False
    assert readiness["response_automation_allowed"] is False


def test_v530_private_cli_projection_never_returns_paths_raw_data_or_secrets(tmp_path: Path) -> None:
    _write_contracts(tmp_path)
    engine = create_engine("sqlite://", future=True)
    Base.metadata.create_all(engine)
    sample_path = tmp_path / "private-sample.log"
    sample_path.write_text("private raw evidence", encoding="utf-8")

    def inspector(**_kwargs: object) -> dict[str, object]:
        return {
            "ok": True,
            "status": "native_panos_preflight_complete",
            "source_evidence": {"rows_processed": 10, "parser_successes": 9, "parser_failures": 1},
            "evidence_roles": {
                "development_fit": {"rows": 4},
                "calibration": {"rows": 2},
                "threshold": {"rows": 2},
                "untouched_future_validation": {"rows": 2},
                "quarantine": {"rows": 0},
            },
            "distinct_time_windows": 4,
            "duplicate_families_contained": True,
            "safety": {
                "configured_database_accessed": False,
                "configured_database_written": False,
                "disposable_index_removed": True,
            },
            "private_path": str(sample_path),
            "raw_log": "private raw evidence",
            "secret": "do-not-return",
        }

    with Session(engine) as db:
        report = run_v530_supervised_evidence_closure(
            db,
            output_dir=tmp_path,
            sample_path=sample_path,
            use_temp_db=True,
            evaluate_registered_shadow=False,
            write_reports=False,
            private_inspector=inspector,
        )
    projection = report["private_native_sample_audit"]
    serialized = json.dumps(projection)
    assert projection["executed"] is True
    assert projection["configured_database_accessed"] is False
    assert projection["temporary_storage_disposed"] is True
    assert str(sample_path) not in serialized
    assert "private raw evidence" not in serialized
    assert "do-not-return" not in serialized
    assert projection["path_returned"] is False
    assert projection["raw_logs_returned"] is False
