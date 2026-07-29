from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pandas as pd

from atdr.app.detection import v53_temporal_generalization as reliability


def _temporal_rows(count: int = 240) -> list[dict]:
    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return [
        {
            "log_id": index + 1,
            "timestamp": started + timedelta(seconds=index),
            "leakage_group": f"group-{index}",
            "safe_queue_target": "needs_review" if index % 4 == 0 else "non_threat",
        }
        for index in range(count)
    ]


def _ood_dataset() -> dict:
    frame = pd.DataFrame(
        {
            "dst_port": [80, 443, 53, 22, 8080, 123, 65535],
            "bytes": [100, 120, 90, 130, 110, 105, 10_000_000],
            "protocol": ["tcp", "tcp", "udp", "tcp", "tcp", "udp", "sctp"],
            "action": ["allow", "allow", "allow", "deny", "allow", "allow", "mirror"],
            "app": ["web", "ssl", "dns", "ssh", "web", "ntp", "novel-app"],
            "src_zone": ["inside"] * 6 + [None],
            "dst_zone": ["outside"] * 6 + [None],
        }
    )
    rows = [
        {
            "original_label": "benign",
            "source_name": "synthetic",
            "app": str(frame.iloc[index]["app"]),
            "action": str(frame.iloc[index]["action"]),
            "dst_port": int(frame.iloc[index]["dst_port"]),
        }
        for index in range(len(frame))
    ]
    return {
        "frame": frame,
        "feature_meta": {
            "numeric_features": ["dst_port", "bytes"],
            "categorical_features": ["protocol", "action", "app", "src_zone", "dst_zone"],
        },
        "rows": rows,
        "targets": ["non_threat"] * len(frame),
    }


def test_rolling_temporal_windows_never_reuse_final_rows_for_tuning():
    rows = _temporal_rows()

    partitions = reliability.build_rolling_temporal_partitions(rows)

    assert len(partitions) == 3
    assert all(partition["status"] == "partitioned" for partition in partitions)
    final_sets = [set(partition["final_test_idx"]) for partition in partitions]
    assert all(not (left & right) for index, left in enumerate(final_sets) for right in final_sets[index + 1 :])
    for partition in partitions:
        development = set(partition["fit_idx"] + partition["calibration_idx"] + partition["threshold_idx"])
        assert not development & set(partition["final_test_idx"])
        assert max(rows[index]["timestamp"] for index in development) < min(
            rows[index]["timestamp"] for index in partition["final_test_idx"]
        )
        assert partition["final_test_labels_used_for_training"] is False
        assert partition["final_test_labels_used_for_calibration"] is False
        assert partition["final_test_labels_used_for_threshold_selection"] is False


def test_ood_profile_uses_fit_rows_and_marks_unfamiliar_schema():
    dataset = _ood_dataset()
    profile = reliability.fit_ood_profile(dataset, list(range(6)))

    states, summary = reliability.score_ood_rows(
        dataset,
        profile,
        [6],
        [0.92],
        threshold=0.50,
    )

    assert profile["fit_labels_used"] is False
    assert profile["final_test_labels_used"] is False
    assert states[0]["ood"] is True
    assert states[0]["decision"] == "insufficient_model_evidence"
    assert "critical_schema_fields_missing" in states[0]["reasons"]
    assert "unseen_category_rate_high" in states[0]["reasons"]
    assert summary["ood_rate"] == 1.0
    assert summary["raw_logs_included"] is False
    assert summary["private_identifiers_included"] is False


def test_abstention_routes_to_review_queue_instead_of_hiding_false_positive(monkeypatch):
    dataset = _ood_dataset()
    dataset["rows"][6]["original_label"] = "benign"
    partition = {"fit_idx": list(range(6)), "final_test_idx": [6]}
    fitted = {
        "status": "evaluated",
        "final_scores": [0.01],
        "threshold_selection": {"selected_threshold": 0.50},
    }

    monkeypatch.setattr(
        reliability,
        "_evaluate_fitted",
        lambda *_args, **_kwargs: {
            "name": "calibrated_abstention_review_queue",
            "status": "evaluated",
            "metrics": {
                "review_queue_rate": 0.0,
                "false_positive": 0,
            },
            "calibration": {},
            "details": {},
            "_predictions": ["non_threat"],
        },
    )

    result = reliability._evaluate_abstention_policy(dataset, partition, fitted, seed=53)

    assert result["ood_and_abstention"]["abstained_rows"] == 1
    assert result["ood_and_abstention"]["abstention_counted_as_review_queue_for_strict_metrics"] is True
    assert result["metrics"]["false_positive"] == 1
    assert result["metrics"]["review_queue_rate"] == 1.0
    assert result["_predictions"] == ["needs_review"]


def test_readiness_remains_shadow_and_never_enables_response():
    selected = {"name": "candidate", "candidate_selected": True}
    split_results = [{"split_mode": mode, "status": "evaluated"} for mode in reliability.V53_REQUIRED_SPLITS]
    rolling = [
        {
            "split_mode": f"rolling_temporal_{index}",
            "status": "evaluated",
            "leakage_audit": {"passed": True},
        }
        for index in range(1, 4)
    ]
    readiness = reliability._readiness(
        selected,
        {"passed_v49_gates": True},
        split_results,
        rolling,
        {
            "available": True,
            "failed_count": 0,
            "false_positive_count": 0,
            "false_negative_count": 0,
        },
        {
            "database_counts_unchanged": True,
            "active_artifact_unchanged": True,
            "response_actions_created": 0,
        },
    )

    assert readiness["decision"] == "shadow_observation"
    assert readiness["model_activated"] is False
    assert readiness["production_promoted"] is False
    assert readiness["response_automation_allowed"] is False
    assert readiness["real_firewall_blocking_enabled"] is False


def test_artifact_reference_is_excluded_from_non_temporal_selection():
    result = reliability._artifact_baseline_strategy(
        {},
        {},
        {"available": True, "compatible_dataset": True},
        split_mode="random_seed_7",
    )

    assert result["status"] == "excluded_from_split_gate"
    assert result["eligible_for_selection"] is False
