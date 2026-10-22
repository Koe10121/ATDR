from __future__ import annotations

import csv
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from atdr.app.detection.schema_contracts import (
    get_schema_contract,
    normalize_common_features,
    validate_schema_row,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_flow_sample(path: Path, *, rows: int = 8) -> None:
    fieldnames = [
        "evidence_id",
        "provider_file",
        "provider_day",
        "provider_row_number",
        "provider_label",
        "atdr_label",
        "queue_target",
        "severity_target",
        "human_reviewed",
        "import_ready",
        "Dst Port",
        "Protocol",
        "Timestamp",
        "Flow Duration",
        "Tot Fwd Pkts",
        "Tot Bwd Pkts",
        "TotLen Fwd Pkts",
        "TotLen Bwd Pkts",
        "Flow Bytes/s",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for index in range(rows):
            threat = index % 2 == 1
            writer.writerow(
                {
                    "evidence_id": f"2018-02-15:{index + 1}",
                    "provider_file": "provider-development.csv",
                    "provider_day": "2018-02-15",
                    "provider_row_number": index + 1,
                    "provider_label": "Bot" if threat else "Benign",
                    "atdr_label": "malicious" if threat else "benign",
                    "queue_target": "needs_review" if threat else "non_threat",
                    "severity_target": "malicious" if threat else "benign",
                    "human_reviewed": False,
                    "import_ready": False,
                    "Dst Port": 4000 + index,
                    "Protocol": 6 if index % 3 else 17,
                    "Timestamp": f"15/02/2018 10:{index:02d}:00",
                    "Flow Duration": 1_000_000 + index,
                    "Tot Fwd Pkts": 3 + index,
                    "Tot Bwd Pkts": 2 + index,
                    "TotLen Fwd Pkts": 300 + index,
                    "TotLen Bwd Pkts": 200 + index,
                    "Flow Bytes/s": 500 + index,
                }
            )




def _evaluated_split(split_mode: str, name: str = "schema_routed_firewall_plus_flow_ensemble") -> dict:
    return {
        "split_mode": split_mode,
        "status": "evaluated",
        "strategies": [
            {
                "name": name,
                "status": "evaluated",
                "metrics": {
                    "queue_precision": 0.90,
                    "queue_recall": 0.88,
                    "queue_f1": 0.89,
                    "benign_like_false_positive_rate": 0.08,
                    "suspicious_recall": 0.82,
                    "malicious_recall": 0.86,
                    "macro_f1": 0.88,
                    "weighted_f1": 0.89,
                    "review_queue_rate": 0.48,
                },
                "calibration": {"passed": True, "brier_score": 0.1},
                "threshold_selection": {
                    "selected_threshold": 0.5,
                    "selected_on": "threshold_selection_partition_only",
                    "used_final_test_labels": False,
                },
                "details": {"active_artifact_written": False},
                "_scores": [0.1, 0.9],
                "_predictions": ["non_threat", "needs_review"],
            }
        ],
    }




def test_v401_schema_contracts_reject_invented_provider_identity():
    provider = get_schema_contract("provider_flow")
    firewall = get_schema_contract("palo_alto")
    assert "src_ip" in provider.unavailable_fields
    assert "src_ip" in firewall.required_fields

    validation = validate_schema_row(
        "provider_flow",
        {
            "timestamp": datetime.now(timezone.utc),
            "src_ip": "192.0.2.10",
            "dst_port": 443,
            "protocol": "tcp",
            "bytes_sent": 10,
            "bytes_received": 20,
            "packets": 3,
            "duration_seconds": 1,
        },
    )
    assert validation["valid"] is False
    assert validation["invented_unavailable_fields"] == ["src_ip"]

    with pytest.raises(ValueError, match="cannot supply unavailable"):
        normalize_common_features(
            "provider_flow",
            {
                "timestamp": datetime.now(timezone.utc),
                "src_ip": "192.0.2.10",
                "dst_port": 443,
                "protocol": "tcp",
                "bytes_sent": 10,
                "bytes_received": 20,
                "packets": 3,
                "duration_seconds": 1,
            },
        )














