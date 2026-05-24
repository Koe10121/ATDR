import argparse
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from atdr.app.db.database import SessionLocal, init_db
from atdr.app.db.models import AuditLog, MLLabel, NormalizedLog, RawLog

DEMO_RAW_PREFIX = "ATDR-DEMO-LABEL"


def _demo_cases() -> list[dict]:
    base = datetime(2026, 5, 20, 9, 0, tzinfo=timezone.utc)
    cases: list[dict] = []
    templates = [
        ("benign", "normal", "allow", "ssl", 2, False, 0.05, 443),
        ("benign", "normal", "allow", "web-browsing", 2, False, 0.04, 80),
        ("benign_unusual", "normal", "allow", "dns", 2, False, 0.03, 53),
        ("benign_unusual", "policy_violation", "allow", "file-sharing", 4, True, -0.12, 445),
        ("suspicious", "port_scan", "deny", "unknown-tcp", 5, True, -0.22, 23),
        ("suspicious", "brute_force", "deny", "ssh", 4, True, -0.2, 22),
        ("malicious", "malware_c2", "drop", "unknown-tcp", 5, True, -0.31, 4444),
        ("malicious", "data_exfiltration_suspicion", "allow", "ftp", 5, True, -0.27, 21),
    ]
    for index in range(32):
        label, attack_type, action, app, risk, is_anomaly, anomaly_score, dst_port = templates[index % len(templates)]
        cases.append(
            {
                "raw_line": f"{DEMO_RAW_PREFIX} synthetic firewall training row {index + 1}",
                "generated_time": base + timedelta(minutes=index),
                "src_ip": f"192.0.2.{10 + (index % 20)}",
                "dst_ip": f"198.51.100.{20 + (index % 30)}" if label in {"benign", "benign_unusual"} else f"203.0.113.{20 + (index % 30)}",
                "app": app,
                "action": action,
                "app_risk": risk,
                "dst_port": dst_port + (index % 3 if attack_type == "port_scan" else 0),
                "is_anomaly": is_anomaly,
                "anomaly_score": anomaly_score,
                "label": label,
                "attack_type": attack_type,
                "confidence": 4 if label != "malicious" else 5,
            }
        )
    return cases


def seed_demo_labels(*, actor: str = "seed_demo_labels", force: bool = False) -> dict:
    init_db()
    with SessionLocal() as db:
        existing = list(db.scalars(select(RawLog).where(RawLog.raw_line.like(f"{DEMO_RAW_PREFIX}%"))))
        if existing and not force:
            return {"status": "skipped", "reason": "demo labels already exist", "existing_demo_logs": len(existing)}
        if force:
            for raw in existing:
                db.delete(raw)
            db.flush()

        created_logs = 0
        created_labels = 0
        label_distribution: dict[str, int] = {}
        for index, case in enumerate(_demo_cases(), start=1):
            raw = RawLog(
                raw_line=case["raw_line"],
                syslog_timestamp=case["generated_time"],
                device_hostname="mfu-demo-fw",
            )
            db.add(raw)
            db.flush()
            log = NormalizedLog(
                raw_log_id=raw.id,
                receive_time=case["generated_time"],
                generated_time=case["generated_time"],
                log_type="TRAFFIC",
                subtype="end",
                src_ip=case["src_ip"],
                dst_ip=case["dst_ip"],
                app=case["app"],
                src_zone="inside" if case["label"] in {"benign", "benign_unusual"} else "outside",
                dst_zone="outside" if case["label"] in {"benign", "benign_unusual"} else "inside",
                src_port=40000 + index,
                dst_port=case["dst_port"],
                protocol="tcp",
                action=case["action"],
                bytes=1500 + index * (50 if case["label"] in {"benign", "benign_unusual"} else 500),
                packets=10 + index,
                app_risk=case["app_risk"],
                is_anomaly=case["is_anomaly"],
                anomaly_score=case["anomaly_score"],
                parsed_json={"demo": True, "source": "seed_demo_labels", "attack_type": case["attack_type"]},
            )
            db.add(log)
            db.flush()
            db.add(
                MLLabel(
                    log_id=log.id,
                    label=case["label"],
                    attack_type=case["attack_type"],
                    confidence=case["confidence"],
                    reviewer=actor,
                    review_note="Synthetic demo label generated for supervised AI workflow testing.",
                )
            )
            created_logs += 1
            created_labels += 1
            label_distribution[case["label"]] = label_distribution.get(case["label"], 0) + 1

        db.add(
            AuditLog(
                actor=actor,
                action="seed_demo_ml_labels",
                target_type="ml_labels",
                target_value="synthetic_demo_dataset",
                details={"created_logs": created_logs, "created_labels": created_labels, "label_distribution": label_distribution},
            )
        )
        db.commit()
        return {
            "status": "created",
            "created_logs": created_logs,
            "created_labels": created_labels,
            "label_distribution": label_distribution,
            "decision_support_only": True,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a safe synthetic ML label dataset for ATDR supervised training demos.")
    parser.add_argument("--actor", default="seed_demo_labels")
    parser.add_argument("--force", action="store_true", help="Replace previous synthetic ATDR demo-label rows.")
    args = parser.parse_args()
    print(json.dumps(seed_demo_labels(actor=args.actor, force=args.force), indent=2, default=str))


if __name__ == "__main__":
    main()
