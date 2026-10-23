"""One run of ATDR's own flow on the database in DATABASE_URL, for test_postgres_smoke.py (not a test itself).

Usage: python -m atdr.tests.postgres_smoke_flow OUT.json   (DATABASE_URL set, schema already migrated)

Imports every scenario file in data/samples/scenarios, runs detection, then records the answer of every GET route
without a path parameter, each alert's detail, and the assistant's look-ups (no model is asked), so that two runs on
two databases can be compared.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from atdr.app.core.config import PROJECT_ROOT, get_settings, validate_runtime_settings
from atdr.app.db.database import SessionLocal
from atdr.app.db.models import Alert, NormalizedLog
from atdr.app.main import app
from atdr.app.services.assistant_tools import build_assistant_tools
from atdr.app.services.detection_service import run_detection
from atdr.app.services.log_service import import_log_file
from atdr.app.services.user_service import create_user

PASSWORD = "smoke-test-admin-password"
WINDOWS = ("all_time", "last_7_days")


def assistant_calls(alert_ids: list[int], log_ids: list[int]) -> list[tuple[str, dict]]:
    calls: list[tuple[str, dict]] = [("security_overview", {"time_window": window}) for window in ("all_time", "today", "last_7_days")]
    for window in WINDOWS:
        for intent in ("count", "trend", "list"):
            calls.append(("query_alerts", {"intent": intent, "time_window": window}))
            if intent != "list":
                calls.append(("query_logs", {"intent": intent, "time_window": window}))
        for group in ("src_ip", "dst_ip", "attack_type", "rule", "severity", "status"):
            calls.append(("query_alerts", {"intent": "top", "time_window": window, "group_by": group}))
        for group in ("src_ip", "dst_ip", "app", "action", "dst_port", "src_country", "dst_country"):
            calls.append(("query_logs", {"intent": "top", "time_window": window, "group_by": group}))
    calls += [("query_alerts", {"intent": "list", "severity": "Critical"}), ("query_logs", {"intent": "count", "action": "denied"})]
    calls += [("explain_concept", {"topic": topic}) for topic in ("alert_creation", "improvements", "detection_accuracy")]
    calls += [("behavior_model_view", {}), ("explain_detection_rules", {"rule": "port scan"})]
    calls += [("system_status", {"area": area}) for area in ("ml", "detection_runs", "operations", "sources", "recent_changes")]
    calls += [("get_alert", {"alert_id": alert_id}) for alert_id in alert_ids]
    calls += [("get_alert_playbook", {"alert_id": alert_id}) for alert_id in alert_ids]
    calls += [("get_log", {"log_id": log_id}) for log_id in log_ids]
    return calls


def main() -> None:
    out = Path(sys.argv[1])
    issues = validate_runtime_settings(get_settings())
    if issues:
        # Otherwise every page answers 503 and the run fails later, on a missing sign-in token.
        raise SystemExit(f"ATDR would not start with these settings: {issues}")
    report: dict = {"imports": [], "detection": {}, "routes": {}, "tools": {}}
    with SessionLocal() as db:
        create_user(db, username="admin", password=PASSWORD, role="admin", full_name="Smoke Test Admin")
        db.commit()
        for path in sorted((PROJECT_ROOT / "data" / "samples" / "scenarios").glob("*.txt")):
            result = import_log_file(db, path, actor="smoke")
            report["imports"].append({"file": path.name, "imported": result.get("imported")})
        detection = run_detection(db, limit=None, actor="smoke")
        report["detection"] = {key: value for key, value in detection.items() if isinstance(value, (int, str, bool))}

    with TestClient(app) as client:
        token = client.post("/api/auth/login", json={"username": "admin", "password": PASSWORD}).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        paths = sorted(path for path, item in app.openapi()["paths"].items() if "get" in item and "{" not in path)
        with SessionLocal() as db:
            alert_ids = list(db.scalars(select(Alert.id).order_by(Alert.id)))
            log_ids = list(db.scalars(select(NormalizedLog.id).order_by(NormalizedLog.id).limit(20)))
        # The log list sorted other ways: where a missing value goes is up to each database unless ATDR says.
        sorted_logs = [f"/api/logs?sort_by={key}" for key in ("src_ip", "action", "app_risk")]
        for path in [*paths, *sorted_logs, *(f"/api/alerts/{alert_id}" for alert_id in alert_ids)]:
            response = client.get(path, headers=headers)
            try:
                body = response.json()
            except ValueError:
                body = response.text[:200]
            report["routes"][path] = {"status": response.status_code, "body": body}

    settings = get_settings()
    for name, arguments in assistant_calls(alert_ids, log_ids):
        with SessionLocal() as db:
            tool = {item.name: item for item in build_assistant_tools(db, settings=settings, hide_ips=False)}[name]
            output = tool.run(arguments)
            report["tools"][f"{name} {json.dumps(arguments, sort_keys=True)}"] = {"text": output.text, "citations": output.citations}
    out.write_text(json.dumps(report, indent=1, default=str), encoding="utf-8")


if __name__ == "__main__":
    main()
