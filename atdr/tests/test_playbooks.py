from sqlalchemy import func, select

from atdr.app.db.database import get_db
from atdr.app.db.models import Alert, AlertNote, AuditLog, ResponseAction
from atdr.app.detection.attack_mapping import ATTACK_TYPE_MAPPINGS, RULE_ATTACK_HINTS
from atdr.app.detection.explanations import RULE_ANALYST_CHECKS
from atdr.app.detection.playbooks import DEFAULT_PLAYBOOK, PLAYBOOK_GUIDANCE, playbook_guidance
from atdr.app.main import app
from atdr.tests.test_api import _client, _login


def _add_alert(**overrides) -> int:
    db = next(app.dependency_overrides[get_db]())
    try:
        fields = {
            "title": "High: port scan",
            "alert_type": "possible_port_scan",
            "src_ip": "203.0.113.60",
            "dst_ip": "10.20.30.60",
            "threat_score": 65,
            "severity": "High",
            "status": "open",
            "explanation": "Source touched 12 destination ports in five minutes.",
            "matched_rules_json": [
                {"code": "possible_port_scan", "title": "Possible vertical port scanning behavior", "score": 25, "explanation": "x"},
                {"code": "deny_drop_action", "title": "Deny or drop action", "score": 25, "explanation": "y"},
            ],
            "recommended_response": "Review.",
        }
        alert = Alert(**{**fields, **overrides})
        db.add(alert)
        db.commit()
        return alert.id
    finally:
        db.close()


def _steps(playbook: dict) -> dict[str, dict]:
    return {step["id"]: step for phase in playbook["phases"] for step in phase["steps"]}


def test_every_alertable_attack_type_has_its_own_playbook():
    # A new attack type must get deliberate guidance, not silently fall back
    # to the generic "unclassified" playbook.
    alertable = set(ATTACK_TYPE_MAPPINGS) - {"normal"}
    assert alertable <= set(PLAYBOOK_GUIDANCE)
    assert set(RULE_ATTACK_HINTS.values()) <= set(PLAYBOOK_GUIDANCE)
    assert set(PLAYBOOK_GUIDANCE) <= set(ATTACK_TYPE_MAPPINGS)


def test_unknown_attack_type_falls_back_to_the_generic_playbook():
    assert playbook_guidance("not_a_type")[0] == DEFAULT_PLAYBOOK
    assert playbook_guidance(None)[0] == DEFAULT_PLAYBOOK
    assert playbook_guidance("brute_force")[0] == "brute_force"


def test_port_scan_alert_gets_a_port_scan_playbook_built_from_its_own_evidence():
    client = _client()
    try:
        alert_id = _add_alert()
        headers = _login(client, "analyst", "analyst123")
        response = client.get(f"/api/alerts/{alert_id}/playbook", headers=headers)
        assert response.status_code == 200
        playbook = response.json()

        assert playbook["alert_id"] == alert_id
        assert playbook["attack_type"] == "port_scan"
        assert playbook["label"] == PLAYBOOK_GUIDANCE["port_scan"].label
        assert playbook["mitre"]["technique_id"] == "T1046"
        assert playbook["claim_boundary"] == ATTACK_TYPE_MAPPINGS["port_scan"]["claim_boundary"]
        assert [phase["key"] for phase in playbook["phases"]] == ["triage", "investigate", "contain", "close"]
        assert playbook["decision_guide"]["false_positive"] == PLAYBOOK_GUIDANCE["port_scan"].false_positive_when

        steps = _steps(playbook)
        # Rule-specific checks are the drawer's own text, reused rather than copied.
        investigate_texts = [step["text"] for step in playbook["phases"][1]["steps"]]
        assert RULE_ANALYST_CHECKS["possible_port_scan"][0] in investigate_texts
        assert "2 rules matched" in steps["triage-why"]["text"]
        assert steps["triage-why"]["action"] == {"kind": "ask", "question": f"Why was alert {alert_id} flagged?"}
        assert steps["investigate-source-activity"]["action"]["path"] == "/logs?src_ip=203.0.113.60"
        assert steps["contain-watch"]["action"]["path"] == "/controls?tab=watchlists"
        assert steps["close-status"]["action"]["path"] == f"/alerts?alert={alert_id}"
        assert not any(step["done"] for step in steps.values())
    finally:
        app.dependency_overrides.clear()


def test_playbook_progress_comes_from_what_analysts_actually_recorded():
    client = _client()
    try:
        alert_id = _add_alert(status="investigating")
        db = next(app.dependency_overrides[get_db]())
        try:
            db.add(AlertNote(alert_id=alert_id, author="analyst", note="Checked scanner inventory."))
            db.add(
                ResponseAction(
                    alert_id=alert_id,
                    action_type="block_ip",
                    target_ip="203.0.113.60",
                    status="simulated",
                    result_message="Simulated block recorded.",
                    executed_by="analyst",
                )
            )
            db.commit()
        finally:
            db.close()
        headers = _login(client, "analyst", "analyst123")

        steps = _steps(client.get(f"/api/alerts/{alert_id}/playbook", headers=headers).json())
        assert steps["triage-claim"]["done"] is True
        assert steps["close-notes"]["done"] is True
        assert steps["contain-block"]["done"] is True
        assert steps["close-status"]["done"] is False

        db = next(app.dependency_overrides[get_db]())
        try:
            db.get(Alert, alert_id).status = "false_positive"
            db.commit()
        finally:
            db.close()
        steps = _steps(client.get(f"/api/alerts/{alert_id}/playbook", headers=headers).json())
        assert steps["close-status"]["done"] is True
    finally:
        app.dependency_overrides.clear()


def test_alert_without_a_source_ip_skips_source_steps_and_uses_generic_guidance():
    client = _client()
    try:
        alert_id = _add_alert(src_ip=None, alert_type="api_test", matched_rules_json=[])
        headers = _login(client, "analyst", "analyst123")
        playbook = client.get(f"/api/alerts/{alert_id}/playbook", headers=headers).json()

        assert playbook["attack_type"] == "unknown_anomaly"
        steps = _steps(playbook)
        assert "investigate-source-activity" not in steps
        assert "contain-watch" not in steps
    finally:
        app.dependency_overrides.clear()


def test_opening_a_playbook_changes_nothing_and_requires_login():
    client = _client()
    try:
        alert_id = _add_alert()
        assert client.get(f"/api/alerts/{alert_id}/playbook").status_code == 401
        headers = _login(client, "analyst", "analyst123")

        db = next(app.dependency_overrides[get_db]())
        try:
            counts = lambda: tuple(  # noqa: E731
                db.scalar(select(func.count()).select_from(model)) for model in (Alert, AlertNote, ResponseAction, AuditLog)
            )
            before = counts()
            before_status = db.get(Alert, alert_id).status
        finally:
            db.close()

        assert client.get(f"/api/alerts/{alert_id}/playbook", headers=headers).status_code == 200
        assert client.get("/api/alerts/999999/playbook", headers=headers).status_code == 404

        db = next(app.dependency_overrides[get_db]())
        try:
            # Login writes audit rows, so compare everything except the audit log,
            # then confirm no audit row came from the playbook itself.
            assert counts()[:3] == before[:3]
            assert db.get(Alert, alert_id).status == before_status
            assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action.like("%playbook%"))) == 0
        finally:
            db.close()
    finally:
        app.dependency_overrides.clear()


def test_playbook_questions_reach_the_matching_assistant_answers():
    # The playbook's "Ask" buttons send these exact questions; each must land
    # on the answer it promises, not a generic fallback.
    client = _client()
    try:
        alert_id = _add_alert()
        headers = _login(client, "analyst", "analyst123")
        steps = _steps(client.get(f"/api/alerts/{alert_id}/playbook", headers=headers).json())
        expected_modes = {
            "triage-why": "alert_explanation",
            "triage-noise": "alert_explanation",
            "investigate-logs": "related_logs",
            "close-brief": "investigation_brief",
        }
        for step_id, mode in expected_modes.items():
            question = steps[step_id]["action"]["question"]
            payload = client.post("/api/assistant/chat", json={"question": question}, headers=headers).json()
            assert payload["response_mode"] == mode, (step_id, payload["response_mode"])
            assert payload["active_context"]["alert_id"] == alert_id, step_id
    finally:
        app.dependency_overrides.clear()
