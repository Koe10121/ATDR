from __future__ import annotations

from pathlib import Path

from atdr.app.services.template_bridge_contract import (
    ATDR_HANDOFF_FILES,
    REQUIRED_TEMPLATE_FILES,
    build_template_bridge_contract_report,
)


def _write(root: Path, relative_path: str, content: str) -> None:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_complete_template(root: Path) -> None:
    marker_text = """
    x-access-token
    signIn
    twofa
    twofaSend
    introspectToken
    getClientProfile
    app.use(path + '/atdr/handoff'
    router.post('/start'
    /exchange
    handoff_code
    /mfu-ai-driven-log-based-threat-detection-and-response/registry
    submitAtdrHandoff
    """
    for relative_path in REQUIRED_TEMPLATE_FILES.values():
        _write(root, relative_path, marker_text)
    _write(
        root,
        "backend-node/.env.local",
        "\n".join(
            [
                "IAM_SDK_BASE_URL=https://iam.example.test",
                "IAM_SDK_CLIENT_ID=atdr-template-local",
                "IAM_SDK_CLIENT_SECRET=x",
                "IAM_SDK_AUDIENCE=atdr-api",
                "IAM_SDK_INTROSPECT_PATH=/api/v1/b2b/introspect",
                "IAM_SDK_PROFILE_PATH=/api/v1/b2b/clients/me",
            ]
        ),
    )


def _write_complete_atdr(root: Path) -> None:
    marker_text = """
    /mfu-iam/handoff/consume
    authenticate_mfu_iam_handoff_code
    httponly=True
    userToCookieSession
    legacy browser-token handoff
    """
    for relative_path in ATDR_HANDOFF_FILES.values():
        _write(root, relative_path, marker_text)


def test_template_bridge_contract_detects_shell_and_hides_secrets(tmp_path):
    template_root = tmp_path / "template"
    atdr_root = tmp_path / "atdr"
    _write_complete_template(template_root)
    _write_complete_atdr(atdr_root)

    report = build_template_bridge_contract_report(template_root=template_root, atdr_root=atdr_root)

    assert report["ok"] is True
    assert report["template_contract_detected"] is True
    assert report["atdr_receiver_detected"] is True
    assert report["secrets_exposed"] is False
    assert report["env_summary"]["values_redacted"] is True
    assert "IAM_SDK_CLIENT_SECRET" in report["env_summary"]["secret_like_env_var_names"]
    assert "IAM_SDK_CLIENT_SECRET=x" not in str(report)
    assert "handoff_code" in report["recommended_local_handoff"]
    assert "mfu_token" not in report["recommended_local_handoff"]
    assert report["template_markers"]["registered_atdr_registry_route"] is True
    assert report["template_markers"]["secure_registry_launcher"] is True
    assert not report["blockers"]


def test_template_bridge_contract_reports_missing_template_files(tmp_path):
    template_root = tmp_path / "template"
    atdr_root = tmp_path / "atdr"
    _write_complete_atdr(atdr_root)

    report = build_template_bridge_contract_report(template_root=template_root, atdr_root=atdr_root)

    assert report["ok"] is False
    assert report["template_contract_detected"] is False
    assert report["atdr_receiver_detected"] is True
    assert report["blockers"]
    assert "IAM_SDK_CLIENT_SECRET=x" not in str(report)
