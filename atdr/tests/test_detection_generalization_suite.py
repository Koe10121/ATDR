import shutil
from pathlib import Path

from atdr.app.core.config import PROJECT_ROOT
from atdr.scripts.generate_detection_variants import generate_detection_variants


def _output_dir(name: str) -> Path:
    path = PROJECT_ROOT / ".tmp" / "tests" / name
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_generate_detection_variants_writes_safe_manifest():
    output_dir = _output_dir("detection_variants")

    manifest = generate_detection_variants(
        scenarios=["port_scan_like_traffic", "normal_web_dns_quic_traffic"],
        variants=2,
        output_dir=output_dir,
    )

    assert manifest["ok"] is True
    assert manifest["variant_count"] == 4
    assert manifest["safety"]["synthetic_defensive_logs_only"] is True
    assert manifest["safety"]["offensive_payloads_generated"] is False
    assert manifest["safety"]["writes_current_database"] is False
    assert Path(manifest["manifest_path"]).exists()
    for variant in manifest["variants"]:
        path = Path(variant["path"])
        assert path.exists()
        assert path.read_text(encoding="utf-8").strip()
        assert "safe_port_variation" in variant["variation_types"]


