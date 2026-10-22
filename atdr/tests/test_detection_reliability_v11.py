import json
from pathlib import Path







def test_internal_controlled_benchmark_manifest_is_safe_and_complete():
    manifest_path = Path("data/samples/benchmarks/internal_controlled_benchmark.json")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["production_readiness_claim"] is False
    assert payload["automatic_response_expected"] is False
    scenarios = {item["scenario"] for item in payload["entries"]}
    assert "normal_allowed_traffic" in scenarios
    assert "port_scan_like_traffic" in scenarios
    assert all(item["expected_no_automatic_response"] is True for item in payload["entries"])








