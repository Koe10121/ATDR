import re
from pathlib import Path

from atdr.app.detection.attack_mapping import ATTACK_TYPE_MAPPINGS, RULE_ATTACK_HINTS

FRONTEND_MAPPING = Path(__file__).resolve().parents[2] / "frontend" / "src" / "lib" / "attackMapping.ts"


def _frontend_rule_hints() -> dict[str, str]:
    source = FRONTEND_MAPPING.read_text(encoding="utf-8")
    block = re.search(r"const ruleHints[^=]*=\s*\{(.*?)\};", source, re.DOTALL)
    assert block, "ruleHints table not found in frontend/src/lib/attackMapping.ts"
    return dict(re.findall(r"^\s*([a-z0-9_]+):\s*\"([a-z0-9_]+)\"", block.group(1), re.MULTILINE))


def test_frontend_attack_type_fallback_mirrors_the_backend_mapping():
    # The two tables drifted before: 486 policy alerts showed as "malware C2" in
    # the alert list while their own detail drawer said "policy violation".
    assert _frontend_rule_hints() == RULE_ATTACK_HINTS


def test_every_rule_hint_names_a_known_attack_type():
    assert set(RULE_ATTACK_HINTS.values()) <= set(ATTACK_TYPE_MAPPINGS)
