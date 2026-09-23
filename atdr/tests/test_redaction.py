from __future__ import annotations

import ast
from pathlib import Path

import pytest

from atdr.app.core.redaction import AI_REVIEWER_PATTERN, IP_PATTERN

# The exact vocabulary AI_REVIEWER_PATTERN matches on. Used below to detect a
# *redefinition* of this pattern anywhere else in the codebase -- this same
# bug class (an independently-defined copy silently missing some of these
# terms) has recurred 5 times across this project's history, most recently
# in v527_blind_review_evaluation.py, v547_manual_anchor_acquisition.py, and
# v533_independent_acceptance_service.py, all now fixed to import the
# canonical pattern instead. This test exists so a 6th recurrence fails CI
# instead of shipping silently.
_CANONICAL_MARKER_WORDS = {
    "assistant", "automated", "bot", "chatgpt", "claude", "codex", "gemini",
    "heuristic", "language model", "llm", "model", "openai", "synthetic",
}
_REDACTION_MODULE = Path(__file__).resolve().parents[1] / "app" / "core" / "redaction.py"


def _is_re_compile_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr == "compile"
    if isinstance(func, ast.Name):
        return func.id == "compile"
    return False


def _named_constant_string_groups(tree: ast.AST):
    """Yield the string literals bound by every top-level constant
    assignment in a module -- the exact shape all 5 historical
    redefinitions of this pattern took: a module-level NAME = ... binding
    to either a single regex string (optionally wrapped in re.compile(...))
    or a set/tuple/list of marker words. Deliberately does NOT scan
    arbitrary string constants (docstrings, error messages, inline literals
    never bound to a name) -- those produce false positives from ordinary
    prose that happens to mention a provider name (e.g. a config validator
    error message listing "gemini, openai, claude" as allowed values)."""
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if value is None:
            continue
        if _is_re_compile_call(value):
            args = value.args
            value = args[0] if args else None
        if value is None:
            continue
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            values = [value.value]
        elif isinstance(value, (ast.Set, ast.Tuple, ast.List)):
            values = [
                elt.value
                for elt in value.elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            ]
        else:
            continue
        if values:
            yield values, node.lineno


def test_no_file_outside_redaction_module_redefines_ai_reviewer_markers():
    app_root = Path(__file__).resolve().parents[1] / "app"
    violations: list[str] = []
    for path in app_root.rglob("*.py"):
        if path.resolve() == _REDACTION_MODULE:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for values, lineno in _named_constant_string_groups(tree):
            blob = " ".join(values).lower()
            hits = sum(1 for marker in _CANONICAL_MARKER_WORDS if marker in blob)
            # A real redefinition reuses most of the vocabulary; an
            # incidental partial overlap (e.g. a docstring mentioning
            # "gemini" and "claude" once) won't reach this threshold.
            if hits >= 5:
                violations.append(f"{path.relative_to(app_root.parent.parent)}:{lineno}")
    assert not violations, (
        "Found file(s) outside atdr/app/core/redaction.py that look like an "
        "independent redefinition of AI_REVIEWER_PATTERN's marker vocabulary "
        "instead of importing it from atdr.app.core.redaction -- this is the "
        "exact duplicated-pattern-drift bug class that has recurred 5 times:\n"
        + "\n".join(violations)
    )


@pytest.mark.parametrize(
    "text,should_match",
    [
        ("192.168.1.1", True),
        ("fe80::1", True),
        ("fe80::1%eth0", True),
        ("2001:db8::1", True),
        ("2001:0db8:0000:0000:0000:ff00:0042:8329", True),
        ("::1", True),
        ("2001:db8:85a3::8a2e:370:7334", True),
        ("alert #1234", False),
        ("case ABCD-1234", False),
        ("mac address 00:1A:2B:3C:4D:5E", False),
        ("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", False),
    ],
)
def test_ip_pattern_covers_ipv4_and_ipv6_without_false_positives(text, should_match):
    assert bool(IP_PATTERN.search(text)) is should_match


def test_ip_pattern_catches_compressed_ipv6_that_the_old_v514_variant_missed():
    # v514_large_file_runtime_service.py previously defined its own broken
    # IP_PATTERN whose IPv6 branch required 2-7 full hextets with no `::`
    # compression support, so every one of these evaded its privacy check.
    for compressed in ("::1", "fe80::1", "2001:db8::1", "fd00::abcd"):
        assert IP_PATTERN.search(compressed), compressed


@pytest.mark.parametrize(
    "reviewer,should_match",
    [
        ("jane.doe", False),
        ("soc-analyst-3", False),
        ("reviewed via language model", True),
        ("gpt-4 assistant", True),
        ("automated-reviewer", True),
        ("Claude", True),
        ("gemini-pro", True),
        ("heuristic-scorer", True),
        ("synthetic-labeler", True),
    ],
)
def test_ai_reviewer_pattern_catches_ai_identity_signals(reviewer, should_match):
    assert bool(AI_REVIEWER_PATTERN.search(reviewer)) is should_match


def test_ai_reviewer_pattern_catches_language_model_phrase():
    # Two of the three previously-independent copies of this pattern
    # (v541_governed_blind_evidence.py, v551_field_qualification_service.py)
    # omitted "language model" as a match term, so this exact reviewer
    # string was rejected by one gate and silently accepted as human by the
    # other two.
    assert AI_REVIEWER_PATTERN.search("reviewed via language model")
