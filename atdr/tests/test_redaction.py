from __future__ import annotations

import pytest

from atdr.app.core.redaction import AI_REVIEWER_PATTERN, IP_PATTERN


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
