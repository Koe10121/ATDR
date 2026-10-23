"""Every ATDR script that the code, the start-up scripts, CI or the current docs name still exists.

The 22 October 2026 clean-up removed 165 scripts nothing ran, but the readiness doctor and the portability audit still
told the operator to run atdr.scripts.run_postgres_lab_validation, and two of the assistant's built-in answers named
removed report scripts (found 23 October). Archived docs and the tests (which name fakes on purpose) are left out.
"""

from __future__ import annotations

import re
import subprocess

from atdr.app.core.config import PROJECT_ROOT

# A name followed by a capital, "*" or "{" is a pattern ("run_vNNN_*.py"), not a script.
NAMED = re.compile(r"atdr[./\\]scripts[./\\]([a-z][a-z0-9_]*)(?![A-Za-z0-9_*{])")
CHECKED_SUFFIXES = (".py", ".ps1", ".cmd", ".yml", ".yaml", ".md", ".ts", ".tsx", ".json")


def _checked_files() -> list[str]:
    tracked = subprocess.run(["git", "ls-files"], cwd=PROJECT_ROOT, capture_output=True, text=True, check=True).stdout.split("\n")
    return [
        path
        for path in tracked
        if path.endswith(CHECKED_SUFFIXES) and not path.startswith(("atdr/tests/", "docs/archive/", "frontend/node_modules/"))
    ]


def test_every_named_atdr_script_exists():
    missing: dict[str, list[str]] = {}
    for path in _checked_files():
        text = (PROJECT_ROOT / path).read_text(encoding="utf-8", errors="replace")
        for name in set(NAMED.findall(text)):
            if name == "__init__" or (PROJECT_ROOT / "atdr" / "scripts" / f"{name}.py").exists():
                continue
            if f'startswith("atdr/scripts/{name}")' in text:  # a prefix the code matches paths against
                continue
            missing.setdefault(name, []).append(path)

    assert not missing, "\n".join(f"atdr.scripts.{name} is named in {', '.join(paths)} but does not exist" for name, paths in sorted(missing.items()))


def test_the_check_finds_a_script_that_is_named_but_gone():
    assert NAMED.findall("run `python -m atdr.scripts.run_postgres_lab_validation --pretty`") == ["run_postgres_lab_validation"]
    assert NAMED.findall('Citation("runner", "atdr/scripts/run_v357_queue_rule_hybrid_agreement.py")') == ["run_v357_queue_rule_hybrid_agreement"]
    assert not (PROJECT_ROOT / "atdr" / "scripts" / "run_postgres_lab_validation.py").exists()


def test_a_name_pattern_is_not_taken_for_a_script():
    assert NAMED.findall("a one-off `atdr/scripts/run_vNNN_*.py` script") == []
    assert NAMED.findall("python -m atdr.scripts.backup_now --pretty") == ["backup_now"]
