"""A test that fails on GitHub is put on the commit as an annotation.

The log of a job there needs a login to read. An annotation does not: it is on the commit's page and in the public
API (check-runs/<id>/annotations). On 10 October 2026 the backend job failed on its Linux machine, in UTC, on a test
that passed on the laptop in Thai time, and nothing public said which test. GitHub keeps the first ten of a step.
"""

from __future__ import annotations

import os

import pytest

MESSAGE_CHARACTERS = 900
LAST_LINES = 8


def _escaped(text: str, *, in_a_property: bool = False) -> str:
    # The characters GitHub's workflow commands give a meaning of their own.
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if in_a_property else text


def annotation(nodeid: str, path: str, line: int | None, said: str) -> str:
    """The workflow command for one failed test: where it is, and the end of what it said (the assertion is there)."""

    lines = [part.rstrip() for part in said.strip().splitlines() if part.strip()]
    message = "\n".join(lines[-LAST_LINES:])[-MESSAGE_CHARACTERS:]
    return (f"::error file={_escaped(path, in_a_property=True)},line={int(line or 0) + 1},"
            f"title={_escaped(nodeid, in_a_property=True)}::{_escaped(message)}")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if os.environ.get("GITHUB_ACTIONS") != "true" or not report.failed:
        return
    reporter = item.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        path, line, _name = report.location
        reporter.write_line(annotation(report.nodeid, path, line, str(report.longrepr)))
