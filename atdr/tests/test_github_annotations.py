"""A test that fails on GitHub is put on the commit, where it can be read without a login."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from atdr.tests import github_annotations as annotations


def _report(*, failed: bool, said: str = "") -> SimpleNamespace:
    return SimpleNamespace(failed=failed, nodeid="atdr/tests/test_notifications.py::test_the_watcher_reports[a, b]",
                           location=("atdr/tests/test_notifications.py", 641, "test_the_watcher_reports[a, b]"), longrepr=said)


def _written(report: SimpleNamespace, *, reporter: bool = True) -> list[str]:
    lines: list[str] = []
    writer = SimpleNamespace(write_line=lines.append) if reporter else None
    item = SimpleNamespace(config=SimpleNamespace(pluginmanager=SimpleNamespace(get_plugin=lambda name: writer if name == "terminalreporter" else None)))
    hook = annotations.pytest_runtest_makereport(item, None)
    next(hook)
    with pytest.raises(StopIteration):
        hook.send(SimpleNamespace(get_result=lambda: report))
    return lines


def test_a_failed_test_is_put_on_the_commit_when_the_tests_run_on_github(monkeypatch):
    said = "    def test():\n>       assert body == 'It began 10:00'\nE       AssertionError: assert 'It began 03:00' == 'It began 10:00'\n\ntest_notifications.py:642: AssertionError"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    line, = _written(_report(failed=True, said=said))
    head, message = line.split("::", 2)[1:]
    assert head == "error file=atdr/tests/test_notifications.py,line=642,title=atdr/tests/test_notifications.py%3A%3Atest_the_watcher_reports[a%2C b]"
    assert message == ("def test():%0A>       assert body == 'It began 10:00'%0AE       AssertionError: assert 'It began 03:00' == 'It began 10:00'"
                       "%0Atest_notifications.py:642: AssertionError"), "the line breaks are GitHub's; blank lines are left out"

    # A test that passed says nothing, and nothing is said anywhere but on GitHub.
    assert _written(_report(failed=False, said=said)) == []
    monkeypatch.setenv("GITHUB_ACTIONS", "false")
    assert _written(_report(failed=True, said=said)) == []
    monkeypatch.delenv("GITHUB_ACTIONS")
    assert _written(_report(failed=True, said=said)) == []
    # Without a terminal to write to (a plugin took it away) the failure is still only a failure.
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert _written(_report(failed=True, said=said), reporter=False) == []


def test_an_annotation_keeps_the_end_of_what_a_test_said_and_escapes_what_github_would_read():
    long = "\n".join(f"line {number}: 100% of it" for number in range(1, 41))
    note = annotations.annotation("a.py::test_x", "a.py", None, long + "\r\nE   assert 1 == 2")
    assert note.startswith("::error file=a.py,line=1,title=a.py%3A%3Atest_x::line 34: 100%25 of it%0A")
    assert note.endswith("%0Aline 40: 100%25 of it%0AE   assert 1 == 2") and note.count("%0A") == 7
    huge = annotations.annotation("a.py::test_x", "a.py", 9, "x" * 5000)
    assert len(huge.split("::", 2)[2]) == annotations.MESSAGE_CHARACTERS == 900


def test_the_hook_is_part_of_the_test_setup(request):
    implementations = request.config.pluginmanager.hook.pytest_runtest_makereport.get_hookimpls()
    assert any(implementation.function is annotations.pytest_runtest_makereport for implementation in implementations)
