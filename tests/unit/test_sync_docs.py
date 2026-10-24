"""The document checker is itself checked, because both of its bugs were silent.

The first version parsed the suite's console summary, which ``pyproject.toml``
already silences with ``-q``: passing a second ``-q`` produced ``-qq``, the "783
passed" line was omitted entirely, and the function fell through to its error
path -- so it had never once worked. The second version read the totals off the
``<testsuites>`` root, but pytest writes them on the nested ``<testsuite>``, so
every run reported "0 tests, 0.0s".

Both failed in the same direction, which is why they are worth tests rather than
a note: a checker that cannot read the truth and a checker that reports success
while rewriting history both look like a green run. The third bug below is the
sharpest of the three -- ``--write`` replaced every match in the file while the
report skipped historical lines, so the README's account of a past failure was
rewritten to claim the current test count had missed it, and the self-check then
passed, because by then the number agreed with the measurement.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tools import sync_docs

JUNIT_WITH_ONE_SKIP = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<testsuites name="pytest tests">'
    '<testsuite name="pytest" errors="0" failures="0" skipped="1"'
    ' tests="783" time="10.210" timestamp="2026-10-24T17:37:11" hostname="host">'
    '<testcase classname="tests.unit.test_x" name="test_y" time="0.001" />'
    "</testsuite>"
    "</testsuites>"
)


def _write_reports(tmp_path: Path, junit: str, percent: float = 94.1) -> tuple[Path, Path]:
    junit_path = tmp_path / "junit.xml"
    junit_path.write_text(junit, encoding="utf-8")
    coverage_path = tmp_path / "coverage.json"
    coverage_path.write_text(json.dumps({"totals": {"percent_covered": percent}}), encoding="utf-8")
    return junit_path, coverage_path


class TestReadingTheSuite:
    def test_the_totals_come_from_the_nested_testsuite(self, tmp_path):
        """The root element carries only ``name``. Reading it reported 0."""
        junit, coverage = _write_reports(tmp_path, JUNIT_WITH_ONE_SKIP)
        measurement = sync_docs._read_reports(junit, coverage)

        assert measurement.tests == 782  # 783 collected, 1 skipped
        assert measurement.coverage == 94
        assert measurement.seconds == pytest.approx(10.21)

    def test_a_skipped_test_is_not_counted_as_a_pass(self, tmp_path):
        """``pytest`` prints "782 passed, 1 skipped"; the document says that
        number, so summing ``tests`` without removing the skips would publish
        783 and be wrong by one."""
        junit, coverage = _write_reports(tmp_path, JUNIT_WITH_ONE_SKIP)
        assert sync_docs._read_reports(junit, coverage).tests == 782

    def test_a_bare_testsuite_root_is_also_read(self, tmp_path):
        """Older plugins emit a single ``<testsuite>`` as the root."""
        bare = JUNIT_WITH_ONE_SKIP.replace('<testsuites name="pytest tests">', "").replace(
            "</testsuites>", ""
        )
        junit, coverage = _write_reports(tmp_path, bare)
        assert sync_docs._read_reports(junit, coverage).tests == 782


class TestReportingDrift:
    def test_a_stale_count_is_reported_as_fixable(self, tmp_path, monkeypatch):
        document = tmp_path / "README.md"
        document.write_text(
            "规则层能被穷举测试。766 个测试，12 秒跑完，覆盖率 94%。\n", encoding="utf-8"
        )
        monkeypatch.setattr(sync_docs, "DOCUMENTS", (document,))

        found = sync_docs.drift(sync_docs.Measurement(tests=783, coverage=94, seconds=12.0))

        assert [item.published for item in found] == ["766 个测试"]
        assert found[0].fixable is True

    def test_a_stale_duration_is_reported_but_never_auto_fixed(self, tmp_path, monkeypatch):
        """The duration depends on the machine -- ~10s on SQLite, ~80s on a
        server database -- so rewriting it would publish whichever box ran last.
        It is reported for a human to re-word instead."""
        document = tmp_path / "README.md"
        document.write_text("783 个测试，12 秒跑完，覆盖率 94%。\n", encoding="utf-8")
        monkeypatch.setattr(sync_docs, "DOCUMENTS", (document,))

        found = sync_docs.drift(sync_docs.Measurement(tests=783, coverage=94, seconds=80.0))

        assert [item.published for item in found] == ["12 秒跑完"]
        assert found[0].fixable is False

    def test_a_matching_document_reports_nothing(self, tmp_path, monkeypatch):
        document = tmp_path / "README.md"
        document.write_text("783 个测试，12 秒跑完，覆盖率 94%。\n", encoding="utf-8")
        monkeypatch.setattr(sync_docs, "DOCUMENTS", (document,))

        assert sync_docs.drift(sync_docs.Measurement(tests=783, coverage=94, seconds=12.0)) == []


class TestRewriting:
    def test_the_current_count_is_updated(self, tmp_path, monkeypatch):
        document = tmp_path / "README.md"
        document.write_text("766 个测试，覆盖率 94%。\n", encoding="utf-8")
        monkeypatch.setattr(sync_docs, "DOCUMENTS", (document,))

        sync_docs.rewrite(sync_docs.Measurement(tests=783, coverage=94, seconds=12.0))

        assert document.read_text(encoding="utf-8") == "783 个测试，覆盖率 94%。\n"

    @pytest.mark.parametrize("marker", ["当时", "那一次", "曾"])
    def test_a_historical_figure_is_left_exactly_as_it_was(self, tmp_path, monkeypatch, marker):
        """The bug this file exists for. The README explains each quality gate
        by naming the failure that put it there -- "the linter missed an import
        and the 278 tests of the day did not catch it" -- and rewriting that to
        the current count would invent a history in which 783 tests missed it."""
        document = tmp_path / "README.md"
        history = f"{marker} 278 个测试没抓到那次崩溃\n"
        document.write_text("783 个测试，覆盖率 94%。\n" + history, encoding="utf-8")
        monkeypatch.setattr(sync_docs, "DOCUMENTS", (document,))

        sync_docs.rewrite(sync_docs.Measurement(tests=783, coverage=94, seconds=12.0))

        assert document.read_text(encoding="utf-8").endswith(history)

    def test_a_drifted_history_and_a_current_figure_are_told_apart(self, tmp_path, monkeypatch):
        """Both on one document, and only the second one moves."""
        document = tmp_path / "README.md"
        document.write_text(
            "766 个测试，覆盖率 87%。\n当时 278 个测试没抓到那次崩溃\n", encoding="utf-8"
        )
        monkeypatch.setattr(sync_docs, "DOCUMENTS", (document,))

        sync_docs.rewrite(sync_docs.Measurement(tests=783, coverage=94, seconds=12.0))

        text = document.read_text(encoding="utf-8")
        assert text.startswith("783 个测试，覆盖率 94%。\n")
        assert text.endswith("当时 278 个测试没抓到那次崩溃\n")

    def test_writing_then_checking_is_clean(self, tmp_path, monkeypatch, capsys):
        """The self-check has to be able to fail. In the buggy version the
        rewrite altered the historical line and the check then passed, so the
        two agreeing proved nothing."""
        document = tmp_path / "README.md"
        document.write_text(
            "766 个测试，覆盖率 94%。\n当时 278 个测试没抓到那次崩溃\n", encoding="utf-8"
        )
        monkeypatch.setattr(sync_docs, "DOCUMENTS", (document,))
        measurement = sync_docs.Measurement(tests=783, coverage=94, seconds=12.0)

        exit_code = sync_docs.main(
            ["--write", "--tests", "783", "--coverage", "94", "--seconds", "12.0"]
        )

        assert exit_code == 0
        assert sync_docs.drift(measurement) == []

    def test_reporting_drift_exits_non_zero(self, tmp_path, monkeypatch):
        document = tmp_path / "README.md"
        document.write_text("766 个测试，覆盖率 94%。\n", encoding="utf-8")
        monkeypatch.setattr(sync_docs, "DOCUMENTS", (document,))

        exit_code = sync_docs.main(["--tests", "783", "--coverage", "94", "--seconds", "12.0"])

        assert exit_code == 1
