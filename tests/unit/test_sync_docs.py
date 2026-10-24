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


#: A stand-in for ``loadtest/results.json``, same shape, carrying the values the
#: published percentages were derived from. Passed to ``drift`` explicitly so
#: these tests do not move when the real benchmark is re-run: a check of the
#: checker must not depend on the data it checks.
_RESULTS = {
    "results": {
        "engine": {"p50_us": 32.6, "p99_us": 142.2},
        "service-uncached": {"p50_us": 1658.4, "p99_us": 5311.7},
        "service-cached": {"p50_us": 1406.7, "p99_us": 5997.9},
        "service-no-audit": {"p50_us": 764.6, "p99_us": 3418.5},
    }
}


@pytest.fixture(autouse=True)
def _no_tracked_benchmark(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the derived-figure checks out of the tests that are about counts.

    Those tests point ``DOCUMENTS`` at a one-line temporary file, which contains
    none of the percentages -- so without this, every pattern would be reported
    as dead and each of them would fail for a reason that has nothing to do with
    what it tests. The tests that *are* about the percentages pass ``results``
    explicitly and are unaffected.
    """
    monkeypatch.setattr(sync_docs, "BENCHMARK_RESULTS", tmp_path / "absent.json")


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

    def test_a_stale_derived_percentage_is_reported(self, tmp_path, monkeypatch):
        """The figures nothing was checking, which is how "the rule layer is 3%"
        survived a re-measurement that made it 2%.

        Counts and durations were verified while these were not, and the reason
        is structural rather than an oversight: a count is *reported* by the
        suite, a percentage is *derived* from a latency run, and no code path
        recomputed it. So the sentence stayed green in four documents.
        """
        document = tmp_path / "README.md"
        document.write_text("规则层只占一次请求的 3%。\n", encoding="utf-8")
        monkeypatch.setattr(sync_docs, "DOCUMENTS", (document,))

        found = sync_docs.drift(
            sync_docs.Measurement(tests=796, coverage=94, seconds=16.7), results=_RESULTS
        )

        assert [item.published for item in found] == ["占一次请求的 3%"]
        assert found[0].actual.startswith("2%")
        assert found[0].fixable is True

    def test_a_derived_percentage_that_matches_reports_nothing(self, tmp_path, monkeypatch):
        """The other half. A check that always fires is as useless as one that
        never does, and there are seven phrases here that all have to agree."""
        document = tmp_path / "README.md"
        document.write_text(
            "规则层只占一次请求的 2%。审计关掉 p99 降 43%，缓存只省 15%。\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(sync_docs, "DOCUMENTS", (document,))

        found = sync_docs.drift(
            sync_docs.Measurement(tests=796, coverage=94, seconds=16.7), results=_RESULTS
        )

        assert found == []

    def test_a_reworded_phrase_is_reported_as_no_longer_checking(self, tmp_path, monkeypatch):
        """A phrase-based check fails by matching nothing, and says nothing.

        That is the same shape of silence this script was written to remove, so
        a pattern that matches no document is a failure rather than a pass --
        otherwise rewording one sentence retires its check without telling
        anyone, and the run stays green.
        """
        document = tmp_path / "README.md"
        document.write_text("规则层占比很小。\n", encoding="utf-8")
        monkeypatch.setattr(sync_docs, "DOCUMENTS", (document,))

        orphans = sync_docs.unmatched_derived_patterns(results=_RESULTS)

        assert len(orphans) == len(sync_docs.DERIVED_FIGURES)
        assert all(isinstance(pattern, str) for pattern in orphans)

    def test_ci_skips_the_duration_but_still_checks_the_percentages(self, tmp_path, monkeypatch):
        """What the CI step asks for, and why it is not "check nothing".

        The duration belongs to the machine that ran the suite; on a runner it
        would fail every push for a reason no change can fix, and a gate like
        that gets deleted rather than obeyed. So CI turns that one comparison
        off -- but it must still fail on a percentage, which is the whole point
        of adding this step.
        """
        document = tmp_path / "README.md"
        document.write_text(
            "796 个测试，80 秒跑完，覆盖率 94%。规则层只占一次请求的 9%。\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(sync_docs, "DOCUMENTS", (document,))
        measurement = sync_docs.Measurement(tests=796, coverage=94, seconds=16.7)

        with_duration = sync_docs.drift(measurement, results=_RESULTS)
        without = sync_docs.drift(measurement, results=_RESULTS, skip_duration=True)

        assert [item.published for item in with_duration] == ["80 秒跑完", "占一次请求的 9%"]
        assert [item.published for item in without] == ["占一次请求的 9%"]


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
