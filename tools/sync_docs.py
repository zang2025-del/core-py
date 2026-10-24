"""Keep every published figure equal to a measured one.

The README's load-bearing claim is that its numbers were measured rather than
remembered: "783 tests, twelve seconds, 94%" is a sentence a reader can check,
and a figure that is stale by twenty costs the whole paragraph its credibility.
It is also the drift that happens by default -- adding a test is a one-line
change, updating four documents is not -- so the figures are compared against a
real run of the suite rather than against a second list hand-edited alongside it.

Run it before a commit that adds or removes tests::

    python tools/sync_docs.py            # report, exit non-zero on drift
    python tools/sync_docs.py --write    # bring the documents up to date

Two kinds of figure are treated differently, and the difference is the point.
The **test count** and the **coverage** are properties of the code, so a
mismatch is always a mistake and ``--write`` fixes it. The **duration** is a
property of the machine as much as of the suite -- the same tests take about ten
seconds on SQLite and about eighty on a server database -- so it is checked
against a tolerance and never rewritten automatically. Publishing whichever
number the last machine happened to produce would be the opposite of honest, so
the drift there is reported for a human to re-word.

Pass ``--tests``, ``--coverage`` and ``--seconds`` to check a run that already
happened instead of starting another one; all three together skip the suite
entirely, which is what a CI job that has just run the suite does.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parent.parent

#: Every file that quotes a figure. The two benchmark modules are here because
#: their docstrings are the text ``--help`` prints -- which makes them documents
#: with a command line attached, and they were the ones that went stale last.
DOCUMENTS: tuple[Path, ...] = (
    ROOT / "README.md",
    ROOT / "docs" / "architecture.md",
    ROOT / "docs" / "backend-resume.md",
    ROOT / "loadtest" / "benchmark.py",
    ROOT / "loadtest" / "backends.py",
)

#: The benchmark output the derived figures are computed from. Tracked in the
#: repository rather than produced on demand: those percentages describe a run
#: that already happened, and re-running a benchmark to check a sentence would
#: make the check depend on whichever machine happened to do it.
BENCHMARK_RESULTS = ROOT / "loadtest" / "results.json"

#: Two spellings of the same number ("766 个测试" and "766 测试"). One pattern
#: with an optional 个 covers both, and ``个?`` cannot match across the count
#: because the count is ``\d+`` immediately before it.
COUNT_PATTERN = re.compile(r"(?P<n>\d+)\s*个?测试")
COVERAGE_PATTERN = re.compile(r"覆盖率\s*(?P<p>\d+)\s*%")
DURATION_PATTERN = re.compile(r"(?P<s>\d+)\s*秒跑完")

#: How far the documented duration may sit from the measured one before it is
#: reported. Generous on purpose: this number is a paraphrase -- "ten seconds"
#: about a run on a developer's laptop -- and treating it as a measurement would
#: make it a promise the project cannot keep across machines.
DURATION_TOLERANCE_SECONDS = 5.0

#: Lines that quote a figure as history rather than as the current state. The
#: README explains each quality gate by naming the failure that put it there --
#: "the linter once missed a missing import, and the 278 tests of the day did not
#: catch the crash" -- and rewriting those numbers would be falsifying the
#: record, which is the opposite of what this script is for. Marked with an
#: explicit word rather than inferred, because inferring tense from prose is
#: exactly the kind of cleverness that silently stops working.
HISTORICAL_MARKERS: tuple[str, ...] = ("当时", "那一次", "曾")


@dataclass(frozen=True, slots=True)
class DerivedFigure:
    """A percentage in the prose, and how to recompute it from the benchmark.

    Kept separate from ``Measurement`` because it comes from a different place:
    the suite reports a count and a duration, while these are ratios of the
    latency figures in ``loadtest/results.json``.
    """

    pattern: re.Pattern[str]
    compute: Callable[[Mapping[str, Any]], int]
    what: str


def _median_us(results: Mapping[str, Any], layer: str) -> float:
    return float(results["results"][layer]["p50_us"])


def _p99_us(results: Mapping[str, Any], layer: str) -> float:
    return float(results["results"][layer]["p99_us"])


def _engine_share_of_a_request(results: Mapping[str, Any]) -> int:
    """The rule layer's p50 as a percentage of a served request's p50."""
    return round(100 * _median_us(results, "engine") / _median_us(results, "service-cached"))


def _audit_p99_drop(results: Mapping[str, Any]) -> int:
    """How far p99 falls when the audit write is removed."""
    return round(
        100 * (1 - _p99_us(results, "service-no-audit") / _p99_us(results, "service-cached"))
    )


def _cache_saving(results: Mapping[str, Any]) -> int:
    """How much of the grant lookup the cache removes, in median terms."""
    return round(
        100 * (1 - _median_us(results, "service-cached") / _median_us(results, "service-uncached"))
    )


#: The derived percentages, each with the phrases that introduce it.
#:
#: **These are the figures that went stale without a sound.** The checker
#: verified counts and durations while "the rule layer is 3%" sat in four
#: documents, wrong, and every run stayed green -- the numbers were not
#: *countable*, they were *derived*, and nothing recomputed them.
#:
#: Literal phrases rather than one general "any percentage" rule, because
#: coverage, recall and the false-positive rate are percentages too and they
#: come from the suite and the evaluation, not from a latency run. The cost of
#: that choice is written down rather than hidden: a phrase reworded out of
#: these documents makes its check silently stop matching, so
#: ``test_every_pattern_still_matches_a_document`` fails when one does. A check
#: that can quietly stop checking is the thing this whole script exists to
#: prevent.
#:
#: Unlike a duration, these are marked fixable. A duration belongs to the
#: machine that ran the suite, so rewriting it would publish whichever box went
#: last; a ratio of two figures in a tracked file recomputes to the same number
#: wherever it is evaluated.
DERIVED_FIGURES: tuple[DerivedFigure, ...] = (
    DerivedFigure(
        pattern=re.compile(r"占(?:一次)?请求的 (?P<p>\d+)%"),
        compute=_engine_share_of_a_request,
        what="the rule layer's share of a served request",
    ),
    DerivedFigure(
        pattern=re.compile(r"只占 (?P<p>\d+)%"),
        compute=_engine_share_of_a_request,
        what="the rule layer's share of a served request",
    ),
    DerivedFigure(
        pattern=re.compile(r"p99 降 (?P<p>\d+)%"),
        compute=_audit_p99_drop,
        what="the fall in p99 when the audit write is removed",
    ),
    DerivedFigure(
        pattern=re.compile(r"只省 (?P<p>\d+)%"),
        compute=_cache_saving,
        what="the median the grant cache saves",
    ),
    DerivedFigure(
        pattern=re.compile(r"rule layer is (?P<p>\d+)%"),
        compute=_engine_share_of_a_request,
        what="the rule layer's share of a served request",
    ),
    DerivedFigure(
        pattern=re.compile(r"cuts p99 by (?P<p>\d+)%"),
        compute=_audit_p99_drop,
        what="the fall in p99 when the audit write is removed",
    ),
    DerivedFigure(
        pattern=re.compile(r"grant cache saves (?P<p>\d+)%"),
        compute=_cache_saving,
        what="the median the grant cache saves",
    ),
)


def benchmark_results() -> Mapping[str, Any] | None:
    """The tracked benchmark output, or ``None`` when it is not there.

    Missing is not fatal -- a checkout without the results file should still
    have its test count checked -- but it must not be *silent*, which is why
    ``main`` prints a line when this returns ``None``. Reporting "matches" for a
    figure nobody compared is the failure this script exists to prevent.
    """
    try:
        return json.loads(BENCHMARK_RESULTS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


@dataclass(frozen=True, slots=True)
class Measurement:
    """What the suite actually did, as opposed to what the documents say."""

    tests: int
    coverage: int
    seconds: float


def measure() -> Measurement:
    """Run the suite once and read the three figures out of its output.

    The run is what ``--cov-fail-under=90`` in CI already does, so this costs
    one suite run and not a bespoke measurement harness.

    Read from ``--junit-xml`` and ``--cov-report=json`` rather than from the
    console summary. The summary is written for a human and changes with
    verbosity: ``pyproject.toml`` already sets ``-q``, so passing another ``-q``
    here produced ``-qq``, which omits the "783 passed in 10.4s" line entirely --
    and the first version of this function, which parsed that line, therefore
    never once succeeded. Machine-readable reports do not have that failure mode.
    """
    with tempfile.TemporaryDirectory() as scratch:
        junit = Path(scratch) / "junit.xml"
        coverage_json = Path(scratch) / "coverage.json"
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "--cov=permgate",
                f"--cov-report=json:{coverage_json}",
                f"--junit-xml={junit}",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        output = f"{completed.stdout}\n{completed.stderr}"
        if not junit.exists() or not coverage_json.exists():
            sys.stderr.write(output[-4000:])
            raise SystemExit(
                "the suite did not produce its reports; run it by hand and pass "
                "--tests/--coverage/--seconds"
            )
        return _read_reports(junit, coverage_json)


def _read_reports(junit: Path, coverage_json: Path) -> Measurement:
    root = ElementTree.parse(junit).getroot()
    # The totals sit on <testsuite>, not on the <testsuites> root -- the root
    # carries only ``name``, which is why the first version of this function
    # reported "0 tests, 0.0s" against a run of 783. Summed over every
    # <testsuite> rather than reading the first one, so a split run stays right.
    suites = root.iter("testsuite") if root.tag == "testsuites" else iter([root])
    total = 0
    skipped = 0
    seconds = 0.0
    for suite in suites:
        total += int(suite.get("tests", "0"))
        skipped += int(suite.get("skipped", "0"))
        skipped += int(suite.get("errors", "0"))
        seconds += float(suite.get("time", "0"))

    totals = json.loads(coverage_json.read_text(encoding="utf-8"))["totals"]
    return Measurement(
        tests=total - skipped,
        coverage=round(totals["percent_covered"]),
        seconds=seconds,
    )


@dataclass(frozen=True, slots=True)
class Drift:
    """One documented figure that does not match the measurement."""

    path: Path
    line_number: int
    line: str
    published: str
    actual: str
    fixable: bool


def drift(
    measurement: Measurement,
    results: Mapping[str, Any] | None = None,
    *,
    skip_duration: bool = False,
) -> list[Drift]:
    """Every documented figure that disagrees with the measurement.

    ``skip_duration`` exists for CI, and only for CI. The duration is a property
    of the machine, which the module docstring already explains, so on a runner
    whose speed has nothing to do with the laptop the documents describe, the
    check would fail on every push for a reason no change can fix -- and a gate
    that fails for an unfixable reason gets deleted. Counts, coverage and the
    derived percentages are compared either way, and those are the figures that
    move when the code moves.
    """
    found: list[Drift] = []
    derived_source = benchmark_results() if results is None else results
    for path in DOCUMENTS:
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if any(marker in line for marker in HISTORICAL_MARKERS):
                continue
            found.extend(_suite_drift(path, line_number, line, measurement))
            if not skip_duration:
                found.extend(_duration_drift(path, line_number, line, measurement))
            found.extend(_derived_drift(path, line_number, line, derived_source))
    return found


def _suite_drift(path: Path, line_number: int, line: str, measurement: Measurement) -> list[Drift]:
    """The two figures the suite reports about itself.

    Both are fixable, because both are properties of the code: a count that is
    wrong is wrong everywhere, and ``--write`` can set it.
    """
    found: list[Drift] = []
    for match in COUNT_PATTERN.finditer(line):
        if int(match["n"]) != measurement.tests:
            found.append(
                Drift(
                    path=path,
                    line_number=line_number,
                    line=line.strip(),
                    published=match.group(0),
                    actual=f"{measurement.tests} 个测试",
                    fixable=True,
                )
            )
    for match in COVERAGE_PATTERN.finditer(line):
        if int(match["p"]) != measurement.coverage:
            found.append(
                Drift(
                    path=path,
                    line_number=line_number,
                    line=line.strip(),
                    published=match.group(0),
                    actual=f"覆盖率 {measurement.coverage}%",
                    fixable=True,
                )
            )
    return found


def _derived_drift(
    path: Path, line_number: int, line: str, results: Mapping[str, Any] | None
) -> list[Drift]:
    """The percentages recomputed from the tracked benchmark output.

    Empty when that file is absent, which is why ``main`` says so out loud
    rather than reporting a clean run: a figure nobody compared is not a figure
    that matches.
    """
    if results is None:
        return []
    found: list[Drift] = []
    for figure in DERIVED_FIGURES:
        expected = figure.compute(results)
        for match in figure.pattern.finditer(line):
            if int(match["p"]) != expected:
                found.append(
                    Drift(
                        path=path,
                        line_number=line_number,
                        line=line.strip(),
                        published=match.group(0),
                        actual=f"{expected}% ({figure.what})",
                        fixable=True,
                    )
                )
    return found


def _duration_drift(
    path: Path, line_number: int, line: str, measurement: Measurement
) -> list[Drift]:
    """The one figure that is reported and never rewritten.

    Extracted from ``drift`` for two reasons, and the second is the real one.
    A duration belongs to the machine that ran the suite -- about ten seconds on
    SQLite, about eighty on a server database -- so setting it to whatever the
    last run produced would publish an arbitrary number with confidence. It is
    compared within a tolerance and handed to a human to re-word.
    """
    found: list[Drift] = []
    for match in DURATION_PATTERN.finditer(line):
        if abs(int(match["s"]) - measurement.seconds) > DURATION_TOLERANCE_SECONDS:
            found.append(
                Drift(
                    path=path,
                    line_number=line_number,
                    line=line.strip(),
                    published=match.group(0),
                    actual=f"measured {measurement.seconds:.1f}s",
                    fixable=False,
                )
            )
    return found


def unmatched_derived_patterns(results: Mapping[str, Any] | None = None) -> list[str]:
    """Regexes that no longer match anything, so they stopped checking.

    A phrase-based check has one failure mode that a value-based one does not:
    reword the sentence and the check keeps passing against nothing. That is the
    same shape of silence this script was written to remove, so it is reported
    as a failure instead of being left to be noticed.
    """
    source = benchmark_results() if results is None else results
    if source is None:
        return []
    text = "\n".join(path.read_text(encoding="utf-8") for path in DOCUMENTS)
    return [figure.pattern.pattern for figure in DERIVED_FIGURES if not figure.pattern.search(text)]


def rewrite(measurement: Measurement, results: Mapping[str, Any] | None = None) -> list[Path]:
    """Set the countable figures to their measured values.

    Line by line, and skipping the same historical lines ``drift`` skips. The
    second part is not tidiness. The first version of this function replaced
    every match in the file while ``drift`` reported only the current-state
    ones, so the README's account of a past failure -- "the linter missed an
    import and the 278 tests of the day did not catch it" -- was rewritten to
    claim that 783 tests had missed it, and the self-check then passed, because
    by then the number agreed with the measurement. A tool that removes drift by
    inventing history is worse than no tool.

    Lines are rewritten individually and rejoined with their own endings
    (``keepends``), so a CRLF file stays CRLF rather than becoming a whole-file
    diff over two changed characters.
    """
    touched: list[Path] = []
    derived_source = benchmark_results() if results is None else results
    for path in DOCUMENTS:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        rewritten: list[str] = []
        for line in lines:
            if any(marker in line for marker in HISTORICAL_MARKERS):
                rewritten.append(line)
                continue
            updated = COUNT_PATTERN.sub(
                lambda match: match.group(0).replace(match["n"], str(measurement.tests)), line
            )
            updated = COVERAGE_PATTERN.sub(
                lambda match: match.group(0).replace(match["p"], str(measurement.coverage)),
                updated,
            )
            if derived_source is not None:
                for figure in DERIVED_FIGURES:
                    expected = str(figure.compute(derived_source))
                    updated = figure.pattern.sub(
                        lambda match, value=expected: match.group(0).replace(match["p"], value),
                        updated,
                    )
            rewritten.append(updated)
        new_text = "".join(rewritten)
        if new_text != "".join(lines):
            path.write_text(new_text, encoding="utf-8")
            touched.append(path)
    return touched


def _display(path: Path) -> str:
    """A path as it should be printed: repo-relative when it is in the repo.

    The documents are inside the project, so the relative form is what a reader
    wants. A test points ``DOCUMENTS`` at a file under ``tmp_path``, which makes
    ``relative_to(ROOT)`` raise ``ValueError`` -- and a reporting tool that
    crashes while reporting is the one failure it cannot afford.
    """
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--write",
        action="store_true",
        help="rewrite the countable figures instead of only reporting",
    )
    parser.add_argument("--tests", type=int, help="use this count instead of running the suite")
    parser.add_argument(
        "--coverage", type=int, help="use this percentage instead of running the suite"
    )
    parser.add_argument(
        "--seconds", type=float, help="use this duration instead of running the suite"
    )
    parser.add_argument(
        "--skip-duration",
        action="store_true",
        help="skip the duration check (for CI, whose machine is not the one described)",
    )
    args = parser.parse_args(argv)

    if args.tests is not None and args.coverage is not None and args.seconds is not None:
        measurement = Measurement(tests=args.tests, coverage=args.coverage, seconds=args.seconds)
        print(
            f"using the supplied run: {measurement.tests} tests, "
            f"{measurement.coverage}% coverage, {measurement.seconds:.1f}s"
        )
    else:
        measurement = measure()
        print(
            f"measured: {measurement.tests} tests, "
            f"{measurement.coverage}% coverage, {measurement.seconds:.1f}s"
        )

    if args.write:
        touched = rewrite(measurement)
        for path in touched:
            print(f"rewrote {_display(path)}")
        if not touched:
            print("nothing to rewrite")

    if benchmark_results() is None:
        print(
            f"\nnote: {_display(BENCHMARK_RESULTS)} is missing, so the derived "
            "percentages were not checked"
        )

    return _report(
        drift(measurement, skip_duration=args.skip_duration), unmatched_derived_patterns()
    )


def _report(remaining: Sequence[Drift], orphans: Sequence[str]) -> int:
    """Print what drifted and say whether the run is clean.

    Split out of ``main`` so each stays readable: ``main`` reads arguments and
    runs the suite, this decides what to say about the result. The two kinds of
    failure are reported separately because they need different fixes -- a value
    that moved is ``--write``, while a phrase that no longer matches is a
    sentence only a human can restore.
    """
    if not remaining and not orphans:
        print("\nevery published figure matches the measured one")
        return 0

    if orphans:
        print(
            f"\n{len(orphans)} derived figure(s) are no longer present in any "
            "document, so those checks compare nothing:"
        )
        for pattern in orphans:
            print(f"  {pattern!r} matched no line")
        print("\nre-word it back, or drop the entry from DERIVED_FIGURES")

    if remaining:
        print(f"\n{len(remaining)} figure(s) do not match:")
        for item in remaining:
            where = f"{_display(item.path)}:{item.line_number}"
            if item.fixable:
                print(f"  {where}  {item.published!r} -> {item.actual!r}")
                print(f"      {item.line}")
            else:
                # Not offerable as a rewrite: see the module docstring. The fix
                # is a re-worded sentence, and only a human can write that.
                print(f"  {where}  {item.published!r} but the run took {item.actual}")
                print(f"      {item.line}")
        print("\nrun again with --write to fix the countable ones")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
