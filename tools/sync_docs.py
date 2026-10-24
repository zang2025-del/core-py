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
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parent.parent

#: Every document that quotes a figure from the suite.
DOCUMENTS: tuple[Path, ...] = (
    ROOT / "README.md",
    ROOT / "docs" / "architecture.md",
    ROOT / "docs" / "backend-resume.md",
)

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


def drift(measurement: Measurement) -> list[Drift]:
    found: list[Drift] = []
    for path in DOCUMENTS:
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if any(marker in line for marker in HISTORICAL_MARKERS):
                continue
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
            for match in DURATION_PATTERN.finditer(line):
                documented = int(match["s"])
                if abs(documented - measurement.seconds) > DURATION_TOLERANCE_SECONDS:
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


def rewrite(measurement: Measurement) -> list[Path]:
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

    remaining = drift(measurement)
    if not remaining:
        print("\nevery published figure matches the measured one")
        return 0

    print(f"\n{len(remaining)} figure(s) do not match:")
    for item in remaining:
        where = f"{_display(item.path)}:{item.line_number}"
        if item.fixable:
            print(f"  {where}  {item.published!r} -> {item.actual!r}")
            print(f"      {item.line}")
        else:
            # Not offerable as a rewrite: see the module docstring. The fix is a
            # re-worded sentence, and only a human can write that.
            print(f"  {where}  {item.published!r} but the run took {item.actual}")
            print(f"      {item.line}")
    print("\nrun again with --write to fix the countable ones")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
