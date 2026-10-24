"""The loadtest package is run by CI, because it once broke and nothing said so.

What this file exists for: adding authentication made every business endpoint
demand a credential, and `bench_http` built an app that presented none. The
service refused to start under it, so the HTTP benchmark was un-runnable for
several commits -- and nothing failed, because `loadtest/` was linted by CI and
never *run* by it. A benchmark that cannot authenticate does not error out; it
measures the 401 path, and a rejected request is a fast one, so the number that
comes back looks like a very good result.

So the gate drives the real function rather than a stand-in. `bench_http` calls
`response.raise_for_status()` on every request, which means "it returned samples
at all" is already the assertion that a credential was accepted: without one the
worker raises, the function re-raises, and this test fails.

Two things are deliberately cheap here. The iteration count is small, because
this checks that the path works and not what it costs -- the published figures
come from a full run on a quiet machine, and re-deriving them in CI would either
be flaky or be ignored. And the port is taken from the OS rather than hard-coded,
because three matrix jobs run the suite at once on shared runners and a fixed
port is a test that fails for reasons unrelated to the code.
"""

from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path

import pytest
from loadtest.benchmark import Samples, bench_http

#: The repository root, so the CLI can be run the way CI and the README run it
#: -- as a module from the project directory, not as an imported function.
ROOT = Path(__file__).resolve().parents[2]

#: Enough requests to exercise the server more than once, few enough that the
#: gate stays cheap. The first request also creates the schema, so the latency
#: of this sample set is not comparable to a published one -- which is why
#: nothing below asserts a duration.
ITERATIONS = 8


def _idle_port() -> int:
    """A port nothing is listening on, as of right now.

    Bind, read the port the OS assigned, close. There is a window between the
    close and uvicorn claiming it, and it cannot be closed from this side; a
    fixed port has the same window plus a guaranteed collision when the matrix
    runs the suite concurrently, so this is the smaller of the two problems.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.mark.slow
def test_bench_http_serves_a_real_decision(tmp_path):
    """The HTTP benchmark can start the app and get an answer out of it.

    This is the regression test for the defect described in the module
    docstring. It is not a performance test: it asserts that the path works,
    and deliberately says nothing about how fast it is.
    """
    samples = bench_http(
        ITERATIONS,
        tmp_path,
        threads=2,
        host="127.0.0.1",
        port=_idle_port(),
    )

    assert isinstance(samples, Samples)
    assert samples.operations == ITERATIONS
    assert len(samples.latencies_us) == ITERATIONS
    # Every request reached the endpoint and came back 2xx; a rejected one would
    # have raised through `raise_for_status` before being recorded.
    assert all(latency > 0 for latency in samples.latencies_us)


def test_the_benchmark_cli_runs():
    """`--help` works, which is the cheap half of "the CLI still runs".

    Run as a subprocess rather than by calling `main()`: `main()` reads
    `sys.argv` and starts a full benchmark, so it cannot be invoked from a unit
    test, and the way CI and the README call this is as a command line anyway.
    The option that matters is `--database-url` -- the backend comparison in
    `loadtest/backends.py` and the documented command line both name it, and an
    option that exists in one place and not the other is the failure this
    catches.
    """
    completed = subprocess.run(
        [sys.executable, "-m", "loadtest.benchmark", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "--database-url" in completed.stdout
    assert "--iterations" in completed.stdout
