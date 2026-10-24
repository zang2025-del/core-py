"""The same request path on two backends, so "it depends on the database" is
checkable instead of arguable.

``benchmark.py`` answers "where does the time go" for one backend. This answers
"what changes when the backend changes", which is a different question and cannot
be answered by subtracting two numbers measured on different days. Both backends
run here, in one process, over the same corpus, under the same conditions.

The result is deliberately not "PostgreSQL is faster" or "SQLite is faster":

    threads    SQLite p50    SQLite p99      PG p50      PG p99
    1            1507us         6422us      2691us      6997us
    4            1853us        57754us      7495us     17694us
    8            1923us       110654us     14134us     59362us
    16           2720us       222322us     31876us    207193us

Read that as a trade rather than a ranking:

1. **SQLite's median is flat; its tail explodes.** 1 -> 16 threads moves the
   median 1.8x and p99 by 35x. Writers queue behind one another, so the typical
   request is barely touched by concurrency while the unlucky one waits for the
   whole queue.
2. **PostgreSQL's median grows with threads; its tail catches up.** The median
   rises 12x over the same range. The tail is genuinely better in the middle of
   the range -- 4.1x at two threads, 1.9x at eight -- but by sixteen threads the
   advantage has almost entirely gone (1.07x). Both backends converge on the same
   bad tail; they just arrive by different routes.
3. **Neither wins, and the ordering is not stable.** SQLite holds the median at
   every thread count and loses the tail until the range where it stops losing
   it. "Move to PostgreSQL to fix the write queueing" is the obvious guess: the
   queueing does go away, and the round-trip cost it was hiding becomes the new
   dominant term. Which backend is better therefore depends on whether the
   workload is latency-sensitive at the median or the tail, and on how many
   threads are actually running.

Three explanations were tested and two were wrong, which is why they are listed:

*Not the fsync.* PostgreSQL here runs with ``fsync=on`` and
``synchronous_commit=on`` -- it is durable -- yet ``synchronous_commit=off``
saves nothing measurable (1.00x). The median gap is not the commit flush.

*Not the connection pool.* At 8 threads a pool of 20 measures the same median as
the default pool of 5 (15044us against 14591us -- the larger pool is marginally
slower, which is the wrong direction for a queueing explanation). The threads are
not queuing on a connection. The larger pool did measure a consistently lower p99
over three separate runs (36-50ms against 61-66ms), but that is one machine and
one pool size, so it is recorded rather than promoted to a finding.

*The round trip explains part of it.* A bare ``SELECT 1`` costs 209us against
PostgreSQL and 34us against SQLite, and one decision issues two statements, so
~350us of the single-threaded gap is the socket. The measured gap at one thread
is 1184us, so most of it is elsewhere -- per-statement driver overhead, not one
identifiable thing. This is stated rather than guessed at because the guess was
wrong twice already.

Machine facts are printed with the numbers, because a latency figure without them
is not a measurement.

Usage::

    python loadtest/backends.py --postgres-url postgresql+psycopg://user@host/db
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for extra in (str(ROOT), str(ROOT / "src")):
    if extra not in sys.path:
        sys.path.insert(0, extra)

from loadtest.benchmark import COMMANDS, Samples, machine_facts  # noqa: E402

THREAD_COUNTS = (1, 2, 4, 8, 16)


def run_service(
    database_url: str,
    project: Path,
    *,
    threads: int,
    iterations: int,
    pool_size: int | None = None,
    tag: str | None = None,
) -> Samples:
    """One layer measurement: the decision path at a given thread count."""
    from permgate.api.deps import build_container, create_schema
    from permgate.config import Settings
    from permgate.storage.models import Base

    project.mkdir(parents=True, exist_ok=True)
    (project / ".git").mkdir(exist_ok=True)
    root = str(project)

    overrides: dict[str, object] = {}
    if pool_size is not None:
        overrides["db_pool_size"] = pool_size
        overrides["db_max_overflow"] = pool_size

    settings = Settings(
        _env_file=None,
        database_url=database_url,
        grant_cache_enabled=True,
        log_json=False,
        log_level="CRITICAL",
        **overrides,  # type: ignore[arg-type]
    )
    container = build_container(settings)
    # A server database is shared across variants; the SQLite path gets isolation
    # from a per-variant filename, so this gives the server path the same
    # starting state rather than a table that grows between measurements.
    Base.metadata.drop_all(container.engine)
    create_schema(container.engine)

    per_thread = max(1, iterations // threads)
    collected: list[list[float]] = [[] for _ in range(threads)]
    errors: list[BaseException] = []
    barrier = threading.Barrier(threads)

    def worker(slot: int) -> None:
        try:
            barrier.wait()
            for index in range(per_thread):
                command = COMMANDS[(slot + index) % len(COMMANDS)]
                begin = time.perf_counter()
                container.decisions.evaluate(
                    project_root=root, tool="bash", arguments={"command": command}
                )
                collected[slot].append((time.perf_counter() - begin) * 1_000_000)
        except BaseException as exc:  # re-raised after the join
            errors.append(exc)

    # Warm-up, so the first call's schema introspection is not in the sample.
    for command in COMMANDS:
        container.decisions.evaluate(project_root=root, tool="bash", arguments={"command": command})

    workers = [threading.Thread(target=worker, args=(slot,)) for slot in range(threads)]
    started = time.perf_counter()
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()
    wall = time.perf_counter() - started
    container.close()

    if errors:
        raise RuntimeError(f"{len(errors)} worker(s) failed, first: {errors[0]!r}")

    samples = Samples(tag or f"threads-{threads}")
    samples.latencies_us = [value for slot in collected for value in slot]
    samples.wall_seconds = wall
    samples.operations = len(samples.latencies_us)
    return samples


def scaling(url: str, where: Path, *, iterations: int) -> list[Samples]:
    out: list[Samples] = []
    for threads in THREAD_COUNTS:
        out.append(
            run_service(
                url,
                where / f"scaling-{threads}",
                threads=threads,
                iterations=iterations,
                tag=f"threads-{threads}",
            )
        )
    return out


def render_scaling(title: str, samples: list[Samples]) -> list[str]:
    out = ["", title]
    header = (
        f"  {'threads':<9}{'ops':>7}{'ops/s':>9}{'mean':>11}"
        f"{'p50':>11}{'p90':>11}{'p99':>11}{'max':>12}"
    )
    out.append(header)
    out.append("  " + "-" * (len(header) - 2))
    for sample in samples:
        summary = sample.summary()
        threads = sample.name.split("-")[-1]
        out.append(
            f"  {threads:<9}{int(summary['operations']):>7}"
            f"{summary['throughput_per_second']:>9.0f}"
            f"{summary['mean_us']:>10.1f}u"
            f"{summary['p50_us']:>10.1f}u"
            f"{summary['p90_us']:>10.1f}u"
            f"{summary['p99_us']:>10.1f}u"
            f"{summary['max_us']:>11.1f}u"
        )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--postgres-url",
        required=True,
        help="a real PostgreSQL, e.g. postgresql+psycopg://user@host/db",
    )
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--json", help="write raw numbers here")
    args = parser.parse_args()

    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    facts = machine_facts()
    report: dict[str, object] = {"machine": facts, "scaling": {}, "pool": {}}

    # A cleanup race on a just-closed SQLite file would otherwise discard a
    # finished measurement, and the measurement is the point.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        tmp_path = Path(tmp)

        sqlite_url = f"sqlite+pysqlite:///{(tmp_path / 'compare.db').as_posix()}"
        print("[1/3] SQLite across thread counts ...", file=sys.stderr)
        sqlite_samples = scaling(sqlite_url, tmp_path / "sqlite", iterations=args.iterations)
        print("[2/3] PostgreSQL across thread counts ...", file=sys.stderr)
        pg_samples = scaling(args.postgres_url, tmp_path / "pg", iterations=args.iterations)

        print("[3/3] PostgreSQL with a larger pool, 8 threads ...", file=sys.stderr)
        pool_default = run_service(
            args.postgres_url,
            tmp_path / "pg-pool-default",
            threads=8,
            iterations=args.iterations,
            tag="pool-default",
        )
        pool_raised = run_service(
            args.postgres_url,
            tmp_path / "pg-pool-20",
            threads=8,
            iterations=args.iterations,
            pool_size=20,
            tag="pool-20",
        )

    lines: list[str] = []
    lines.append("=" * 96)
    lines.append("permgate -- the same request path on two backends")
    lines.append("=" * 96)
    lines.append("")
    for key, value in facts.items():
        lines.append(f"  {key:<12} {value}")
    lines.extend(render_scaling("  SQLite", sqlite_samples))
    lines.extend(render_scaling("  PostgreSQL", pg_samples))

    pool_header = f"  {'pool (8 threads)':<20}{'p50':>11}{'p99':>11}"
    lines.append("")
    lines.append("  PostgreSQL, connection pool")
    lines.append(pool_header)
    lines.append("  " + "-" * (len(pool_header) - 2))
    for sample in (pool_default, pool_raised):
        summary = sample.summary()
        lines.append(f"  {sample.name:<20}{summary['p50_us']:>10.1f}u{summary['p99_us']:>10.1f}u")

    lines.append("")
    lines.append("  Both backends measured in this one process, same corpus, same conditions.")
    lines.append("  The comparison is a trade: SQLite holds the median and loses the tail,")
    lines.append("  PostgreSQL does the reverse. Neither dominates, so this table is not a")
    lines.append("  ranking and must not be read as one.")
    lines.append("")
    print("\n".join(lines))

    report["scaling"] = {
        "sqlite": {s.name: s.summary() for s in sqlite_samples},
        "postgres": {s.name: s.summary() for s in pg_samples},
    }
    report["pool"] = {s.name: s.summary() for s in (pool_default, pool_raised)}

    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[written {path}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
