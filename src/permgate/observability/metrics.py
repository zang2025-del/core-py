"""Prometheus metrics.

The label sets are closed enumerations, not free strings, and that is the
design decision worth defending: ``rule`` comes from ``domain.decision.Rule``,
so the label cardinality is bounded by the number of rules in the code. A
``rule`` label fed a raw reason string would grow with the corpus -- every new
command shape a new time series -- which is how a metrics backend falls over.
Reasons belong in the logs and the audit table; counts belong in Prometheus.

What is measured, and why each one earns its place:

``permgate_decisions_total{verdict, rule, tool}``
    The business outcome. ``verdict="deny"`` rising is either an attack or a
    misconfiguration, and the ``rule`` label says which.

``permgate_decision_latency_seconds``
    Histogram over the whole request-side decision path, cache included. This is
    the number a p99 SLO is written against.

``permgate_grant_cache_events_total{event}``
    ``hit`` / ``miss`` / ``eviction`` / ``invalidation``. A hit rate that drops,
    or evictions that are not zero, is the early warning for the two ways the
    cache misbehaves -- being useless, or being too small.

``permgate_grants_total{action}``
    ``created`` / ``revoked`` / ``cleared`` / ``unchanged``. The ``unchanged``
    count is the idempotency path actually being taken.
"""

from __future__ import annotations

from typing import Final, Protocol

from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest

NAMESPACE: Final = "permgate"

#: Latency buckets tuned to the workload: a decision is a handful of string
#: comparisons plus one indexed read, so the interesting range is sub-millisecond
#: to tens of milliseconds. The Prometheus defaults start at 5ms and would put
#: most of the traffic in the first bucket, which measures nothing.
LATENCY_BUCKETS: Final = (
    0.00005,
    0.0001,
    0.00025,
    0.0005,
    0.001,
    0.0025,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
)


class MetricsSink(Protocol):
    """The seam the services write to.

    A protocol rather than the prometheus objects directly, so that unit tests
    get a recording stub instead of a global registry that leaks between tests.
    """

    def decision(self, *, verdict: str, rule: str, tool: str, latency_seconds: float) -> None: ...
    def grant(self, *, action: str) -> None: ...
    def cache(self, *, event: str, size: int = 0) -> None: ...


class NullMetrics:
    """Records nothing. The default for tests and for ``metrics_enabled=false``."""

    def decision(self, *, verdict: str, rule: str, tool: str, latency_seconds: float) -> None:
        return None

    def grant(self, *, action: str) -> None:
        return None

    def cache(self, *, event: str, size: int = 0) -> None:
        return None


class PrometheusMetrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self._decisions = Counter(
            "decisions_total",
            "Tool-call decisions, by verdict and the rule that produced it.",
            ["verdict", "rule", "tool"],
            namespace=NAMESPACE,
            registry=self.registry,
        )
        self._latency = Histogram(
            "decision_latency_seconds",
            "End-to-end decision latency, cache included.",
            namespace=NAMESPACE,
            registry=self.registry,
            buckets=LATENCY_BUCKETS,
        )
        self._grants = Counter(
            "grants_total",
            "Grant store writes.",
            ["action"],
            namespace=NAMESPACE,
            registry=self.registry,
        )
        self._cache = Counter(
            "grant_cache_events_total",
            "Grant cache activity.",
            ["event"],
            namespace=NAMESPACE,
            registry=self.registry,
        )

    def decision(self, *, verdict: str, rule: str, tool: str, latency_seconds: float) -> None:
        self._decisions.labels(verdict=verdict, rule=rule, tool=tool).inc()
        self._latency.observe(latency_seconds)

    def grant(self, *, action: str) -> None:
        self._grants.labels(action=action).inc()

    def cache(self, *, event: str, size: int = 0) -> None:
        self._cache.labels(event=event).inc()

    def render(self) -> bytes:
        return generate_latest(self.registry)


class RecordingMetrics:
    """Test double: keeps the calls so a test can assert what was reported."""

    def __init__(self) -> None:
        self.decisions: list[dict[str, object]] = []
        self.grants: list[str] = []
        self.cache_events: list[str] = []

    def decision(self, *, verdict: str, rule: str, tool: str, latency_seconds: float) -> None:
        self.decisions.append(
            {"verdict": verdict, "rule": rule, "tool": tool, "latency": latency_seconds}
        )

    def grant(self, *, action: str) -> None:
        self.grants.append(action)

    def cache(self, *, event: str, size: int = 0) -> None:
        self.cache_events.append(event)
