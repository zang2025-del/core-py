"""Composition root.

Every dependency the request path needs is built once, at startup, and hung off
``app.state``. Nothing constructs an engine, a session factory or a service
inside a request.

The reason is not tidiness. A service that builds its own session factory per
call gets a connection pool per call, and the failure that produces under load
is a connection storm that looks like a database problem and is not one. Making
construction explicit and once-only means "how many connections does this
service open?" has an answer that does not depend on traffic.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from ..config import Settings
from ..domain.policies import DEFAULT_REGISTRY, PolicyRegistry
from ..observability.metrics import MetricsSink, NullMetrics, PrometheusMetrics
from ..services.decision_service import DecisionService
from ..services.grant_service import AuditService, GrantService
from ..storage.cache import GrantCache, build_cache
from ..storage.database import create_db_engine, create_session_factory
from ..storage.models import Base
from ..storage.triggers import install_append_only_triggers


@dataclass(slots=True)
class Container:
    """Everything a request can reach, and nothing else."""

    settings: Settings
    engine: Engine
    session_factory: sessionmaker[Session]
    cache: GrantCache
    registry: PolicyRegistry
    metrics: MetricsSink
    decisions: DecisionService
    grants: GrantService
    audit: AuditService

    def close(self) -> None:
        self.engine.dispose()


def build_container(settings: Settings, *, metrics: MetricsSink | None = None) -> Container:
    engine = create_db_engine(settings)
    session_factory = create_session_factory(engine)
    cache = build_cache(
        enabled=settings.grant_cache_enabled,
        ttl_seconds=settings.grant_cache_ttl_seconds,
        max_entries=settings.grant_cache_max_entries,
    )

    if metrics is not None:
        sink: MetricsSink = metrics
    elif settings.metrics_enabled:
        sink = PrometheusMetrics()
    else:
        sink = NullMetrics()

    return Container(
        settings=settings,
        engine=engine,
        session_factory=session_factory,
        cache=cache,
        registry=DEFAULT_REGISTRY,
        metrics=sink,
        decisions=DecisionService(
            session_factory=session_factory,
            settings=settings,
            cache=cache,
            registry=DEFAULT_REGISTRY,
            metrics=sink,
        ),
        grants=GrantService(session_factory=session_factory, cache=cache, metrics=sink),
        audit=AuditService(session_factory=session_factory, settings=settings),
    )


def create_schema(engine: Engine) -> None:
    """Create the tables if they are not there, and protect the audit trail.

    Alembic owns migrations; this exists so the test suite and a first local run
    do not need a migration step before they can do anything. Production runs
    ``alembic upgrade head`` and leaves the auto-create off.

    The triggers are installed here as well as in the migration, from the same
    module. Two paths that create the schema would otherwise be two places for
    the append-only guarantee to drift apart -- and the drift would be invisible,
    because a missing trigger looks exactly like a table that was never written
    to.
    """
    Base.metadata.create_all(engine)
    install_append_only_triggers(engine)


def schema_revision(engine: Engine) -> str | None:
    """Read Alembic's revision without importing Alembic.

    Readiness has to be answerable by the process being probed, and pulling the
    migration toolchain into the serving image to answer one query is the kind
    of dependency that only hurts when something is already wrong.
    """
    try:
        with engine.connect() as connection:
            row = connection.execute(text("SELECT version_num FROM alembic_version")).first()
    except Exception:
        return None
    return str(row[0]) if row else None


def get_container(request: Request) -> Container:
    container: Container = request.app.state.container
    return container
