"""Shared fixtures.

Every fixture builds its own settings object with ``_env_file=None``, so a
developer's local ``.env`` cannot change what the tests measure. That is not a
hypothetical: the first version of this suite read the ambient environment, and
a ``PERMGATE_PREAPPROVED_SCOPES`` left over from a manual experiment silently
turned four denial tests into passes.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from permgate.api.deps import Container, build_container, create_schema
from permgate.config import Settings
from permgate.main import create_app
from permgate.observability.metrics import RecordingMetrics


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        database_url=f"sqlite+pysqlite:///{(tmp_path / 'permgate-test.db').as_posix()}",
        log_json=False,
        log_level="WARNING",
        grant_cache_enabled=True,
        grant_cache_ttl_seconds=15.0,
        grant_cache_max_entries=128,
    )


@pytest.fixture
def metrics() -> RecordingMetrics:
    return RecordingMetrics()


@pytest.fixture
def container(settings: Settings, metrics: RecordingMetrics) -> Container:
    built = build_container(settings, metrics=metrics)
    create_schema(built.engine)
    yield built
    built.close()


@pytest.fixture
def session_factory(container: Container) -> sessionmaker[Session]:
    return container.session_factory


@pytest.fixture
def app(settings: Settings, metrics: RecordingMetrics):
    return create_app(settings, metrics=metrics)


@pytest.fixture
def client(app) -> TestClient:
    # The context manager matters: without it the lifespan never runs, so the
    # schema is never created and the failure looks like a missing table rather
    # than a misused fixture.
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def project(tmp_path):
    """A real directory with a project marker, so project-root discovery is
    exercised rather than bypassed."""
    root = tmp_path / "workspace"
    root.mkdir()
    (root / ".git").mkdir()
    return root
