"""Shared fixtures.

Every fixture builds its own settings object with ``_env_file=None``, so a
developer's local ``.env`` cannot change what the tests measure. That is not a
hypothetical: the first version of this suite read the ambient environment, and
a ``PERMGATE_PREAPPROVED_SCOPES`` left over from a manual experiment silently
turned four denial tests into passes.

**Authentication is on in every test**, and that is a deliberate change of
posture rather than a default inherited by accident. Before it, ``POST
/v1/grants`` was reachable by anyone who could open a socket, and the suite
could not have noticed -- it asserted verdicts, not callers. Now the shared
``settings`` fixture provisions a bootstrap client so the app under test
*starts at all*, and the shared ``client`` fixture presents its token. Tests
that build their own app need the same two things, which is why the token lives
in one constant here rather than being spelled out in each of them.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from permgate.api.deps import Container, build_container, create_schema
from permgate.config import Settings
from permgate.main import create_app
from permgate.observability.metrics import RecordingMetrics

#: The credential the shared ``client`` fixture presents. Not a secret and not
#: pretending to be one: it exists so that "authenticated" is the state every
#: test starts from, and so an accidental change to that state fails loudly.
TEST_TOKEN = "bearer-token-for-the-test-suite"


def build_settings(tmp_path, **overrides) -> Settings:
    """A ``Settings`` for one test, with identity on and a way in.

    Two things here are not incidental. ``auth_bootstrap_token`` means the
    service will start: with ``auth_required`` on and no client, ``create_app``
    refuses to come up, which is the intended production behaviour and an
    unhelpful one in a test that is about request-size limits.
    ``auth_bootstrap_roots`` scopes that client to the test's own ``tmp_path``,
    so an authorisation check that starts working is visible as a failure rather
    than absorbed by an over-broad allowlist.
    """
    values: dict = {
        "_env_file": None,
        "database_url": f"sqlite+pysqlite:///{(tmp_path / 'permgate-test.db').as_posix()}",
        "log_json": False,
        "log_level": "WARNING",
        "grant_cache_enabled": True,
        "grant_cache_ttl_seconds": 15.0,
        "grant_cache_max_entries": 128,
        "auth_bootstrap_token": TEST_TOKEN,
        "auth_bootstrap_roots": [str(tmp_path)],
    }
    values.update(overrides)
    return Settings(**values)


def authorised(client: TestClient) -> TestClient:
    """Make a client carry the test credential. Used by the few tests that build
    their own app instead of taking the shared fixture."""
    client.headers["Authorization"] = f"Bearer {TEST_TOKEN}"
    return client


@pytest.fixture
def settings(tmp_path) -> Settings:
    return build_settings(tmp_path)


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
    #
    # The header is set once, here, rather than in the eight test modules that
    # make requests. That is the point: authentication is a cross-cutting
    # concern, and a concern that every call site has to remember is a concern
    # that one call site forgets.
    with TestClient(app) as test_client:
        test_client.headers["Authorization"] = f"Bearer {TEST_TOKEN}"
        yield test_client


@pytest.fixture
def project(tmp_path):
    """A real directory with a project marker, so project-root discovery is
    exercised rather than bypassed."""
    root = tmp_path / "workspace"
    root.mkdir()
    (root / ".git").mkdir()
    return root
