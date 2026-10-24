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

**The suite runs on either database.** Unset ``TEST_DATABASE_URL`` and every
test gets its own SQLite file, which is the default because it needs no server.
Set it to a PostgreSQL URL and every test gets its own *schema* on that server
instead. This is the difference between "PostgreSQL is a supported code path"
and "PostgreSQL is a tested one", and for a long time this project claimed the
second while only having the first -- the claim lived in a docstring and no test
had ever connected to a server database.
"""

from __future__ import annotations

import hashlib
import os
from functools import lru_cache

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool

from permgate.api.deps import Container, build_container, create_schema
from permgate.config import Settings
from permgate.main import create_app
from permgate.observability.metrics import RecordingMetrics

#: The credential the shared ``client`` fixture presents. Not a secret and not
#: pretending to be one: it exists so that "authenticated" is the state every
#: test starts from, and so an accidental change to that state fails loudly.
TEST_TOKEN = "bearer-token-for-the-test-suite"

#: ``TEST_DATABASE_URL`` selects the database the whole suite runs on. The
#: prefixed spelling is accepted too, so it can sit beside the other knobs in a
#: ``.env``-style file without looking like it belongs to a different scheme.
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL") or os.environ.get(
    "PERMGATE_TEST_DATABASE_URL"
)

#: Prefix for the per-test schemas. Also the handle the session finaliser uses to
#: find them again, so it has to be distinctive enough not to match a schema
#: somebody else created on a shared server.
_SCHEMA_PREFIX = "permgate_test_"


@lru_cache(maxsize=1)
def _admin_engine() -> Engine:
    """An engine on the server itself, used only to create and drop schemas.

    ``NullPool`` matters here: this engine is touched once or twice per test and
    keeping connections open would count against the server's connection limit
    for the whole run, which on a shared server is how a test suite becomes
    somebody else's outage.
    """
    assert TEST_DATABASE_URL is not None
    return create_engine(TEST_DATABASE_URL, poolclass=NullPool, future=True)


def _schema_name(tmp_path) -> str:
    """A stable, legal schema name per ``tmp_path``.

    Stable because a single test may build settings more than once and they
    should land in the same database, the way they would share one SQLite file.
    Hashed because a ``tmp_path`` contains separators, a drive letter and a user
    name, none of which belong in an identifier, and the 63-byte limit is easy
    to exceed.
    """
    digest = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:12]
    return f"{_SCHEMA_PREFIX}{digest}"


def _postgres_url_for(tmp_path) -> str:
    assert TEST_DATABASE_URL is not None
    schema = _schema_name(tmp_path)
    with _admin_engine().begin() as connection:
        connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
    separator = "&" if "?" in TEST_DATABASE_URL else "?"
    # ``search_path`` is set per connection through the driver's startup
    # options rather than with a ``SET`` per session: the pool hands out
    # connections without calling back into application code, so a statement
    # issued after checkout would arrive too late for the first query.
    return f"{TEST_DATABASE_URL}{separator}options=-csearch_path%3D{schema}"


def database_url_for(tmp_path) -> str:
    """Where this test's database lives, on whichever backend is configured."""
    if TEST_DATABASE_URL is None:
        return f"sqlite+pysqlite:///{(tmp_path / 'permgate-test.db').as_posix()}"
    return _postgres_url_for(tmp_path)


@pytest.fixture(scope="session", autouse=True)
def _drop_test_schemas():
    """Leave the server as we found it.

    A run that creates a schema per test and never drops them degrades the next
    run -- and on a shared server it is somebody else's problem. The finaliser
    is deliberately tied to the session, not the test, so a ``--pdb`` session
    that aborts leaves its schemas inspectable.

    **One transaction per schema**, which is not the obvious way to write this.
    Dropping every schema in a single transaction needs a lock on every table,
    index, sequence and trigger being dropped, all held until commit; past a few
    hundred schemas that exceeds ``max_locks_per_transaction``, the statement
    fails with "out of shared memory" (HINT: increase max_locks_per_transaction),
    and the *whole* transaction rolls back -- so the litter survives, and the
    failure lands as a teardown error on an otherwise green run. That is this
    project's own history, not a hypothetical: the run that found it had about a
    hundred and eighty accumulated schemas on a stock server.

    Committing per schema keeps the lock demand flat and makes the cleanup
    incremental, so one schema that refuses to drop costs the others nothing.
    The names are materialised with ``.all()`` before any is dropped, because
    dropping schemas while a cursor over ``pg_namespace`` is still open invites
    trouble on some server versions.
    """
    yield
    if TEST_DATABASE_URL is None:
        return
    engine = _admin_engine()
    try:
        with engine.connect() as connection:
            names = (
                connection.execute(
                    text("SELECT nspname FROM pg_namespace WHERE nspname LIKE :pattern"),
                    {"pattern": f"{_SCHEMA_PREFIX}%"},
                )
                .scalars()
                .all()
            )
        for name in names:
            with engine.begin() as connection:
                connection.execute(text(f'DROP SCHEMA IF EXISTS "{name}" CASCADE'))
    finally:
        engine.dispose()


def build_settings(tmp_path, **overrides) -> Settings:
    """A ``Settings`` for one test, with identity on and a way in.

    Three things here are not incidental. ``auth_bootstrap_token`` means the
    service will start: with ``auth_required`` on and no client, ``create_app``
    refuses to come up, which is the intended production behaviour and an
    unhelpful one in a test that is about request-size limits.
    ``auth_bootstrap_roots`` scopes that client to the test's own ``tmp_path``,
    so an authorisation check that starts working is visible as a failure rather
    than absorbed by an over-broad allowlist. ``create_schema_on_startup`` is
    ``True`` because a server database has no ``create_all`` by default -- the
    schema there belongs to a migration, and a test that had to remember to run
    one would be a test that silently measured an empty database.
    """
    values: dict = {
        "_env_file": None,
        "database_url": database_url_for(tmp_path),
        "create_schema_on_startup": True,
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
