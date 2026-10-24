"""The suite knows which database it is testing.

Setting ``TEST_DATABASE_URL`` has to change what the suite measures, and that is
not a property the other test files can notice: every one of them would pass just
as happily against SQLite if the switch were silently ignored. The failure mode
is specific and nasty -- a CI job named "postgres" that runs the whole suite,
reports green, and never opens a connection to PostgreSQL -- so it gets its own
file and its own assertions.

Two things are checked here. That the dialect the engine actually speaks is the
one the environment asked for, and that ``build_settings`` -- the single place
every test gets its database from -- routes to the same backend. The second is
what keeps the first from being true only for this file.
"""

from __future__ import annotations

from sqlalchemy import text
from tests.conftest import TEST_DATABASE_URL, build_settings, database_url_for

from permgate.storage.database import create_db_engine


def _dialect(settings) -> str:
    engine = create_db_engine(settings)
    try:
        with engine.connect() as connection:
            return connection.dialect.name
    finally:
        engine.dispose()


class TestTheConfiguredBackendIsTheTestedBackend:
    def test_the_engine_speaks_the_configured_dialect(self, settings):
        """``TEST_DATABASE_URL`` selects the backend; nothing else does."""
        expected = "postgresql" if TEST_DATABASE_URL else "sqlite"
        assert _dialect(settings) == expected

    def test_the_shared_settings_builder_routes_to_that_backend(self, tmp_path):
        """Every test's database comes from ``build_settings``.

        If the URL that helper builds ignored ``TEST_DATABASE_URL``, the tests in
        this file would still pass while the other 700 measured SQLite -- the
        assertion above would be about a backend nothing else used.
        """
        settings = build_settings(tmp_path)
        expected = "postgresql" if TEST_DATABASE_URL else "sqlite"
        assert _dialect(settings) == expected

    def test_a_postgres_run_does_not_come_up_on_sqlite(self, tmp_path):
        """The negative half, stated so it cannot be satisfied by accident."""
        expected = "postgresql" if TEST_DATABASE_URL else "sqlite"
        assert _dialect(build_settings(tmp_path)) != (
            "sqlite" if expected == "postgresql" else "postgresql"
        )

    def test_on_postgres_the_connection_is_a_real_server(self, settings):
        """``sqlite`` is a file; here it is a server, which is the difference
        between a database nobody else can see and the one a deployment runs.

        The version is asserted to be *recent*, not to be a specific release: a
        guard test that fails because someone pointed ``TEST_DATABASE_URL`` at
        PostgreSQL 17 would be reporting the wrong problem.
        """
        if not TEST_DATABASE_URL:
            return
        engine = create_db_engine(settings)
        try:
            with engine.connect() as connection:
                version = connection.execute(text("SHOW server_version")).scalar()
                database = connection.execute(text("SELECT current_database()")).scalar()
                info = connection.dialect.server_version_info
        finally:
            engine.dispose()
        assert version, "a server that will not name its version is not one"
        assert info is not None and info[0] >= 12, f"unexpected server: {version}"
        assert database


class TestTheSwitchItself:
    def test_the_url_helper_agrees_with_the_environment(self, tmp_path):
        url = database_url_for(tmp_path)
        if TEST_DATABASE_URL:
            assert url.startswith(TEST_DATABASE_URL), "the test database URL was not honoured"
        else:
            assert url.startswith("sqlite+pysqlite:///")

    def test_two_tests_do_not_share_a_database(self, tmp_path):
        """Per-test isolation, on whichever backend.

        On SQLite a throwaway file does this. On PostgreSQL the equivalent is a
        schema per ``tmp_path``, and the thing that makes it work is a
        connection-level ``search_path`` that the pool applies on checkout --
        not a statement issued per session, which would arrive too late for the
        first query in a transaction.
        """
        from tests.conftest import _schema_name

        first = build_settings(tmp_path)
        second = build_settings(tmp_path / "other")
        assert first.database_url != second.database_url, "two tests would share a database"
        if TEST_DATABASE_URL:
            assert _schema_name(tmp_path) != _schema_name(tmp_path / "other")
