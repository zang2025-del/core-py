"""Request-scoped middleware.

The body-size limit is the one piece of the request path that runs *before*
anything else can reject a request, which means it is also the piece whose
failures are hardest to notice: an oversized request that gets parsed anyway
does not error, it just costs memory.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from tests.conftest import authorised, build_settings

from permgate.api.deps import build_container, create_schema
from permgate.config import Settings
from permgate.main import create_app
from permgate.observability.metrics import RecordingMetrics


def _exact_body(tmp_path, size: int) -> bytes:
    """A valid decision request padded to exactly ``size`` bytes.

    Padding the command rather than the JSON keeps the body parseable, so a
    413 from the size check is distinguishable from a 422 from the parser.
    """
    import json

    payload: dict = {
        "project_root": str(tmp_path),
        "tool": "bash",
        "arguments": {"command": "ls"},
    }
    pad = size - len(json.dumps(payload).encode())
    payload["arguments"]["command"] = "ls" + " " * pad
    body = json.dumps(payload).encode()
    assert len(body) == size, "the pad calculation drifted from the encoder"
    return body


def _client(tmp_path, **overrides) -> TestClient:
    """An app that will start and whose requests are authenticated.

    Both halves come from :func:`tests.conftest.build_settings`: identity is on,
    and a bootstrap client exists so the lifespan gets past the fail-closed
    check. Sidestepping that check here would mean these tests measured a
    service configuration that cannot be deployed.
    """
    settings = build_settings(
        tmp_path, database_url=f"sqlite+pysqlite:///{(tmp_path / 'mw.db').as_posix()}", **overrides
    )
    return authorised(TestClient(create_app(settings, metrics=RecordingMetrics())))


class TestBodySizeLimit:
    def test_an_oversized_body_is_refused_before_it_is_read(self, tmp_path):
        with _client(tmp_path, max_request_bytes=2048) as client:
            response = client.post(
                "/v1/decisions",
                json={
                    "project_root": str(tmp_path),
                    "tool": "bash",
                    "arguments": {"command": "x" * 8192},
                },
            )
        assert response.status_code == 413
        assert response.json()["error"]["code"] == "payload_too_large"

    def test_a_body_within_the_limit_is_served(self, tmp_path):
        with _client(tmp_path, max_request_bytes=65536) as client:
            response = client.post(
                "/v1/decisions",
                json={
                    "project_root": str(tmp_path),
                    "tool": "bash",
                    "arguments": {"command": "ls -la"},
                },
            )
        assert response.status_code == 200

    def test_exactly_at_the_limit_is_allowed(self, tmp_path):
        """`>` not `>=`. An off-by-one here rejects the request that happens to
        land on the boundary, which is the one somebody will eventually send.

        The body is padded up to the limit rather than the limit being lowered
        to meet it: the settings validator refuses anything under a kilobyte,
        because a ceiling an ordinary request can hit is a misconfiguration
        rather than a configuration.
        """
        body = _exact_body(tmp_path, 1024)
        with _client(tmp_path, max_request_bytes=1024) as client:
            response = client.post(
                "/v1/decisions", content=body, headers={"content-type": "application/json"}
            )
        assert response.status_code == 200, response.text

    def test_one_byte_over_the_limit_is_refused(self, tmp_path):
        body = _exact_body(tmp_path, 1025)
        with _client(tmp_path, max_request_bytes=1024) as client:
            response = client.post(
                "/v1/decisions", content=body, headers={"content-type": "application/json"}
            )
        assert response.status_code == 413


class TestRequestContext:
    def test_a_missing_request_id_is_generated(self, tmp_path):
        with _client(tmp_path) as client:
            response = client.get("/healthz")
        assert response.headers.get("X-Request-ID")

    def test_a_supplied_request_id_is_echoed(self, tmp_path):
        with _client(tmp_path) as client:
            response = client.get("/healthz", headers={"X-Request-ID": "abc-123"})
        assert response.headers["X-Request-ID"] == "abc-123"

    def test_the_header_is_configurable(self, tmp_path):
        with _client(tmp_path, request_id_header="X-Trace") as client:
            response = client.get("/healthz", headers={"X-Trace": "trace-9"})
        assert response.headers["X-Trace"] == "trace-9"

    def test_a_refused_request_still_gets_an_id(self, tmp_path):
        """The context middleware is outermost precisely so that a request
        rejected further in still leaves a trace. A 413 with no id is the gap
        that only shows up when someone is flooding the service."""
        with _client(tmp_path, max_request_bytes=1024) as client:
            response = client.post(
                "/v1/decisions",
                json={
                    "project_root": str(tmp_path),
                    "tool": "bash",
                    "arguments": {"command": "y" * 4096},
                },
            )
        assert response.status_code == 413
        assert response.headers.get("X-Request-ID")


class TestContainerLifecycle:
    def test_the_container_is_built_once_at_startup(self, tmp_path):
        """A service that builds its own engine per request gets a connection
        pool per request, and the failure that produces under load looks like a
        database problem and is not one."""
        app = create_app(build_settings(tmp_path), metrics=RecordingMetrics())
        with TestClient(app):
            first = id(app.state.container)
            second = id(app.state.container)
        assert first == second

    def test_the_engine_is_disposed_on_shutdown(self, tmp_path, monkeypatch):
        """`dispose()` does not make an engine unusable -- SQLAlchemy will open
        a fresh connection on the next query -- so "a query still works" proves
        nothing. The call itself is what has to be observed."""
        app = create_app(build_settings(tmp_path), metrics=RecordingMetrics())

        engine = app.state.container.engine
        disposed: list[bool] = []
        original = engine.dispose

        def spy(*args, **kwargs):
            disposed.append(True)
            return original(*args, **kwargs)

        monkeypatch.setattr(engine, "dispose", spy)
        with TestClient(app):
            assert disposed == [], "disposing at startup would close the pool in use"
        assert disposed == [True]

    def test_importing_main_does_not_open_a_database(self, tmp_path, monkeypatch):
        """`import permgate.main` builds nothing. A module whose import opens a
        connection makes "the import failed because the database was down" a
        confusing failure for something that is not a query."""
        import importlib
        import sys

        monkeypatch.setenv(
            "PERMGATE_DATABASE_URL", f"sqlite+pysqlite:///{(tmp_path / 'never.db').as_posix()}"
        )
        sys.modules.pop("permgate.main", None)
        module = importlib.import_module("permgate.main")
        assert not (tmp_path / "never.db").exists()
        assert module.__getattr__("app") is not None  # still reachable on demand
        assert not (tmp_path / "never.db").exists(), "building the app must not connect yet"

    def test_an_unknown_attribute_still_raises(self):
        import pytest

        from permgate import main

        with pytest.raises(AttributeError):
            _ = main.definitely_not_a_thing


class TestSchemaBootstrap:
    def test_the_schema_is_created_for_sqlite_on_startup(self, tmp_path):
        with _client(tmp_path) as client:
            assert client.get("/readyz").json()["status"] == "ready"

    def test_build_container_does_not_touch_the_schema(self, tmp_path):
        """`build_container` composes; `create_schema` creates. Mixing them
        would mean a read-only replica or a migration job could not build the
        object graph without also trying to write DDL."""
        settings = Settings(
            _env_file=None,
            database_url=f"sqlite+pysqlite:///{(tmp_path / 'compose.db').as_posix()}",
        )
        container = build_container(settings, metrics=RecordingMetrics())
        try:
            from sqlalchemy import inspect

            assert inspect(container.engine).get_table_names() == []
            create_schema(container.engine)
            assert "projects" in inspect(container.engine).get_table_names()
        finally:
            container.close()
