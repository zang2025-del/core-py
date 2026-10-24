"""Authentication and authorisation: two questions, two answers.

The rest of the suite asks "does the policy decide correctly". This file asks
the question that has to be answered *before* it -- **who is calling, and which
workspaces may they name** -- and it is deliberately a separate file because
the failure it covers is a different kind of failure. A wrong verdict is a bug
in a rule; an unauthenticated caller is the bug that makes every other test
here describe a service nobody deployed.

Three things are worth knowing before reading:

**The two status codes are not interchangeable.** ``401`` means "I do not know
who you are" and ``403`` means "I know, and you may not name that workspace".
Collapsing them hides which of the two problems is in front of you, and they
have entirely different fixes.

**A refused workspace is refused by directory, not by string.** ``/srv/app-2``
starts with ``/srv/app``, so a string comparison would hand a client scoped to
one repository its neighbour's standing grants. ``TestPathContainment`` pins
that down at the function, and ``TestAuthorisation`` pins it down over HTTP.

**Identity comes from the credential.** ``actor`` still exists in the request
body so that older clients are not broken by a 422, but it no longer decides
anything: an audit trail that records the caller's own claim about who it is
answers no question an auditor would ask.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from tests.conftest import database_url_for

from permgate.api.deps import build_container, create_schema
from permgate.api.security import token_digest
from permgate.config import Settings
from permgate.main import create_app
from permgate.observability.metrics import RecordingMetrics
from permgate.storage.database import create_db_engine, create_session_factory, session_scope
from permgate.storage.models import Client
from permgate.storage.repositories import ClientRepository

TOKEN = "token-for-the-tests"
OTHER_TOKEN = "token-for-the-other-tenant"
VOUCHED = "ls -la"


# --------------------------------------------------------------------- fixtures


class Workspaces:
    """Two sibling workspaces, so "allowed" and "not allowed" are both real
    directories on disk. A 403 that fires against a path which does not exist
    proves less: it cannot distinguish "not on your list" from "not there".
    """

    __slots__ = ("allowed", "outside")

    def __init__(self, allowed, outside) -> None:
        self.allowed = allowed
        self.outside = outside


@pytest.fixture
def workspaces(tmp_path) -> Workspaces:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / ".git").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / ".git").mkdir()
    return Workspaces(allowed=allowed, outside=outside)


def _settings(tmp_path, **overrides) -> Settings:
    """No bootstrap token: the clients are provisioned explicitly below.

    Relying on the bootstrap path here would mean every test exercised the one
    way of making a client that production code has, and none of the decisions
    it can get wrong.
    """
    values: dict = {
        "_env_file": None,
        "database_url": database_url_for(tmp_path),
        "create_schema_on_startup": True,
        "log_level": "CRITICAL",
        "log_json": False,
    }
    values.update(overrides)
    return Settings(**values)


def _provision(settings: Settings, clients: list[tuple[str, str, list[str]]]) -> None:
    """Create the clients before the app starts, the way an operator would."""
    container = build_container(settings)
    try:
        create_schema(container.engine)
        with session_scope(container.session_factory) as session:
            repo = ClientRepository(session)
            for name, token, roots in clients:
                repo.upsert(name=name, token_hash=token_digest(token), roots=roots)
    finally:
        container.close()


def _app(settings: Settings, clients: list[tuple[str, str, list[str]]]):
    _provision(settings, clients)
    return create_app(settings, metrics=RecordingMetrics())


def _decide(client: TestClient, project_root, *, token: str | None = None, headers=None):
    request_headers = dict(headers or {})
    if token is not None:
        request_headers["Authorization"] = f"Bearer {token}"
    return client.post(
        "/v1/decisions",
        headers=request_headers,
        json={
            "project_root": str(project_root),
            "tool": "bash",
            "arguments": {"command": VOUCHED},
        },
    )


# ------------------------------------------------------------------ authentication


class TestAuthentication:
    def test_a_request_without_a_token_is_refused(self, tmp_path, workspaces):
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        with TestClient(app) as client:
            response = _decide(client, workspaces.allowed)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "authentication_required"

    def test_the_refusal_offers_the_scheme_it_wants(self, tmp_path, workspaces):
        """A 401 without ``WWW-Authenticate`` is an error; with it, it is an
        instruction. Clients and proxies both read it."""
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        with TestClient(app) as client:
            response = _decide(client, workspaces.allowed)
        assert response.headers["www-authenticate"] == "Bearer"

    def test_an_unrecognised_token_is_refused(self, tmp_path, workspaces):
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        with TestClient(app) as client:
            response = _decide(client, workspaces.allowed, token="not-the-token")
        assert response.status_code == 401

    def test_two_different_wrong_tokens_are_indistinguishable(self, tmp_path, workspaces):
        """The response must not say "no such token", or a caller can search the
        token space by watching which guesses are *differently* wrong.

        Not sending one at all is a different matter and is allowed to read
        differently: the caller already knows what it sent, so "a token is
        required" tells it nothing it did not have.
        """
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        with TestClient(app) as client:
            first = _decide(client, workspaces.allowed, token="guess-one").json()["error"]
            second = _decide(client, workspaces.allowed, token="guess-two").json()["error"]
        assert first["code"] == second["code"]
        assert first["message"] == second["message"]
        assert "guess" not in first["message"]

    def test_a_revoked_token_stops_working_immediately(self, tmp_path, workspaces):
        """No credential cache, no TTL. A token that has been turned off has to
        be off on the next request, not fifteen seconds later."""
        settings = _settings(tmp_path)
        app = _app(
            settings,
            [
                ("ci", TOKEN, [str(workspaces.allowed)]),
                ("other", OTHER_TOKEN, [str(workspaces.allowed)]),
            ],
        )
        engine = create_db_engine(settings)
        try:
            with TestClient(app) as client:
                assert _decide(client, workspaces.allowed, token=TOKEN).status_code == 200

                with create_session_factory(engine)() as session:
                    assert ClientRepository(session).revoke("ci") is True
                    session.commit()

                assert _decide(client, workspaces.allowed, token=TOKEN).status_code == 401
                # The peer client is untouched -- revoking one is not an outage.
                assert _decide(client, workspaces.allowed, token=OTHER_TOKEN).status_code == 200
        finally:
            engine.dispose()

    def test_the_probes_need_no_credentials(self, tmp_path, workspaces):
        """A probe cannot present a bearer token, and a liveness check that
        fails when the database is unreachable would restart a healthy process."""
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        with TestClient(app) as client:
            assert client.get("/healthz").status_code == 200
            assert client.get("/readyz").status_code == 200

    def test_a_malformed_authorization_header_is_a_401_not_a_422(self, tmp_path, workspaces):
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        with TestClient(app) as client:
            for header in ("Bearer", "Bearer ", "Basic dXNlcjpwYXNz", TOKEN):
                response = _decide(client, workspaces.allowed, headers={"Authorization": header})
                assert response.status_code == 401, header


# ------------------------------------------------------------------ authorisation


class TestAuthorisation:
    def test_a_workspace_on_the_list_is_served(self, tmp_path, workspaces):
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        with TestClient(app) as client:
            response = _decide(client, workspaces.allowed, token=TOKEN)
        assert response.status_code == 200

    def test_a_child_of_an_allowed_workspace_is_served(self, tmp_path, workspaces):
        """A client allowed the repository is allowed what is inside it --
        otherwise every ``cd src/`` would be a 403."""
        nested = workspaces.allowed / "src" / "deep"
        nested.mkdir(parents=True)
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        with TestClient(app) as client:
            response = _decide(client, nested, token=TOKEN)
        assert response.status_code == 200

    def test_a_workspace_off_the_list_is_a_403(self, tmp_path, workspaces):
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        with TestClient(app) as client:
            response = _decide(client, workspaces.outside, token=TOKEN)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "root_not_allowed"

    def test_a_sibling_sharing_a_string_prefix_is_not_covered(self, tmp_path, workspaces):
        """``allowed-2`` starts with ``allowed``. Path containment is a question
        about directories, so the answer has to be 403 -- a string prefix would
        let a client scoped to one repository reach the one beside it.
        """
        sibling = workspaces.allowed.parent / (workspaces.allowed.name + "-2")
        sibling.mkdir()
        (sibling / ".git").mkdir()
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        with TestClient(app) as client:
            response = _decide(client, sibling, token=TOKEN)
        assert response.status_code == 403

    def test_the_refusal_names_the_workspace_that_was_checked(self, tmp_path, workspaces):
        """The error has to speak about the resolved form. Showing the raw input
        would leave the operator comparing two spellings of the same path."""
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        with TestClient(app) as client:
            response = _decide(client, workspaces.outside, token=TOKEN)
        assert response.json()["error"]["details"]["project_root"] == (
            workspaces.outside.resolve().as_posix()
        )

    def test_every_workspace_endpoint_checks_the_same_list(self, tmp_path, workspaces):
        """One endpoint with its own idea of the allowlist is worse than none:
        the leak would be on whichever one was forgotten."""
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        headers = {"Authorization": f"Bearer {TOKEN}"}
        with TestClient(app) as client:
            assert (
                client.get(
                    "/v1/grants", headers=headers, params={"project_root": str(workspaces.outside)}
                ).status_code
                == 403
            )
            assert (
                client.post(
                    "/v1/grants",
                    headers=headers,
                    json={"project_root": str(workspaces.outside), "tool": "bash"},
                ).status_code
                == 403
            )
            # A write that must not have happened is only proven by reading back.
            assert (
                client.get(
                    "/v1/grants", headers=headers, params={"project_root": str(workspaces.allowed)}
                ).json()["grants"]
                == []
            )
            assert (
                client.delete(
                    "/v1/grants/bash",
                    headers=headers,
                    params={"project_root": str(workspaces.outside)},
                ).status_code
                == 403
            )
            assert (
                client.delete(
                    "/v1/grants", headers=headers, params={"project_root": str(workspaces.outside)}
                ).status_code
                == 403
            )
            assert (
                client.get(
                    "/v1/audit", headers=headers, params={"project_root": str(workspaces.outside)}
                ).status_code
                == 403
            )

    def test_a_client_with_no_workspaces_can_name_none(self, tmp_path, workspaces):
        app = _app(_settings(tmp_path), [("ci", TOKEN, [])])
        with TestClient(app) as client:
            assert _decide(client, workspaces.allowed, token=TOKEN).status_code == 403
            # Authenticated, so the audit read is allowed -- and empty.
            audit = client.get("/v1/audit", headers={"Authorization": f"Bearer {TOKEN}"})
        assert audit.status_code == 200
        assert audit.json()["entries"] == []


# ----------------------------------------------------------------------- identity


class TestIdentity:
    def test_the_actor_recorded_is_the_authenticated_client(self, tmp_path, workspaces):
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        headers = {"Authorization": f"Bearer {TOKEN}"}
        with TestClient(app) as client:
            client.post(
                "/v1/decisions",
                headers=headers,
                json={
                    "project_root": str(workspaces.allowed),
                    "tool": "bash",
                    "arguments": {"command": VOUCHED},
                    # A caller that could name itself could name someone else.
                    "actor": "somebody-else-entirely",
                },
            )
            entries = client.get(
                "/v1/audit", headers=headers, params={"project_root": str(workspaces.allowed)}
            ).json()["entries"]
        assert [entry["actor"] for entry in entries] == ["ci"]

    def test_a_grant_records_the_authenticated_client(self, tmp_path, workspaces):
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        headers = {"Authorization": f"Bearer {TOKEN}"}
        with TestClient(app) as client:
            created = client.post(
                "/v1/grants",
                headers=headers,
                json={
                    "project_root": str(workspaces.allowed),
                    "tool": "bash",
                    "actor": "somebody-else",
                },
            )
        assert created.json()["granted_by"] == "ci"

    def test_answering_a_decision_outside_your_workspaces_is_a_404(self, tmp_path, workspaces):
        """Not a 403. The id is a UUID the caller could not have guessed, so a
        distinct status would confirm that a guessed id exists."""
        settings = _settings(tmp_path)
        app = _app(
            settings,
            [
                ("ci", TOKEN, [str(workspaces.allowed)]),
                ("other", OTHER_TOKEN, [str(workspaces.outside)]),
            ],
        )
        with TestClient(app) as client:
            theirs = _decide(client, workspaces.outside, token=OTHER_TOKEN).json()["decision_id"]
            response = client.post(
                f"/v1/decisions/{theirs}/answer",
                headers={"Authorization": f"Bearer {TOKEN}"},
                json={"answer": "once"},
            )
        assert response.status_code == 404

    def test_answering_your_own_decision_works(self, tmp_path, workspaces):
        """The 404 above has to be about ownership, not about the endpoint."""
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        headers = {"Authorization": f"Bearer {TOKEN}"}
        with TestClient(app) as client:
            mine = _decide(client, workspaces.allowed, token=TOKEN).json()["decision_id"]
            response = client.post(
                f"/v1/decisions/{mine}/answer", headers=headers, json={"answer": "once"}
            )
        assert response.status_code == 200
        assert response.json()["answer"] == "once"


# -------------------------------------------------------------------- audit scoping


class TestAuditScoping:
    def test_omitting_project_root_narrows_instead_of_widening(self, tmp_path, workspaces):
        """The unparameterised read is the one an attacker makes, so it has to be
        the more restricted one. A default meaning "all projects" would undo the
        per-client allowlist in a single request."""
        settings = _settings(tmp_path)
        app = _app(
            settings,
            [
                ("mine", TOKEN, [str(workspaces.allowed)]),
                ("theirs", OTHER_TOKEN, [str(workspaces.outside)]),
            ],
        )
        with TestClient(app) as client:
            assert _decide(client, workspaces.allowed, token=TOKEN).status_code == 200
            assert _decide(client, workspaces.outside, token=OTHER_TOKEN).status_code == 200

            mine = client.get("/v1/audit", headers={"Authorization": f"Bearer {TOKEN}"}).json()
            theirs = client.get(
                "/v1/audit", headers={"Authorization": f"Bearer {OTHER_TOKEN}"}
            ).json()

        assert len(mine["entries"]) == 1
        assert len(theirs["entries"]) == 1
        assert mine["entries"][0]["decision_id"] != theirs["entries"][0]["decision_id"]

    def test_the_filter_survives_a_subdirectory(self, tmp_path, workspaces):
        """A root recorded as ``allowed/src`` still belongs to the client that
        may name ``allowed``."""
        nested = workspaces.allowed / "src"
        nested.mkdir()
        app = _app(_settings(tmp_path), [("ci", TOKEN, [str(workspaces.allowed)])])
        with TestClient(app) as client:
            assert _decide(client, nested, token=TOKEN).status_code == 200
            entries = client.get("/v1/audit", headers={"Authorization": f"Bearer {TOKEN}"}).json()[
                "entries"
            ]
        assert len(entries) == 1


# --------------------------------------------------------------------- fail-closed


class TestFailClosed:
    def test_a_deployment_with_no_client_cannot_start(self, tmp_path):
        """Coming up with identity on and nobody able to authenticate is a
        service that answers every request until someone notices -- and
        noticing is not a control. A process that cannot be reached is a deploy
        that fails loudly."""
        settings = _settings(tmp_path)
        create_schema(build_container(settings).engine)
        with (
            pytest.raises(RuntimeError, match="no client exists"),
            TestClient(create_app(settings, metrics=RecordingMetrics())),
        ):
            pass

    def test_revoking_the_last_client_also_prevents_startup(self, tmp_path, workspaces):
        settings = _settings(tmp_path)
        _provision(settings, [("ci", TOKEN, [str(workspaces.allowed)])])
        engine = create_db_engine(settings)
        try:
            with create_session_factory(engine)() as session:
                ClientRepository(session).revoke("ci")
                session.commit()
        finally:
            engine.dispose()
        with (
            pytest.raises(RuntimeError, match="no client exists"),
            TestClient(create_app(settings, metrics=RecordingMetrics())),
        ):
            pass

    def test_a_bootstrap_token_creates_the_first_client(self, tmp_path, workspaces):
        settings = _settings(
            tmp_path,
            auth_bootstrap_token="first-way-in",
            auth_bootstrap_roots=[str(workspaces.allowed)],
        )
        with TestClient(create_app(settings, metrics=RecordingMetrics())) as client:
            assert _decide(client, workspaces.allowed, token="first-way-in").status_code == 200

    def test_turning_identity_off_names_the_caller_anonymous(self, tmp_path, workspaces):
        """The escape hatch is real and has to be honest about itself: rows say
        ``anonymous`` rather than pretending somebody acted."""
        settings = _settings(tmp_path, auth_required=False)
        app = create_app(settings, metrics=RecordingMetrics())
        with TestClient(app) as client:
            response = _decide(client, workspaces.outside)
            assert response.status_code == 200
            entries = client.get(
                "/v1/audit", params={"project_root": str(workspaces.outside)}
            ).json()["entries"]
        assert [entry["actor"] for entry in entries] == ["anonymous"]


# -------------------------------------------------------------------------- tokens


class TestStoredTokens:
    def test_only_the_digest_is_stored(self, tmp_path, workspaces):
        """A database is backed up, replicated and restored into staging. A
        table of live credentials turns every one of those into a leak."""
        settings = _settings(tmp_path)
        _provision(settings, [("ci", TOKEN, [str(workspaces.allowed)])])
        engine = create_db_engine(settings)
        try:
            with create_session_factory(engine)() as session:
                stored = session.query(Client).one()
                assert stored.token_hash == token_digest(TOKEN)
                assert TOKEN not in stored.token_hash
                assert len(stored.token_hash) == 64
        finally:
            engine.dispose()

    def test_the_digest_is_not_reversible_by_reading_the_row(self, tmp_path, workspaces):
        """Stated as its own check because "we store a hash" is the kind of
        claim that gets copied into a README and stops being true."""
        settings = _settings(tmp_path)
        _provision(settings, [("ci", TOKEN, [str(workspaces.allowed)])])
        engine = create_db_engine(settings)
        try:
            with create_session_factory(engine)() as session:
                columns = {column.name for column in Client.__table__.columns}
                row = {
                    column.name: getattr(session.query(Client).one(), column.name)
                    for column in Client.__table__.columns
                }
        finally:
            engine.dispose()
        assert "token" not in columns
        assert TOKEN not in str(row.values())
