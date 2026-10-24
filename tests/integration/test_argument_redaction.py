"""Arguments that reach for a credential are not written down.

The audit row is read by more people than the person who caused it: an operator
debugging an incident, a backup, a staging restore, an export somebody forgot
about. Arguments are the one column that can hold a credential, and a token in a
table outlives the reason it was needed.

So the row keeps the digest -- which still proves *which* call it was, and is
what the digest was already for -- and drops the arguments.

The two ways to end up with no arguments are different facts and the row
distinguishes them: ``arguments_redacted`` is true when this particular call was
withheld, and false when the operator turned raw storage off for the whole
deployment. A reader deciding whether to go looking for the arguments needs to
know which.

``redaction.py`` states what this deliberately does not catch -- inline secrets
that never look like a path, and files whose contents are secret when the command
does not name them. That boundary is tested here too, so it stays a documented
limit rather than an assumption someone makes about a column called "redacted".
"""

from __future__ import annotations

import pytest

from permgate.storage.redaction import arguments_are_sensitive
from permgate.storage.repositories import digest_arguments

VOUCHED = "ls -la"


class TestWhatCountsAsSensitive:
    @pytest.mark.parametrize(
        "command",
        [
            "cat .env",
            "cat ~/.ssh/id_rsa",
            "cat /home/me/.aws/credentials",
            "openssl rsa -in server.pem",
            "cp .netrc /tmp/",
            "less ~/.docker/config.json",
        ],
    )
    def test_credential_shaped_paths_are_recognised(self, command: str):
        assert arguments_are_sensitive({"command": command})

    @pytest.mark.parametrize(
        "command",
        [VOUCHED, "pytest -q", "git status", "cat README.md", "npm run build"],
    )
    def test_ordinary_commands_are_not(self, command: str):
        assert not arguments_are_sensitive({"command": command})

    def test_documentation_files_are_exempt(self):
        """``cat .env.example`` is how a project tells you what to set. Crying
        wolf on it would train people to ignore the flag."""
        assert not arguments_are_sensitive({"command": "cat .env.example"})

    def test_a_credential_nested_in_the_arguments_is_found(self):
        """Tool arguments nest, and a check that only looked at the top level
        would pass both of these."""
        assert arguments_are_sensitive({"env": {"TOKEN_FILE": "/home/me/.ssh/id_rsa"}})
        assert arguments_are_sensitive({"files": ["src/app.py", "server.pem"]})

    def test_a_hit_anywhere_wins(self):
        """Conservative in one direction only: a false positive costs a hidden
        column, a false negative costs a secret in a database."""
        assert arguments_are_sensitive({"command": VOUCHED, "note": "see .env"})


class TestTheRowRecordsWhyItIsEmpty:
    def _decide(self, client, project, arguments):
        return client.post(
            "/v1/decisions",
            json={"project_root": str(project), "tool": "bash", "arguments": arguments},
        )

    def _entry(self, client, project, decision_id):
        entries = client.get("/v1/audit", params={"project_root": str(project)}).json()["entries"]
        return next(entry for entry in entries if entry["decision_id"] == decision_id)

    def test_a_credential_shaped_call_is_not_stored(self, client, project):
        created = self._decide(client, project, {"command": "cat .env"})
        entry = self._entry(client, project, created.json()["decision_id"])

        assert entry["arguments"] is None
        assert entry["arguments_redacted"] is True
        assert entry["arguments_digest"], "the row must still identify the call"

    def test_an_ordinary_call_is_stored(self, client, project):
        created = self._decide(client, project, {"command": VOUCHED})
        entry = self._entry(client, project, created.json()["decision_id"])

        assert entry["arguments"] == {"command": VOUCHED}
        assert entry["arguments_redacted"] is False

    def test_the_digest_still_identifies_a_withheld_call(self, client, project):
        """The point of keeping the digest: a row whose arguments were withheld
        is not a row that has forgotten what it was about. Two different withheld
        calls must still be distinguishable."""
        first = self._decide(client, project, {"command": "cat .env"})
        second = self._decide(client, project, {"command": "cat ~/.ssh/id_rsa"})

        left = self._entry(client, project, first.json()["decision_id"])
        right = self._entry(client, project, second.json()["decision_id"])

        assert left["arguments"] is None and right["arguments"] is None
        assert left["arguments_digest"] != right["arguments_digest"]

    def test_storage_being_off_is_not_the_same_as_redaction(self, tmp_path, metrics):
        """Both rows have no arguments. Only one of them was withheld for being
        sensitive, and a reader has to be able to tell."""
        from fastapi.testclient import TestClient
        from tests.conftest import authorised, build_settings

        from permgate.main import create_app

        settings = build_settings(tmp_path, audit_store_arguments=False)
        with authorised(TestClient(create_app(settings, metrics=metrics))) as client:
            created = client.post(
                "/v1/decisions",
                json={
                    "project_root": str(tmp_path),
                    "tool": "bash",
                    "arguments": {"command": VOUCHED},
                },
            )
            entry = self._entry(client, tmp_path, created.json()["decision_id"])

        assert entry["arguments"] is None
        assert entry["arguments_redacted"] is False, (
            "storage was off for the deployment, which is not this call being withheld"
        )

    def test_the_digest_is_over_the_original_arguments_not_the_redacted_ones(
        self, session_factory, tmp_path
    ):
        """If the digest were taken after redaction it would hash ``None`` and
        every withheld call would share one fingerprint -- which would make the
        column prove nothing exactly when it matters most."""
        from permgate.storage.repositories import DecisionRepository, ProjectRepository

        arguments = {"command": "cat .env"}
        with session_factory() as session:
            project = ProjectRepository(session).get_or_create(str(tmp_path))
            row = DecisionRepository(session).record(
                decision_id="d-redacted",
                project_id=project.id,
                tool="bash",
                arguments=arguments,
                arguments_json='{"command": "cat .env"}',
                verdict="ask",
                rule="flagged",
                reason=None,
                scope=None,
                run_mode="interactive",
                latency_us=1,
                actor="tester",
                request_id=None,
            )
            session.commit()
            assert row.arguments is None
            assert row.arguments_redacted is True
            assert row.arguments_digest == digest_arguments(arguments)
