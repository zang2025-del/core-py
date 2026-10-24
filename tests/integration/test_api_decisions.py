"""End-to-end: the two-phase decision flow over HTTP.

A decision is a round trip, not a function call -- the agent asks, a human
answers, and the service has to remember the question in between. These tests
exercise the whole loop against a real database and a real (in-memory) cache.
"""

from __future__ import annotations

VOUCHED = "ls -la"
FLAGGED = "kubectl delete namespace production"


def _decide(client, project, command: str, **extra):
    body = {"project_root": str(project), "tool": "bash", "arguments": {"command": command}}
    body.update(extra)
    response = client.post("/v1/decisions", json=body)
    assert response.status_code == 200, response.text
    return response.json()


class TestDecisionEndpoint:
    def test_a_vouched_command_still_asks_the_first_time(self, client, project):
        """'Vouched for' means 'not flagged', not 'auto-allowed'.

        A first-time `ls` in an interactive session is asked about, and the rule
        says so explicitly -- `unrecognised`, not `risk_flagged`. Conflating the
        two would make the audit trail unable to distinguish "we did not know
        this command" from "we knew this command was dangerous".
        """
        body = _decide(client, project, VOUCHED)
        assert body["verdict"] == "ask"
        assert body["rule"] == "unrecognised"
        assert body["reason"] is None

    def test_a_flagged_command_asks_with_a_reason(self, client, project):
        body = _decide(client, project, FLAGGED)
        assert body["verdict"] == "ask"
        assert body["rule"] == "risk_flagged"
        assert body["reason"] and "kubectl" in body["reason"]
        assert body["scope"] == "kubectl delete"

    def test_every_decision_gets_an_id_and_a_latency(self, client, project):
        body = _decide(client, project, VOUCHED)
        assert body["decision_id"]
        assert body["latency_us"] >= 0

    def test_the_project_root_is_normalised(self, client, project):
        body = _decide(client, project, VOUCHED)
        assert body["project_root"] == project.resolve().as_posix()

    def test_a_subdirectory_resolves_to_the_same_project(self, client, project):
        """A run in ``proj/src/`` must share the grant made in ``proj/``."""
        nested = project / "src" / "deep"
        nested.mkdir(parents=True)
        first = _decide(client, project, VOUCHED)
        second = _decide(client, nested, VOUCHED)
        assert first["project_root"] == second["project_root"]

    def test_read_only_tools_are_allowed_without_a_prompt(self, client, project):
        response = client.post(
            "/v1/decisions",
            json={"project_root": str(project), "tool": "read_file", "arguments": {}},
        )
        assert response.status_code == 200
        assert response.json()["verdict"] == "allow"
        assert response.json()["rule"] == "read_only"

    def test_unknown_fields_are_rejected(self, client, project):
        response = client.post(
            "/v1/decisions",
            json={"project_root": str(project), "tool": "bash", "arguments": {}, "oops": 1},
        )
        assert response.status_code == 422

    def test_empty_project_root_is_rejected(self, client):
        response = client.post(
            "/v1/decisions", json={"project_root": "", "tool": "bash", "arguments": {}}
        )
        assert response.status_code == 422


class TestModePolicy:
    def test_a_client_supplied_mode_is_refused_by_default(self, client, project):
        """A client that can choose its own run mode can choose bypass, which
        would make the rest of the service decorative."""
        response = client.post(
            "/v1/decisions",
            json={
                "project_root": str(project),
                "tool": "bash",
                "arguments": {"command": VOUCHED},
                "mode": "unattended",
            },
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "mode_not_allowed"

    def test_bypass_is_refused_even_when_modes_are_allowed(self, tmp_path, metrics):
        from fastapi.testclient import TestClient
        from tests.conftest import authorised, build_settings

        from permgate.main import create_app

        settings = build_settings(
            tmp_path,
            allow_client_supplied_mode=True,
            allow_bypass_mode=False,  # the point of the test
        )
        with authorised(TestClient(create_app(settings, metrics=metrics))) as client:
            response = client.post(
                "/v1/decisions",
                json={
                    "project_root": str(tmp_path),
                    "tool": "bash",
                    "arguments": {"command": FLAGGED},
                    "mode": "bypass",
                },
            )
        assert response.status_code == 403
        assert response.json()["error"]["details"]["mode"] == "bypass"


class TestAnswerFlow:
    def test_answering_always_makes_the_next_call_silent(self, client, project):
        first = _decide(client, project, VOUCHED)
        assert first["verdict"] == "ask"

        answered = client.post(
            f"/v1/decisions/{first['decision_id']}/answer", json={"answer": "always"}
        )
        assert answered.status_code == 200
        assert answered.json()["granted_key"] == "bash"
        assert answered.json()["grant_created"] is True

        second = _decide(client, project, VOUCHED)
        assert second["verdict"] == "allow"
        assert second["rule"] == "tool_grant"

    def test_always_on_a_flagged_call_grants_nothing_and_does_not_cover_it(self, client, project):
        """The asymmetry, end to end.

        The human agreed to one destructive command. That says nothing about the
        next one, so no grant is recorded and the following call is still asked
        about -- while the `once` answer still lets this call through.
        """
        first = _decide(client, project, FLAGGED)
        answered = client.post(
            f"/v1/decisions/{first['decision_id']}/answer", json={"answer": "always"}
        )
        assert answered.status_code == 200
        assert answered.json()["granted_key"] is None
        assert answered.json()["grant_created"] is False

        second = _decide(client, project, FLAGGED)
        assert second["verdict"] == "ask"
        assert second["rule"] == "risk_flagged"

    def test_scoped_covers_the_family_including_flagged_calls(self, client, project):
        first = _decide(client, project, FLAGGED)
        answered = client.post(
            f"/v1/decisions/{first['decision_id']}/answer", json={"answer": "scoped"}
        )
        assert answered.json()["granted_key"] == "bash:kubectl delete"

        same_family = _decide(client, project, "kubectl delete namespace staging")
        assert same_family["verdict"] == "allow"
        assert same_family["rule"] == "scoped_grant"

    def test_scoped_does_not_leak_to_a_sibling_family(self, client, project):
        first = _decide(client, project, FLAGGED)
        client.post(f"/v1/decisions/{first['decision_id']}/answer", json={"answer": "scoped"})

        other = _decide(client, project, "terraform destroy -auto-approve")
        assert other["verdict"] == "ask"

    def test_once_records_nothing(self, client, project):
        first = _decide(client, project, VOUCHED)
        answered = client.post(
            f"/v1/decisions/{first['decision_id']}/answer", json={"answer": "once"}
        )
        assert answered.json()["granted_key"] is None
        assert _decide(client, project, VOUCHED)["verdict"] == "ask"

    def test_a_replayed_answer_is_refused(self, client, project):
        """Rewriting what a person decided is the one thing an audit trail must
        never permit, so the second write loses rather than overwriting."""
        first = _decide(client, project, VOUCHED)
        client.post(f"/v1/decisions/{first['decision_id']}/answer", json={"answer": "once"})
        again = client.post(
            f"/v1/decisions/{first['decision_id']}/answer", json={"answer": "always"}
        )
        assert again.status_code == 409
        assert again.json()["error"]["code"] == "already_answered"

    def test_an_unknown_decision_is_a_404(self, client):
        response = client.post("/v1/decisions/does-not-exist/answer", json={"answer": "once"})
        assert response.status_code == 404

    def test_an_unknown_answer_is_a_422(self, client, project):
        first = _decide(client, project, VOUCHED)
        response = client.post(
            f"/v1/decisions/{first['decision_id']}/answer", json={"answer": "maybe"}
        )
        assert response.status_code == 422
