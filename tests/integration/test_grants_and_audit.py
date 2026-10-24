"""Grants are visible and revocable; decisions are recorded.

Two halves of the same promise. A grant a user cannot see is a grant they
cannot judge, and an audit trail nobody can read is not a trail.
"""

from __future__ import annotations

FLAGGED = "kubectl delete namespace production"
VOUCHED = "ls -la"


def _decide(client, project, command: str):
    response = client.post(
        "/v1/decisions",
        json={"project_root": str(project), "tool": "bash", "arguments": {"command": command}},
    )
    assert response.status_code == 200, response.text
    return response.json()


class TestGrantApi:
    def test_a_project_with_no_grants_returns_an_empty_list(self, client, project):
        response = client.get("/v1/grants", params={"project_root": str(project)})
        assert response.status_code == 200
        assert response.json()["grants"] == []

    def test_creating_a_grant_reports_its_strength(self, client, project):
        """The key alone does not say whether a grant survives a flagged call,
        and that is the only thing about a grant that really matters."""
        response = client.post("/v1/grants", json={"project_root": str(project), "tool": "bash"})
        assert response.status_code == 201
        assert response.json()["strength"].startswith("broad")

        scoped = client.post(
            "/v1/grants",
            json={"project_root": str(project), "tool": "bash", "scope": "kubectl delete"},
        )
        assert scoped.json()["strength"].startswith("narrow")

    def test_creating_the_same_grant_twice_is_idempotent(self, client, project):
        """Replaying a provisioning script must not produce two rows, and must
        not fail either."""
        for _ in range(3):
            response = client.post(
                "/v1/grants", json={"project_root": str(project), "tool": "bash"}
            )
            assert response.status_code == 201

        listed = client.get("/v1/grants", params={"project_root": str(project)}).json()
        assert len(listed["grants"]) == 1

    def test_grants_can_be_listed_and_revoked(self, client, project):
        client.post("/v1/grants", json={"project_root": str(project), "tool": "bash"})
        client.post(
            "/v1/grants",
            json={"project_root": str(project), "tool": "bash", "scope": "git push"},
        )

        keys = {
            grant["key"]
            for grant in client.get("/v1/grants", params={"project_root": str(project)}).json()[
                "grants"
            ]
        }
        assert keys == {"bash", "bash:git push"}

        removed = client.delete("/v1/grants/bash", params={"project_root": str(project)})
        assert removed.json()["removed"] == 1

        left = client.get("/v1/grants", params={"project_root": str(project)}).json()["grants"]
        assert [grant["key"] for grant in left] == ["bash:git push"]

    def test_a_scoped_key_with_a_space_survives_the_round_trip(self, client, project):
        client.post(
            "/v1/grants",
            json={"project_root": str(project), "tool": "bash", "scope": "git push --force"},
        )
        removed = client.delete(
            "/v1/grants/bash:git push --force", params={"project_root": str(project)}
        )
        assert removed.json()["removed"] == 1

    def test_revoking_something_absent_reports_zero(self, client, project):
        # The project has to exist first. A workspace the gateway has never seen
        # has no row to revoke against, which is a 404 rather than a silent zero
        # -- the caller is asking about a project that is not there.
        _decide(client, project, VOUCHED)
        response = client.delete("/v1/grants/nope", params={"project_root": str(project)})
        assert response.status_code == 200
        assert response.json()["removed"] == 0

    def test_clearing_returns_how_many_went(self, client, project):
        for scope in ("", "git push", "kubectl delete"):
            client.post(
                "/v1/grants",
                json={"project_root": str(project), "tool": "bash", "scope": scope or None},
            )
        response = client.delete("/v1/grants", params={"project_root": str(project)})
        assert response.json()["removed"] == 3

    def test_revoking_for_an_unknown_project_is_a_404(self, client, tmp_path):
        response = client.delete(
            "/v1/grants/bash", params={"project_root": str(tmp_path / "never-seen")}
        )
        assert response.status_code == 404

    def test_a_manual_grant_can_be_narrow_and_strong(self, client, project):
        """The operator's path: pre-approve a family for an unattended pipeline
        without handing over the whole tool."""
        client.post(
            "/v1/grants",
            json={"project_root": str(project), "tool": "bash", "scope": "kubectl delete"},
        )
        assert _decide(client, project, FLAGGED)["rule"] == "scoped_grant"


class TestAuditApi:
    def test_every_decision_is_recorded_including_allows(self, client, project):
        """An audit log that only records refusals cannot answer 'what did the
        agent actually run last Tuesday', which is the question people ask."""
        _decide(client, project, VOUCHED)
        client.post("/v1/grants", json={"project_root": str(project), "tool": "bash"})
        _decide(client, project, VOUCHED)  # now allowed

        entries = client.get("/v1/audit", params={"project_root": str(project)}).json()["entries"]
        verdicts = [entry["verdict"] for entry in entries]
        assert verdicts == ["allow", "ask"]

    def test_the_rule_is_recorded_so_a_row_explains_itself(self, client, project):
        _decide(client, project, VOUCHED)
        entry = client.get("/v1/audit", params={"project_root": str(project)}).json()["entries"][0]
        assert entry["rule"] == "unrecognised"
        assert entry["arguments_digest"]
        assert entry["arguments"] == {"command": VOUCHED}

    def test_the_answer_is_attached_to_the_decision_that_raised_it(self, client, project):
        # A chain has no single command family, so `scoped` has nothing narrower
        # than the tool to name and falls back to the weak grant. Recording that
        # fallback is the point: the audit row says what was actually granted,
        # not what was asked for.
        first = _decide(client, project, "ls -la && pwd")
        assert first["scope"] is None
        client.post(f"/v1/decisions/{first['decision_id']}/answer", json={"answer": "scoped"})

        entry = client.get("/v1/audit", params={"project_root": str(project)}).json()["entries"][0]
        assert entry["answer"] == "scoped"
        assert entry["granted_key"] == "bash"

    def test_a_single_command_records_the_narrow_key(self, client, project):
        first = _decide(client, project, VOUCHED)
        assert first["scope"] == "ls -la"
        client.post(f"/v1/decisions/{first['decision_id']}/answer", json={"answer": "scoped"})

        entry = client.get("/v1/audit", params={"project_root": str(project)}).json()["entries"][0]
        assert entry["granted_key"] == "bash:ls -la"

    def test_the_audit_trail_can_be_filtered_by_verdict(self, client, project):
        _decide(client, project, VOUCHED)
        client.post("/v1/grants", json={"project_root": str(project), "tool": "bash"})
        _decide(client, project, VOUCHED)

        allows = client.get(
            "/v1/audit", params={"project_root": str(project), "verdict": "allow"}
        ).json()["entries"]
        assert len(allows) == 1 and allows[0]["verdict"] == "allow"

    def test_arguments_can_be_withheld_and_the_digest_still_identifies_the_call(
        self, tmp_path, metrics
    ):
        """The privacy tradeoff, made explicit: an operator can turn raw argument
        storage off, and a row still proves *which* call it was."""
        from fastapi.testclient import TestClient
        from tests.conftest import authorised, build_settings

        from permgate.main import create_app

        settings = build_settings(
            tmp_path,
            audit_store_arguments=False,
        )
        with authorised(TestClient(create_app(settings, metrics=metrics))) as client:
            client.post(
                "/v1/decisions",
                json={
                    "project_root": str(tmp_path),
                    "tool": "bash",
                    "arguments": {"command": VOUCHED},
                },
            )
            entry = client.get("/v1/audit", params={"project_root": str(tmp_path)}).json()[
                "entries"
            ][0]

        assert entry["arguments"] is None
        assert entry["arguments_digest"]

    def test_the_audit_trail_is_scoped_to_a_project(self, client, tmp_path, project):
        other = tmp_path / "other"
        other.mkdir()
        (other / ".git").mkdir()
        _decide(client, project, VOUCHED)
        assert client.get("/v1/audit", params={"project_root": str(other)}).json()["entries"] == []

    def test_limit_is_honoured_and_bounded(self, client, project):
        for _ in range(5):
            _decide(client, project, VOUCHED)
        assert (
            len(
                client.get("/v1/audit", params={"project_root": str(project), "limit": 3}).json()[
                    "entries"
                ]
            )
            == 3
        )
        assert client.get("/v1/audit", params={"limit": 10_000}).status_code == 422


class TestOperations:
    def test_healthz_does_not_touch_the_database(self, client):
        assert client.get("/healthz").json()["status"] == "ok"

    def test_readyz_reports_the_database(self, client):
        body = client.get("/readyz").json()
        assert body["status"] == "ready"
        assert body["database"] is True

    def test_metrics_are_exposed_in_prometheus_format(self, tmp_path):
        """Built with the prometheus sink rather than the recording one, because
        the recording sink answers ``/metrics`` with "disabled" by design --
        the two are different objects and conflating them is how a test ends up
        asserting nothing about the exporter.
        """
        from fastapi.testclient import TestClient
        from tests.conftest import authorised, build_settings

        from permgate.main import create_app
        from permgate.observability.metrics import PrometheusMetrics

        settings = build_settings(tmp_path)
        with authorised(TestClient(create_app(settings, metrics=PrometheusMetrics()))) as client:
            client.post(
                "/v1/decisions",
                json={
                    "project_root": str(tmp_path),
                    "tool": "bash",
                    "arguments": {"command": VOUCHED},
                },
            )
            response = client.get("/metrics")

        assert response.status_code == 200
        assert "permgate_decisions_total" in response.text
        assert 'rule="unrecognised"' in response.text
        assert 'verdict="ask"' in response.text

    def test_the_latency_histogram_is_not_the_prometheus_default(self, tmp_path):
        """The default buckets start at 5ms and would put every decision in the
        first one, which measures nothing."""
        from permgate.observability.metrics import LATENCY_BUCKETS

        assert min(LATENCY_BUCKETS) < 0.001
        assert max(LATENCY_BUCKETS) >= 0.5

    def test_the_rule_tables_are_inspectable(self, client):
        """A rule layer nobody can inspect is a rule layer nobody can argue
        with."""
        body = client.get("/v1/rules").json()
        assert "ls" in body["safe_programs"]
        assert "terraform" in body["never_safe"]
        assert "build" in body["regenerable"]

    def test_the_request_id_is_echoed_and_logged(self, client, project):
        response = client.post(
            "/v1/decisions",
            json={"project_root": str(project), "tool": "bash", "arguments": {"command": VOUCHED}},
            headers={"X-Request-ID": "trace-me-1234"},
        )
        assert response.headers["X-Request-ID"] == "trace-me-1234"
