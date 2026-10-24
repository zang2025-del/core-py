"""Every endpoint answers with the same project root, and grant keys survive URLs.

Two narrow but real defects lived here, and neither was caught by the existing
suite -- which is the point of giving them their own file rather than folding
them into the endpoint tests.

**Identity.** ``POST /v1/decisions`` returns the *resolved* root, while the
grant endpoints echoed back whatever string the caller sent. So the same
workspace came back as ``C:\\Users\\me\\proj`` from one endpoint and
``C:/Users/me/proj`` from another. Nothing failed: each endpoint was
self-consistent, and every test passed. A client that read its project identity
from one and handed it to another was quietly working with two.

**Keys in URLs.** Scoped keys routinely contain spaces
(``bash:terraform destroy -auto-approve``), and a raw space is not a legal URL
path character. The client has to percent-encode; the server has to decode.
``httpx`` does the encoding transparently, so this path was being exercised
without any test saying so out loud.
"""

from __future__ import annotations

from permgate.storage.keys import normalise_root

VOUCHED = "ls -la"
A_KEY_WITH_SPACES = "terraform destroy -auto-approve"


def _decide(client, project, command: str):
    response = client.post(
        "/v1/decisions",
        json={"project_root": str(project), "tool": "bash", "arguments": {"command": command}},
    )
    assert response.status_code == 200, response.text
    return response.json()


class TestOneCanonicalRoot:
    def test_the_decision_endpoint_defines_the_canonical_form(self, client, project):
        assert _decide(client, project, VOUCHED)["project_root"] == normalise_root(project)

    def test_the_grant_listing_reports_the_same_root(self, client, project):
        canonical = _decide(client, project, VOUCHED)["project_root"]
        listed = client.get("/v1/grants", params={"project_root": str(project)}).json()
        assert listed["project_root"] == canonical

    def test_the_listing_is_canonical_even_for_a_workspace_never_seen(self, client, tmp_path):
        """There is no row to read the root from, so it has to be *resolved*
        rather than looked up -- otherwise the empty case is the only one that
        answers differently."""
        unseen = tmp_path / "never-asked"
        unseen.mkdir()
        listed = client.get("/v1/grants", params={"project_root": str(unseen)}).json()
        assert listed["grants"] == []
        assert listed["project_root"] == normalise_root(unseen)

    def test_the_create_response_reports_the_root_and_whether_it_created(self, client, project):
        canonical = _decide(client, project, VOUCHED)["project_root"]

        first = client.post("/v1/grants", json={"project_root": str(project), "tool": "bash"})
        assert first.json()["project_root"] == canonical
        assert first.json()["created"] is True

        again = client.post("/v1/grants", json={"project_root": str(project), "tool": "bash"})
        assert again.json()["created"] is False
        assert again.json()["key"] == first.json()["key"]

    def test_the_revoke_response_reports_the_same_root(self, client, project):
        canonical = _decide(client, project, VOUCHED)["project_root"]
        client.post("/v1/grants", json={"project_root": str(project), "tool": "bash"})

        revoked = client.delete("/v1/grants/bash", params={"project_root": str(project)})
        assert revoked.json()["project_root"] == canonical

        cleared = client.delete("/v1/grants", params={"project_root": str(project)})
        assert cleared.json()["project_root"] == canonical

    def test_a_relative_path_and_an_absolute_one_are_one_project(
        self, client, project, monkeypatch
    ):
        """The resolved form is what makes `proj`, `./proj/` and an absolute
        path one workspace rather than three."""
        monkeypatch.chdir(project)
        absolute = _decide(client, project, VOUCHED)["project_root"]
        relative = _decide(client, ".", VOUCHED)["project_root"]
        assert absolute == relative

    def test_a_subdirectory_is_the_same_workspace_everywhere(self, client, project):
        nested = project / "src" / "deep"
        nested.mkdir(parents=True)
        root = _decide(client, project, VOUCHED)["project_root"]
        listed = client.get("/v1/grants", params={"project_root": str(nested)}).json()
        assert listed["project_root"] == root


class TestGrantKeysInUrls:
    def test_a_key_containing_spaces_survives_a_url_encoded_round_trip(self, client, project):
        created = client.post(
            "/v1/grants",
            json={
                "project_root": str(project),
                "tool": "bash",
                "scope": A_KEY_WITH_SPACES,
            },
        ).json()
        key = created["key"]
        assert " " in key, "the scope is supposed to contain spaces; this test is about that"

        revoked = client.delete(f"/v1/grants/{key}", params={"project_root": str(project)})
        assert revoked.status_code == 200, revoked.text
        assert revoked.json()["removed"] == 1
        assert revoked.json()["key"] == key

    def test_the_colon_separator_is_not_read_as_a_prefix(self, client, project):
        client.post(
            "/v1/grants",
            json={"project_root": str(project), "tool": "bash", "scope": "git push"},
        )
        listed = client.get("/v1/grants", params={"project_root": str(project)}).json()
        assert [grant["key"] for grant in listed["grants"]] == ["bash:git push"]

        removed = client.delete("/v1/grants/bash:git push", params={"project_root": str(project)})
        assert removed.json()["removed"] == 1

    def test_revoking_a_scoped_key_leaves_the_tool_level_grant_alone(self, client, project):
        """`bash` and `bash:git push` differ by a suffix and authorise different
        things. A prefix match would delete both."""
        for scope in (None, "git push"):
            client.post(
                "/v1/grants",
                json={"project_root": str(project), "tool": "bash", "scope": scope},
            )

        client.delete("/v1/grants/bash:git push", params={"project_root": str(project)})
        left = client.get("/v1/grants", params={"project_root": str(project)}).json()["grants"]
        assert [grant["key"] for grant in left] == ["bash"]
