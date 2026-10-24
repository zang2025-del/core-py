"""A retried call decides once.

``POST /v1/decisions`` is not safe to retry on its own, and the retry is what
every client does after a timeout -- which is exactly when the service is most
likely to be slow. So the retry cannot be discouraged away; it has to be made
harmless. With an ``Idempotency-Key``, the second request gets the first
answer, and the trail keeps one row for one command.

Three properties are worth pinning, and they fail in different ways:

* the response is **the same**, byte for byte, so a client comparing bodies
  detects nothing spurious and a client that does not compare still gets the
  right verdict;
* the audit trail has **one** row, because a trail with a duplicate is a trail
  that overstates what the agent did;
* a key reused for a **different request** is refused rather than answered with
  the first call's verdict -- answering it would decide a call nobody evaluated,
  which is worse than any error.
"""

from __future__ import annotations

import pytest

VOUCHED = "ls -la"
FLAGGED = "kubectl delete namespace production"
KEY = "Idempotency-Key"


def _decide(client, project, command: str, *, key: str | None = None, **extra):
    headers = {KEY: key} if key is not None else {}
    return client.post(
        "/v1/decisions",
        headers=headers,
        json={
            "project_root": str(project),
            "tool": "bash",
            "arguments": {"command": command},
            **extra,
        },
    )


def _trail(client, project) -> list[dict]:
    response = client.get("/v1/audit", params={"project_root": str(project)})
    assert response.status_code == 200, response.text
    return response.json()["entries"]


class TestAReplayedCall:
    def test_the_same_key_returns_the_first_answer(self, client, project):
        first = _decide(client, project, VOUCHED, key="retry-me")
        second = _decide(client, project, VOUCHED, key="retry-me")

        assert first.status_code == 200
        assert second.status_code == 200
        assert first.json() == second.json()
        assert second.headers.get("Idempotency-Replayed") == "true"
        assert first.headers.get("Idempotency-Replayed") is None

    def test_the_body_is_byte_for_byte_identical(self, client, project):
        """A replay is reported in a header, not a field.

        A client that detects replays by comparing bodies -- the obvious way to
        write one -- must not see a difference, or the guarantee reads as broken
        at the exact moment it worked.
        """
        first = _decide(client, project, VOUCHED, key="same-bytes")
        second = _decide(client, project, VOUCHED, key="same-bytes")
        assert first.content == second.content

    def test_a_replay_does_not_write_a_second_audit_row(self, client, project):
        """The row count is the property, not the response. A retried call that
        recorded twice would make the trail overstate what actually ran."""
        for _ in range(4):
            assert _decide(client, project, VOUCHED, key="one-row").status_code == 200

        rows = _trail(client, project)
        assert len(rows) == 1

    def test_an_ask_is_not_raised_twice(self, client, project):
        """The case that makes this worth building: a retried prompt is a second
        question to a human about a call they are already looking at."""
        first = _decide(client, project, FLAGGED, key="one-prompt")
        second = _decide(client, project, FLAGGED, key="one-prompt")

        assert first.json()["verdict"] == "ask"
        assert second.json()["verdict"] == "ask"
        assert second.json()["decision_id"] == first.json()["decision_id"]

    def test_replaying_after_a_grant_still_returns_the_old_verdict(self, client, project):
        """A replay is the *old* answer, not a re-evaluation.

        Re-deciding would be a different feature: it would let a client turn a
        retry into a second chance at a verdict, so a call refused a moment ago
        could come back allowed once an unrelated grant was written.
        """
        first = _decide(client, project, VOUCHED, key="cached-verdict")
        assert first.json()["verdict"] == "ask"

        client.post("/v1/grants", json={"project_root": str(project), "tool": "bash"})
        # The same command without a key now allows, which is what the grant did.
        assert _decide(client, project, VOUCHED).json()["verdict"] == "allow"
        # The key still answers with what it answered before.
        assert _decide(client, project, VOUCHED, key="cached-verdict").json() == first.json()

    def test_a_call_without_a_key_is_never_deduplicated(self, client, project):
        """Opting in is per request. Two identical calls with no key are two
        calls, and collapsing them would silently drop a real evaluation."""
        first = _decide(client, project, VOUCHED)
        second = _decide(client, project, VOUCHED)

        assert first.json()["decision_id"] != second.json()["decision_id"]
        assert len(_trail(client, project)) == 2


class TestAKeyThatIsReused:
    def test_the_same_key_for_a_different_command_is_a_conflict(self, client, project):
        _decide(client, project, VOUCHED, key="reused")
        response = _decide(client, project, FLAGGED, key="reused")

        assert response.status_code == 409
        assert response.json()["error"]["code"] == "idempotency_conflict"

    def test_the_same_key_for_a_different_workspace_is_a_conflict(self, client, project, tmp_path):
        other = tmp_path / "other"
        other.mkdir()

        _decide(client, project, VOUCHED, key="two-roots")
        response = _decide(client, other, VOUCHED, key="two-roots")

        assert response.status_code == 409

    def test_different_spellings_of_one_workspace_are_the_same_call(self, client, project):
        """The fingerprint is taken over the *resolved* root. A key that only
        matched an exact string would miss the retry it exists for, because a
        retry is usually rebuilt by other code that spells the path differently.
        """
        first = _decide(client, project, VOUCHED, key="spelled-twice")
        nested = project / "src" / "deep"
        nested.mkdir(parents=True)
        second = _decide(client, nested, VOUCHED, key="spelled-twice")

        assert first.status_code == 200
        assert second.status_code == 200
        assert second.headers.get("Idempotency-Replayed") == "true"

    def test_a_key_is_not_a_way_to_read_another_callers_answer(self, container, project):
        """Keys are scoped per caller.

        A shared namespace would let one client name a key -- a name it can
        guess, since keys are chosen by clients -- and receive a decision that
        belongs to another caller. Driven at the service layer because that is
        where the identity is a value to pass in; the API supplies it from the
        credential.
        """
        kwargs = {
            "project_root": str(project),
            "tool": "bash",
            "arguments": {"command": FLAGGED},
            "idempotency_key": "shared-name",
        }
        first = container.decisions.evaluate(actor="client-a", **kwargs)
        other = container.decisions.evaluate(actor="client-b", **kwargs)

        assert other.decision_id != first.decision_id
        assert other.replayed is False

        # The same caller replaying, however, does get the stored answer.
        again = container.decisions.evaluate(actor="client-a", **kwargs)
        assert again.decision_id == first.decision_id
        assert again.replayed is True

    def test_a_retry_after_a_rejected_request_is_not_blocked(self, client, project, tmp_path):
        """Only successful calls claim a key.

        A request refused for a reason the caller can fix -- here, a workspace
        they may not name -- must not spend the key, or fixing the request would
        require inventing a new key as well.
        """
        outside = tmp_path.parent / f"{tmp_path.name}-outside"
        outside.mkdir()
        refused = _decide(client, outside, VOUCHED, key="after-a-403")
        assert refused.status_code == 403

        accepted = _decide(client, project, VOUCHED, key="after-a-403")
        assert accepted.status_code == 200
        assert accepted.headers.get("Idempotency-Replayed") is None


class TestTheKeyItself:
    def test_an_empty_key_is_rejected(self, client, project):
        response = _decide(client, project, VOUCHED, key="")
        assert response.status_code == 422

    def test_an_over_long_key_is_rejected(self, client, project):
        response = _decide(client, project, VOUCHED, key="k" * 256)
        assert response.status_code == 422

    @pytest.mark.parametrize("key", ["abc", "a" * 255, "key with spaces", "with/slash+plus=eq"])
    def test_ordinary_keys_are_accepted(self, client, project, key):
        assert _decide(client, project, VOUCHED, key=key).status_code == 200
