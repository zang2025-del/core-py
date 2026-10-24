"""Two people clicking the same prompt at the same instant.

A sequential replay does not test this. Send the same answer twice in a row and
the second one is refused by any implementation that checks ``row.answer is not
None`` before writing -- which is how this method used to work, and it was
wrong. The property that matters is that the *first* request wins when both are
in flight, and only a concurrent test can see it.

So this test does not hope for an unlucky interleaving. It holds every thread's
read at a barrier until all of them have read, which guarantees the worst case:
every request observes an unanswered decision and every request proceeds to
write. Exactly one may be right. On the old read-then-write check all of them
would be -- the last commit silently overwriting what a person decided -- so
this fails loudly on that code rather than passing on a lucky schedule.

The ``FOR UPDATE`` version of this test is the reason the fix is not a row lock:
SQLite compiles that clause away entirely, so a lock would be held in CI and not
in the default deployment. See ``DecisionRepository.answer``.
"""

from __future__ import annotations

import threading
from typing import Any

from permgate.storage.repositories import DecisionRepository

VOUCHED = "ls -la"


def _decide(client, project, command: str = VOUCHED) -> dict[str, Any]:
    response = client.post(
        "/v1/decisions",
        json={"project_root": str(project), "tool": "bash", "arguments": {"command": command}},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _audit_for(client, project, decision_id: str) -> list[dict[str, Any]]:
    entries = client.get("/v1/audit", params={"project_root": str(project)}).json()["entries"]
    return [entry for entry in entries if entry["decision_id"] == decision_id]


class TestSimultaneousAnswers:
    def test_exactly_one_simultaneous_answer_is_accepted(self, client, project, monkeypatch):
        """Four writers, all released at once, all holding an unanswered row.

        ``once`` rather than ``always`` on purpose: this test is about the
        ``decisions.answer`` column, and a grant-writing answer would fold in a
        second race (the grant's unique constraint) whose idempotence is already
        pinned by its own tests. One mechanism per test.
        """
        decision_id = _decide(client, project)["decision_id"]

        writers = 4
        # Every thread waits here, so the reads all complete before any write
        # starts. The timeout is a failure mode, not a race: if a request never
        # reaches the repository the barrier breaks and the test says so,
        # instead of quietly degenerating into the sequential test.
        rendezvous = threading.Barrier(writers, timeout=30)
        real_get = DecisionRepository.get

        def get_then_hold(self: DecisionRepository, requested: str):
            row = real_get(self, requested)
            if requested == decision_id:
                rendezvous.wait()
            return row

        monkeypatch.setattr(DecisionRepository, "get", get_then_hold)

        responses: list[Any] = [None] * writers
        failures: list[BaseException] = []

        def answer(index: int) -> None:
            try:
                responses[index] = client.post(
                    f"/v1/decisions/{decision_id}/answer", json={"answer": "once"}
                )
            except BaseException as exc:  # reported below, not swallowed
                failures.append(exc)

        threads = [threading.Thread(target=answer, args=(index,)) for index in range(writers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)

        assert not failures, failures
        assert all(response is not None for response in responses), responses

        accepted = [r for r in responses if r.status_code == 200]
        refused = [r for r in responses if r.status_code != 200]
        assert len(accepted) == 1, [(r.status_code, r.text) for r in responses]
        for response in refused:
            assert response.status_code == 409, response.text
            assert response.json()["error"]["code"] == "already_answered"

        # The row holds one answer, and it is the one the winner sent -- not a
        # blend, not the last writer's.
        assert accepted[0].json()["answer"] == "once"
        entries = _audit_for(client, project, decision_id)
        assert len(entries) == 1, entries
        assert entries[0]["answer"] == "once"

    def test_the_refused_writers_do_not_leave_a_grant_behind(self, client, project, monkeypatch):
        """A loser must not have written a grant before losing.

        ``always`` on an unflagged command is the answer that records a standing
        grant, so it is the one where a half-applied answer would show up as
        real authority. The loser's grant is written in the same transaction as
        its conditional update, so losing rolls it back; this asserts that,
        rather than trusting the transaction boundary to be where it looks.
        """
        decision_id = _decide(client, project)["decision_id"]

        rendezvous = threading.Barrier(2, timeout=30)
        real_get = DecisionRepository.get

        def get_then_hold(self: DecisionRepository, requested: str):
            row = real_get(self, requested)
            if requested == decision_id:
                rendezvous.wait()
            return row

        monkeypatch.setattr(DecisionRepository, "get", get_then_hold)

        responses: list[Any] = [None, None]

        def answer(index: int) -> None:
            responses[index] = client.post(
                f"/v1/decisions/{decision_id}/answer", json={"answer": "always"}
            )

        threads = [threading.Thread(target=answer, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)

        assert [r.status_code for r in responses].count(200) == 1, [
            (r.status_code, r.text) for r in responses
        ]
        grants = client.get("/v1/grants", params={"project_root": str(project)}).json()["grants"]
        # One grant, not two. Two rows would mean the loser committed its grant
        # and then lost only the answer -- which is the failure this asserts
        # against, and it would be invisible in the answer's own status code.
        assert len(grants) == 1, grants
