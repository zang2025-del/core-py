"""The audit trail is append-only because the database says so.

Every test here writes with raw SQL rather than through the service. That is the
point: the service is not the only thing that can reach a database, and a
guarantee that holds only while the application cooperates is the guarantee this
rule exists to replace. A migration, an operator with ``psql``, or a future bug
can all issue the same statements.

The rule is not "no UPDATE" -- answering a prompt legitimately sets the answer
columns. It is: one transition, unanswered to answered, and never a DELETE.

These run against whichever backend ``TEST_DATABASE_URL`` selects, so the claim
"both engines enforce this" is checked on both rather than asserted. The DDL for
the two differs; the behaviour must not.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

from permgate.storage.repositories import DecisionRepository, ProjectRepository

VOUCHED = "ls -la"


@pytest.fixture
def decision(session_factory, tmp_path):
    """One recorded decision, and the ids a raw writer would need."""
    with session_factory() as session:
        project = ProjectRepository(session).get_or_create(str(tmp_path))
        DecisionRepository(session).record(
            decision_id="d-append-only",
            project_id=project.id,
            tool="bash",
            arguments={"command": VOUCHED},
            arguments_json='{"command": "ls -la"}',
            verdict="ask",
            rule="unrecognised",
            reason=None,
            scope=None,
            run_mode="interactive",
            latency_us=1,
            actor="original",
            request_id=None,
        )
        session.commit()
        return {"decision_id": "d-append-only", "project_id": project.id}


def _attempt(session_factory, sql: str) -> None:
    """Run one statement and raise whatever the database says about it."""
    with session_factory() as session:
        session.execute(text(sql))
        session.commit()


class TestDeletesAreRefused:
    def test_one_audit_row_cannot_be_deleted(self, session_factory, decision):
        with pytest.raises(DatabaseError):
            _attempt(session_factory, f"DELETE FROM decisions WHERE id='{decision['decision_id']}'")

    def test_deleting_the_workspace_does_not_erase_its_history(self, session_factory, decision):
        """The cascade is refused rather than allowed to sweep the table.

        ``decisions.project_id`` is ``ON DELETE CASCADE``, so without this the
        way to empty the audit trail would be to delete the workspace it belongs
        to -- and the trail would be gone with no record that it ever existed.
        The intended precedence is the opposite: the history wins and the delete
        fails.
        """
        with pytest.raises(DatabaseError):
            _attempt(session_factory, f"DELETE FROM projects WHERE id={decision['project_id']}")

        # And the row is still there afterwards, not merely reported as failed.
        with session_factory() as session:
            assert session.scalar(text("SELECT count(*) FROM decisions")) == 1


class TestUpdatesAreRefusedExceptTheAnswer:
    def test_rewriting_the_answer_is_refused(self, session_factory, decision):
        decision_id = decision["decision_id"]
        _attempt(
            session_factory,
            f"UPDATE decisions SET answer='once', answered_at=CURRENT_TIMESTAMP"
            f" WHERE id='{decision_id}'",
        )
        with pytest.raises(DatabaseError):
            _attempt(
                session_factory,
                f"UPDATE decisions SET answer='always' WHERE id='{decision_id}'",
            )

    def test_rewriting_the_verdict_is_refused(self, session_factory, decision):
        with pytest.raises(DatabaseError):
            _attempt(
                session_factory,
                f"UPDATE decisions SET verdict='allow' WHERE id='{decision['decision_id']}'",
            )

    def test_rewriting_the_recorded_arguments_is_refused(self, session_factory, decision):
        """The digest proves which call a row refers to. Editing the arguments
        while leaving the digest would make the row attest to something that
        never happened."""
        with pytest.raises(DatabaseError):
            _attempt(
                session_factory,
                'UPDATE decisions SET arguments=\'{"command": "rm -rf /"}\''
                f" WHERE id='{decision['decision_id']}'",
            )

    def test_setting_an_answer_on_an_answered_row_is_refused(self, session_factory, decision):
        """Not just a second answer -- any UPDATE of an answered row. The window
        is one transition wide, and it closes."""
        decision_id = decision["decision_id"]
        _attempt(
            session_factory,
            f"UPDATE decisions SET answer='once', answered_at=CURRENT_TIMESTAMP"
            f" WHERE id='{decision_id}'",
        )
        with pytest.raises(DatabaseError):
            _attempt(
                session_factory,
                f"UPDATE decisions SET answer_actor='someone' WHERE id='{decision_id}'",
            )


class TestTheLegitimateWriteStillWorks:
    def test_answering_through_the_service_is_allowed(self, client, project):
        """The constraint has to be narrow enough to permit the one write the
        service actually makes -- otherwise it would be discovered by the first
        person to click a prompt in production."""
        created = client.post(
            "/v1/decisions",
            json={"project_root": str(project), "tool": "bash", "arguments": {"command": VOUCHED}},
        )
        decision_id = created.json()["decision_id"]

        answered = client.post(f"/v1/decisions/{decision_id}/answer", json={"answer": "once"})
        assert answered.status_code == 200, answered.text

        entries = client.get("/v1/audit", params={"project_root": str(project)}).json()["entries"]
        recorded = [entry for entry in entries if entry["decision_id"] == decision_id]
        assert recorded[0]["answer"] == "once"
        assert recorded[0]["verdict"] == "ask", "the original verdict must survive the answer"
