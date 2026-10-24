"""Storage-layer behaviour: constraints, idempotency, transactions.

These test the database directly rather than through the API, because the
properties being checked are the ones the API relies on and would otherwise
only exercise by accident -- a UNIQUE constraint that is never contended, a
cascade that is never triggered.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from permgate.storage.keys import find_project_root, normalise_root, project_key
from permgate.storage.models import Decision, Grant, Project
from permgate.storage.repositories import (
    DecisionRepository,
    GrantRepository,
    ProjectRepository,
    digest_arguments,
)


class TestProjectIdentity:
    def test_a_subdirectory_resolves_to_its_project_root(self, tmp_path):
        root = tmp_path / "proj"
        (root / ".git").mkdir(parents=True)
        nested = root / "src" / "deep"
        nested.mkdir(parents=True)
        assert find_project_root(nested) == find_project_root(root)

    def test_a_directory_outside_any_project_is_its_own_root(self, tmp_path):
        lone = tmp_path / "nowhere"
        lone.mkdir()
        assert find_project_root(lone) == normalise_root(lone)

    def test_resolution_is_stable_across_spellings(self, tmp_path):
        root = tmp_path / "proj"
        root.mkdir()
        assert normalise_root(root) == normalise_root(str(root) + "/")
        assert normalise_root(root / ".." / "proj") == normalise_root(root)

    def test_keys_differ_for_same_named_projects(self, tmp_path):
        """A key derived from the directory name alone would collide these."""
        first, second = tmp_path / "a" / "api", tmp_path / "b" / "api"
        first.mkdir(parents=True)
        second.mkdir(parents=True)
        assert project_key(first) != project_key(second)

    def test_the_key_keeps_a_readable_slug(self, tmp_path):
        root = tmp_path / "checkout-api"
        root.mkdir()
        assert project_key(root).startswith("checkout-api-")

    def test_a_name_with_separators_is_slugified(self, tmp_path):
        root = tmp_path / "weird name!"
        root.mkdir()
        assert project_key(root).startswith("weird-name-")


class TestConstraintBehaviour:
    def test_the_same_root_never_produces_two_projects(self, session_factory, tmp_path):
        with session_factory() as session:
            projects = ProjectRepository(session)
            first = projects.get_or_create(str(tmp_path))
            second = projects.get_or_create(str(tmp_path))
            assert first.id == second.id
            session.commit()

    def test_two_projects_sharing_a_name_stay_separate(self, session_factory, tmp_path):
        first, second = tmp_path / "a" / "api", tmp_path / "b" / "api"
        first.mkdir(parents=True)
        second.mkdir(parents=True)
        with session_factory() as session:
            projects = ProjectRepository(session)
            assert projects.get_or_create(str(first)).id != projects.get_or_create(str(second)).id
            session.commit()

    def test_a_tool_level_grant_cannot_be_duplicated(self, session_factory, tmp_path):
        """The reason `scope` is NOT NULL with an empty-string default. A
        nullable scope would have SQLite, PostgreSQL and MySQL all treat two
        tool-level grants as distinct, and the UNIQUE constraint would do
        nothing for the most common grant there is."""
        with session_factory() as session:
            project = ProjectRepository(session).get_or_create(str(tmp_path))
            grants = GrantRepository(session)
            _, created_first = grants.add(project_id=project.id, tool="bash")
            row, created_second = grants.add(project_id=project.id, tool="bash")
            session.commit()

            assert created_first is True
            assert created_second is False
            total = session.scalar(
                select(func.count()).select_from(Grant).where(Grant.project_id == project.id)
            )
            assert total == 1
            assert row.scope == ""

    def test_scoped_and_tool_level_grants_coexist(self, session_factory, tmp_path):
        with session_factory() as session:
            project = ProjectRepository(session).get_or_create(str(tmp_path))
            grants = GrantRepository(session)
            grants.add(project_id=project.id, tool="bash")
            grants.add(project_id=project.id, tool="bash", scope="git push")
            session.commit()
            assert grants.keys_for_project(project.id) == {"bash", "bash:git push"}

    def test_deleting_a_project_takes_its_grants_with_it(self, session_factory, tmp_path):
        with session_factory() as session:
            project = ProjectRepository(session).get_or_create(str(tmp_path))
            GrantRepository(session).add(project_id=project.id, tool="bash")
            session.commit()

            session.delete(project)
            session.commit()
            assert session.scalar(select(func.count()).select_from(Grant)) == 0


class TestAuditWrites:
    def _record(self, session, project_id: int, decision_id: str, **overrides):
        payload = {
            "decision_id": decision_id,
            "project_id": project_id,
            "tool": "bash",
            "arguments": {"command": "ls"},
            "arguments_json": '{"command": "ls"}',
            "verdict": "ask",
            "rule": "unrecognised",
            "reason": None,
            "scope": "ls",
            "run_mode": "interactive",
            "latency_us": 42,
            "actor": "tester",
            "request_id": None,
        }
        payload.update(overrides)
        return DecisionRepository(session).record(**payload)

    def test_a_decision_is_append_only_across_answers(self, session_factory, tmp_path):
        with session_factory() as session:
            project = ProjectRepository(session).get_or_create(str(tmp_path))
            self._record(session, project.id, "d-1")
            session.commit()

            DecisionRepository(session).answer(
                decision_id="d-1", answer="once", actor="human", granted_key=None
            )
            session.commit()

            row = session.get(Decision, "d-1")
            assert row is not None
            assert row.verdict == "ask", "the original verdict must not be rewritten"
            assert row.answer == "once"

    def test_an_answer_cannot_be_overwritten(self, session_factory, tmp_path):
        with session_factory() as session:
            project = ProjectRepository(session).get_or_create(str(tmp_path))
            self._record(session, project.id, "d-2")
            session.commit()
            repo = DecisionRepository(session)
            assert (
                repo.answer(decision_id="d-2", answer="once", actor="a", granted_key=None)
                is not None
            )
            assert (
                repo.answer(decision_id="d-2", answer="always", actor="b", granted_key="bash")
                is None
            )
            session.commit()
            assert session.get(Decision, "d-2").answer == "once"

    def test_the_arguments_digest_ignores_key_order(self):
        """Otherwise the digest would be a transcript of the JSON encoder
        rather than a fingerprint of the call."""
        assert digest_arguments({"a": 1, "b": 2}) == digest_arguments({"b": 2, "a": 1})

    def test_the_arguments_digest_separates_different_calls(self):
        assert digest_arguments({"command": "ls"}) != digest_arguments({"command": "ls -la"})

    def test_the_digest_is_recorded_even_when_the_arguments_are_not(
        self, session_factory, tmp_path
    ):
        with session_factory() as session:
            project = ProjectRepository(session).get_or_create(str(tmp_path))
            self._record(session, project.id, "d-3", arguments_json=None)
            session.commit()
            row = session.get(Decision, "d-3")
            assert row.arguments is None
            assert len(row.arguments_digest) == 64


class TestTransactions:
    def test_a_failed_transaction_leaves_no_grant_behind(self, session_factory, tmp_path):
        """A grant with no audit row is the state an audit trail must never be
        in, so the write and the record share one transaction."""
        with session_factory() as session:
            project = ProjectRepository(session).get_or_create(str(tmp_path))
            session.commit()

        from permgate.storage.database import session_scope

        with pytest.raises(RuntimeError), session_scope(session_factory) as session:
            GrantRepository(session).add(project_id=project.id, tool="bash")
            raise RuntimeError("something went wrong after the write")

        with session_factory() as session:
            assert session.scalar(select(func.count()).select_from(Grant)) == 0

    def test_session_scope_commits_on_success(self, session_factory, tmp_path):
        from permgate.storage.database import session_scope

        with session_scope(session_factory) as session:
            project = ProjectRepository(session).get_or_create(str(tmp_path))
            project_id = project.id

        with session_factory() as session:
            assert session.get(Project, project_id) is not None
