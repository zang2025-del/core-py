"""Repositories: every SQL statement in the service lives here.

Nothing above this layer imports SQLAlchemy. That is not ceremony -- it is what
lets ``services/`` be tested against an in-memory seam, and it is what makes
"which transaction is this write in?" a question with a local answer.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, cast

from sqlalchemy import CursorResult, delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .keys import find_project_root, project_key
from .models import Decision, Grant, Project


def digest_arguments(arguments: Mapping[str, Any]) -> str:
    """Stable SHA-256 over the arguments.

    Sorted keys and no whitespace, so two calls that differ only in how they
    were serialised hash the same -- otherwise the digest would be a transcript
    of the JSON encoder rather than a fingerprint of the call.
    """
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ProjectRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get_or_create(self, root: str) -> Project:
        """Resolve a project root to a row, creating it on first contact.

        The ``IntegrityError`` retry is not defensive noise. Two requests for a
        project nobody has seen before can arrive together, both find nothing,
        and both try to insert; the unique constraint picks a winner and the
        loser re-reads. Doing the read-then-write without this would make the
        first request from a new workspace a race.
        """
        # find_project_root, not normalise_root: a request from
        # `proj/src/deep/` has to resolve to `proj/`, or the grant made in the
        # project root does not cover the run happening two directories down.
        normalised = find_project_root(root)
        existing = self._session.scalar(select(Project).where(Project.root == normalised))
        if existing is not None:
            return existing

        project = Project(root=normalised, key=project_key(normalised))
        self._session.add(project)
        try:
            self._session.flush()
        except IntegrityError:
            self._session.rollback()
            return self._session.scalars(select(Project).where(Project.root == normalised)).one()
        return project

    def get_by_root(self, root: str) -> Project | None:
        """Look a project up the same way it was created.

        ``find_project_root`` rather than ``normalise_root``, for the same reason
        ``get_or_create`` uses it: a revoke issued from ``proj/src/`` has to
        reach the project registered at ``proj/``. Looking up with a different
        rule than the one used to store is how a caller ends up told their
        workspace does not exist.
        """
        return self._session.scalar(select(Project).where(Project.root == find_project_root(root)))

    def all(self) -> Sequence[Project]:
        return self._session.scalars(select(Project).order_by(Project.root)).all()


class GrantRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def keys_for_project(self, project_id: int) -> frozenset[str]:
        """Every standing grant for a project, in the engine's key form.

        One query, no join, no ORM object construction: this runs on the hot
        path of every decision, and the cache in front of it exists precisely
        because this is the only expensive thing ``decide()`` waits for.
        """
        rows = self._session.execute(
            select(Grant.tool, Grant.scope).where(Grant.project_id == project_id)
        ).all()
        return frozenset(tool if not scope else f"{tool}:{scope}" for tool, scope in rows)

    def list_for_project(self, project_id: int) -> Sequence[Grant]:
        return self._session.scalars(
            select(Grant).where(Grant.project_id == project_id).order_by(Grant.tool, Grant.scope)
        ).all()

    def add(
        self,
        *,
        project_id: int,
        tool: str,
        scope: str = "",
        granted_by: str | None = None,
        note: str | None = None,
    ) -> tuple[Grant, bool]:
        """Record a grant. Returns ``(grant, created)``.

        Idempotent by construction: clicking "always allow" twice, or replaying
        a request after a timeout, must not produce two rows -- and must not
        fail either. The unique constraint decides, and the loser of the race
        returns the row that won.
        """
        existing = self._session.scalar(
            select(Grant).where(
                Grant.project_id == project_id,
                Grant.tool == tool,
                Grant.scope == scope,
            )
        )
        if existing is not None:
            return existing, False

        grant = Grant(
            project_id=project_id, tool=tool, scope=scope, granted_by=granted_by, note=note
        )
        self._session.add(grant)
        try:
            self._session.flush()
        except IntegrityError:
            self._session.rollback()
            winner = self._session.scalars(
                select(Grant).where(
                    Grant.project_id == project_id,
                    Grant.tool == tool,
                    Grant.scope == scope,
                )
            ).one()
            return winner, False
        return grant, True

    def revoke(self, *, project_id: int, key: str) -> bool:
        """Drop one grant by its engine key. True if a row went away."""
        tool, separator, scope = key.partition(":")
        # The parentheses are load-bearing. `Grant.scope == scope if separator
        # else ""` binds as `(Grant.scope == scope) if separator else ""`, which
        # hands an empty string to where() and raises at query build time -- a
        # precedence slip that only bites for tool-level keys, i.e. the most
        # common revoke there is.
        matches = Grant.scope == (scope if separator else "")
        result = cast(
            "CursorResult[Any]",
            self._session.execute(
                delete(Grant).where(Grant.project_id == project_id, Grant.tool == tool, matches)
            ),
        )
        return bool(result.rowcount)

    def clear(self, *, project_id: int) -> int:
        result = cast(
            "CursorResult[Any]",
            self._session.execute(delete(Grant).where(Grant.project_id == project_id)),
        )
        return int(result.rowcount or 0)

    def count_for_project(self, project_id: int) -> int:
        return int(
            self._session.scalar(
                select(func.count()).select_from(Grant).where(Grant.project_id == project_id)
            )
            or 0
        )


class DecisionRepository:
    """The audit trail. Insert-only apart from the answer columns."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def record(
        self,
        *,
        decision_id: str,
        project_id: int,
        tool: str,
        arguments: Mapping[str, Any],
        arguments_json: str | None,
        verdict: str,
        rule: str,
        reason: str | None,
        scope: str | None,
        run_mode: str,
        latency_us: int,
        actor: str | None,
        request_id: str | None,
    ) -> Decision:
        row = Decision(
            id=decision_id,
            project_id=project_id,
            tool=tool,
            arguments=arguments_json,
            arguments_digest=digest_arguments(arguments),
            verdict=verdict,
            rule=rule,
            reason=reason,
            scope=scope,
            run_mode=run_mode,
            latency_us=latency_us,
            actor=actor,
            request_id=request_id,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def get(self, decision_id: str) -> Decision | None:
        return self._session.get(Decision, decision_id)

    def answer(
        self,
        *,
        decision_id: str,
        answer: str,
        actor: str | None,
        granted_key: str | None,
    ) -> Decision | None:
        """Attach a human's answer to the decision that raised the prompt.

        Refuses to overwrite an existing answer, so a replayed request cannot
        silently rewrite what a person decided.
        """
        row = self._session.get(Decision, decision_id)
        if row is None or row.answer is not None:
            return None
        row.answer = answer
        row.answered_at = datetime.now(timezone.utc)
        row.answer_actor = actor
        row.granted_key = granted_key
        self._session.flush()
        return row

    def recent(
        self,
        *,
        project_id: int | None = None,
        limit: int = 50,
        verdict: str | None = None,
    ) -> Sequence[Decision]:
        statement = select(Decision).order_by(Decision.occurred_at.desc(), Decision.id.desc())
        if project_id is not None:
            statement = statement.where(Decision.project_id == project_id)
        if verdict is not None:
            statement = statement.where(Decision.verdict == verdict)
        return self._session.scalars(statement.limit(limit)).all()
