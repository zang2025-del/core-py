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

from sqlalchemy import CursorResult, delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .keys import find_project_root, normalise_root, project_key
from .models import Client, ClientRoot, Decision, Grant, Project, utcnow


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
    ) -> bool:
        """Attach a human's answer to the decision that raised the prompt.

        Returns whether this call is the one that wrote the answer. ``False``
        means the row does not exist, or somebody else answered it first -- the
        caller distinguishes the two, because a missing decision is a 404 and a
        lost race is a 409.

        **The write decides, not the read.** The obvious version of this method
        reads the row, checks that ``answer`` is still null, and assigns -- and
        that version loses simultaneous answers. Two requests both read null,
        both pass the check, and the second silently overwrites what a person
        decided. A row lock is the usual fix and it is the wrong one here:
        SQLAlchemy compiles ``SELECT ... FOR UPDATE`` into nothing at all on
        SQLite, so the lock would exist in CI and not in the default deployment.
        A conditional UPDATE has the same meaning on both backends -- the
        database compares and swaps in one statement, and ``rowcount`` says who
        won.
        """
        result = cast(
            "CursorResult[Any]",
            self._session.execute(
                update(Decision)
                .where(Decision.id == decision_id, Decision.answer.is_(None))
                .values(
                    answer=answer,
                    answered_at=datetime.now(timezone.utc),
                    answer_actor=actor,
                    granted_key=granted_key,
                )
                # The ORM holds no copy of this row worth synchronising, and
                # asking it to update one it may not have loaded is a source of
                # surprises rather than of correctness.
                .execution_options(synchronize_session=False)
            ),
        )
        return bool(result.rowcount)

    def recent(
        self,
        *,
        project_id: int | None = None,
        project_ids: Sequence[int] | None = None,
        limit: int = 50,
        verdict: str | None = None,
    ) -> Sequence[Decision]:
        """Recent rows, optionally narrowed to one project or to a set of them.

        ``project_ids`` exists for the caller-scoped audit read. When a caller
        omits ``project_root`` it must still see only its own workspaces, and
        the answer to "which ones" is a set rather than a single id. Passing an
        empty sequence returns nothing rather than everything -- a caller
        allowed to name no workspace is not the same as a caller allowed to name
        all of them, and the two are one falsy check apart.
        """
        statement = select(Decision).order_by(Decision.occurred_at.desc(), Decision.id.desc())
        if project_id is not None:
            statement = statement.where(Decision.project_id == project_id)
        elif project_ids is not None:
            if not project_ids:
                return []
            statement = statement.where(Decision.project_id.in_(project_ids))
        if verdict is not None:
            statement = statement.where(Decision.verdict == verdict)
        return self._session.scalars(statement.limit(limit)).all()

    def project_root_for(self, decision_id: str) -> str | None:
        """The workspace a decision belongs to, or ``None`` if there is no such row.

        The answer endpoint takes no ``project_root``: the client is answering a
        prompt it was shown, and the only safe way to authorise that is to ask
        which workspace the prompt belongs to rather than to trust a second
        field the caller supplies. Callers use this to make that check before
        the answer is written, not after.
        """
        return self._session.scalar(
            select(Project.root)
            .join(Decision, Decision.project_id == Project.id)
            .where(Decision.id == decision_id)
        )


class ClientRepository:
    """Who may call the service, and which workspaces each caller may name.

    Two questions, kept apart on purpose: ``find_active_by_token_hash`` answers
    "is this caller who it claims to be" and ``roots_for`` answers "may it name
    that workspace". Collapsing them is how a token that should only read one
    project becomes one that writes to all of them.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def find_active_by_token_hash(self, token_hash: str) -> Client | None:
        """A live client for this token digest. Revoked rows never match.

        Lookup is on the digest rather than by fetching every client and
        comparing tokens in constant time: the digest is what the database
        indexes, and an attacker who cannot invert the hash learns nothing
        useful from how long a lookup against a B-tree took.
        """
        return self._session.scalar(
            select(Client).where(
                Client.token_hash == token_hash,
                Client.revoked_at.is_(None),
            )
        )

    def roots_for(self, client_id: int) -> tuple[str, ...]:
        rows = self._session.scalars(
            select(ClientRoot.prefix)
            .where(ClientRoot.client_id == client_id)
            .order_by(ClientRoot.prefix)
        ).all()
        return tuple(rows)

    def find_by_name(self, name: str) -> Client | None:
        return self._session.scalar(select(Client).where(Client.name == name))

    def upsert(self, *, name: str, token_hash: str, roots: Sequence[str]) -> tuple[Client, bool]:
        """Create or update a client. Returns ``(client, created)``.

        Used by the startup bootstrap path and by tests. Updating replaces the
        whole allowlist rather than merging it, because a bootstrap that only
        ever added roots would make removing one impossible -- and an allowlist
        you cannot shrink is not an allowlist.
        """
        client = self.find_by_name(name)
        created = client is None
        normalised = sorted({normalise_root(root) for root in roots})

        if client is None:
            client = Client(name=name, token_hash=token_hash)
            self._session.add(client)
            self._session.flush()
        else:
            client.token_hash = token_hash
            # Re-running bootstrap after a revoke has to bring the client back,
            # otherwise the only way out of a mistaken revoke is a manual delete.
            client.revoked_at = None
            for existing in list(client.roots):
                self._session.delete(existing)
            self._session.flush()

        for prefix in normalised:
            self._session.add(ClientRoot(client_id=client.id, prefix=prefix))
        self._session.flush()
        return client, created

    def revoke(self, name: str) -> bool:
        """Turn a client off, keeping the row. True if this call did it."""
        client = self.find_by_name(name)
        if client is None or client.revoked_at is not None:
            return False
        client.revoked_at = utcnow()
        self._session.flush()
        return True

    def all(self) -> Sequence[Client]:
        return self._session.scalars(select(Client).order_by(Client.name)).all()

    def count_active(self) -> int:
        return int(
            self._session.scalar(
                select(func.count()).select_from(Client).where(Client.revoked_at.is_(None))
            )
            or 0
        )
