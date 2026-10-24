"""Repositories: every SQL statement in the service lives here.

Nothing above this layer imports SQLAlchemy. That is not ceremony -- it is what
lets ``services/`` be tested against an in-memory seam, and it is what makes
"which transaction is this write in?" a question with a local answer.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast

from sqlalchemy import CursorResult, and_, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .keys import find_project_root, normalise_root, project_key
from .models import (
    Client,
    ClientRoot,
    Decision,
    Grant,
    IdempotencyKey,
    Project,
    as_utc,
    utcnow,
)
from .redaction import redact_arguments


def encode_cursor(occurred_at: datetime, decision_id: str) -> str:
    """The position of one audit row, in a form a client can hold and hand back.

    Opaque by intent, not by encryption: it is base64 of the sort key, so a
    client that decodes it learns ``(occurred_at, id)`` -- which it was already
    shown in the entry the cursor came from. It is not documented as a stable
    format because it is one sort-key change away from being a different format,
    and a client should carry it rather than build one.
    """
    raw = f"{occurred_at.isoformat()}|{decision_id}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    """Inverse of :func:`encode_cursor`, raising ``ValueError`` on anything else.

    Raises rather than returning ``None`` so the caller cannot forget: a cursor
    that silently decoded to nothing would read as "the beginning of the trail",
    which is the one wrong answer a paging read must never give -- it would look
    like a client looping forever rather than like a bad request.
    """
    # Padding is restored rather than required: `=` is awkward in a query string
    # and in a shell, so it is stripped on the way out and put back here.
    padded = cursor + "=" * (-len(cursor) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, UnicodeEncodeError) as exc:
        raise ValueError(f"not valid base64: {exc}") from exc
    stamp, separator, decision_id = raw.partition("|")
    if not separator or not decision_id:
        raise ValueError("missing the separator or the decision id")
    try:
        occurred_at = datetime.fromisoformat(stamp)
    except ValueError as exc:
        raise ValueError(f"does not carry a timestamp: {exc}") from exc
    if occurred_at.tzinfo is None:
        # A naive timestamp would compare against stored values that are always
        # UTC and be silently wrong by the machine's offset, which shifts which
        # rows a page returns rather than failing.
        raise ValueError("its timestamp has no timezone")
    # Normalised to UTC before it reaches the query: SQLite compares timestamps
    # as text, so a cursor in another offset would compare by its written digits
    # rather than by the instant they denote.
    return as_utc(occurred_at), decision_id


@dataclass(frozen=True, slots=True)
class StoredResponse:
    """A key's fingerprint and the response it produced.

    A plain value rather than the ORM row, so the service layer can hold it
    after the session that read it is closed -- which is exactly what happens
    when a replay returns early.
    """

    fingerprint: str
    response: str


def fingerprint_request(
    *,
    project_root: str,
    tool: str,
    arguments: Mapping[str, Any],
    mode: str | None,
) -> str:
    """What the call asked for, as one hash.

    Only the request goes in, never the identity: the key is already scoped per
    caller, and folding the caller in twice would make a key legitimately
    replayed by the same client after a token rotation look like a different
    call. ``mode`` is included because the same call in a different run mode is
    a different decision.
    """
    return digest_arguments(
        {"project_root": project_root, "tool": tool, "arguments": arguments, "mode": mode}
    )


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
        """Write one audit row.

        Redaction happens here rather than at the call site on purpose: this is
        the only statement in the service that writes ``decisions``, so putting
        it here makes "can a credential reach this table?" a question with one
        place to look, rather than a property of every caller remembering.
        """
        stored, redacted = redact_arguments(arguments, arguments_json)
        row = Decision(
            id=decision_id,
            project_id=project_id,
            tool=tool,
            arguments=stored,
            arguments_redacted=redacted,
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
        cursor: tuple[datetime, str] | None = None,
    ) -> Sequence[Decision]:
        """Recent rows, optionally narrowed to one project or to a set of them.

        ``project_ids`` exists for the caller-scoped audit read. When a caller
        omits ``project_root`` it must still see only its own workspaces, and
        the answer to "which ones" is a set rather than a single id. Passing an
        empty sequence returns nothing rather than everything -- a caller
        allowed to name no workspace is not the same as a caller allowed to name
        all of them, and the two are one falsy check apart.

        ``cursor`` is a *keyset*, not an offset, and the difference is why an
        audit read can be paged at all. ``OFFSET`` makes the server re-count
        every row it already skipped, so page N costs N times page 1; worse, a
        decision recorded between two requests shifts every later page by one,
        which silently repeats a row or drops one. For a trail whose whole value
        is completeness, silently dropping a row is the failure mode to design
        out. Comparing ``(occurred_at, id)`` against the last row of the previous
        page is one index seek, and ``id`` is in the comparison because two
        decisions can share a timestamp -- breaking that tie differently on each
        page is the same repeat-or-skip bug in miniature.
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
        if cursor is not None:
            occurred_at, decision_id = cursor
            statement = statement.where(
                or_(
                    Decision.occurred_at < occurred_at,
                    and_(
                        Decision.occurred_at == occurred_at,
                        Decision.id < decision_id,
                    ),
                )
            )
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


class IdempotencyRepository:
    """A caller's keys, and the responses they already produced."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def find(self, *, client: str, key: str) -> StoredResponse | None:
        row = self._session.scalar(
            select(IdempotencyKey).where(IdempotencyKey.client == client, IdempotencyKey.key == key)
        )
        if row is None:
            return None
        return StoredResponse(fingerprint=row.fingerprint, response=row.response)

    def record(
        self, *, client: str, key: str, fingerprint: str, response: str
    ) -> tuple[StoredResponse, bool]:
        """Store one key and its response. Returns ``(stored, created)``.

        The unique constraint decides a concurrent duplicate rather than a
        read-then-insert, and the loser gets the winner's value back -- the same
        shape as ``GrantRepository.add`` and for the same reason: two requests
        that arrive together both see nothing, and the tie has to be broken by
        the database rather than by which one happens to check second.

        A lost race rolls this transaction back, which also discards whatever
        the caller had written alongside it. That is the point: the losing
        duplicate must not leave a second audit row behind, or a retried call
        would appear in the trail twice and the trail would stop being a record
        of what happened.
        """
        row = IdempotencyKey(client=client, key=key, fingerprint=fingerprint, response=response)
        self._session.add(row)
        try:
            self._session.flush()
        except IntegrityError:
            self._session.rollback()
            winner = self.find(client=client, key=key)
            if winner is None:
                # The constraint fired for a reason this method cannot explain
                # -- a different unique index, or a concurrent delete. Re-raised
                # rather than reported as a duplicate: an unexplained conflict
                # is a bug here, not a fact about the caller's request.
                raise
            return winner, False
        return StoredResponse(fingerprint=fingerprint, response=response), True
