"""Grant administration and audit reads.

Two services in one module because they are two halves of the same promise. A
grant a user cannot see is a grant they cannot judge, and an audit trail nobody
can read is not a trail -- so the operations that *write* standing authority and
the ones that *read* what authority was exercised are kept next to each other,
and every write invalidates the cache in the same call.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from ..config import Settings
from ..observability.metrics import MetricsSink, NullMetrics
from ..storage.cache import GrantCache, NullGrantCache
from ..storage.keys import find_project_root, is_within
from ..storage.repositories import DecisionRepository, GrantRepository, ProjectRepository
from .errors import ProjectNotFound


@dataclass(frozen=True, slots=True)
class GrantListing:
    """A project's grants, keyed by the root the service resolved.

    ``project_root`` is the **resolved** root, not the string the caller sent.
    Echoing the input back looked harmless and was not: ``POST /v1/decisions``
    answers with the resolved root, so a client that learned its project
    identity from one endpoint and handed it to another got two different
    answers for the same workspace -- ``C:\\Users\\me\\proj`` from one and
    ``C:/Users/me/proj`` from the other. Exactly one of them is canonical, and
    it has to be the same one everywhere.
    """

    project_root: str
    grants: list[GrantView]


@dataclass(frozen=True, slots=True)
class RevokeResult:
    project_root: str
    """Resolved, for the same reason as :class:`GrantListing`."""

    key: str | None
    removed: int


@dataclass(frozen=True, slots=True)
class GrantCreated:
    project_root: str
    """Resolved, for the same reason as :class:`GrantListing`."""

    grant: GrantView
    created: bool
    """False when an identical grant was already there. The write is idempotent,
    so a replay reports ``False`` rather than failing or duplicating."""


@dataclass(frozen=True, slots=True)
class GrantView:
    key: str
    tool: str
    scope: str | None
    granted_at: datetime
    granted_by: str | None
    note: str | None

    @property
    def strength(self) -> str:
        """Whether this grant survives a flagged call.

        Surfaced in the API because the difference is invisible from the key
        alone, and it is the single most consequential thing about a grant.
        ``bash`` looks narrower than ``bash:git push`` in a list sorted
        alphabetically, and it authorises strictly less.
        """
        return "narrow (covers flagged calls)" if self.scope else "broad (unflagged calls only)"


@dataclass(frozen=True, slots=True)
class AuditView:
    decision_id: str
    occurred_at: datetime
    tool: str
    verdict: str
    rule: str
    reason: str | None
    scope: str | None
    run_mode: str
    latency_us: int
    actor: str | None
    answer: str | None
    granted_key: str | None
    arguments: dict[str, Any] | None
    arguments_digest: str


class GrantService:
    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        cache: GrantCache | None = None,
        metrics: MetricsSink | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._cache: GrantCache = cache or NullGrantCache()
        self._metrics: MetricsSink = metrics or NullMetrics()

    def list_for_project(self, project_root: str) -> GrantListing:
        # Resolved before the lookup, and outside it, so the response carries
        # the same root the decision endpoint would report -- including for a
        # workspace the gateway has never seen, which has no row to read it from.
        resolved = find_project_root(project_root)

        session = self._session_factory()
        try:
            project = ProjectRepository(session).get_by_root(resolved)
            # An unknown project is not an error here: it simply has no grants.
            # Returning 200 with an empty list is what makes this endpoint safe
            # to poll for a workspace that has not made a request yet.
            if project is None:
                return GrantListing(project_root=resolved, grants=[])
            rows = GrantRepository(session).list_for_project(project.id)
            return GrantListing(
                project_root=resolved,
                grants=[
                    GrantView(
                        key=row.key,
                        tool=row.tool,
                        scope=row.scope or None,
                        granted_at=row.granted_at,
                        granted_by=row.granted_by,
                        note=row.note,
                    )
                    for row in rows
                ],
            )
        finally:
            session.close()

    def create(
        self,
        *,
        project_root: str,
        tool: str,
        scope: str | None = None,
        actor: str | None = None,
        note: str | None = None,
    ) -> GrantCreated:
        """Write a standing grant directly.

        Idempotent: the second identical call reports ``created=False`` and
        returns the same grant rather than duplicating it or failing. An
        operator replaying a provisioning script must not end up with two rows.
        """
        resolved = find_project_root(project_root)
        session = self._session_factory()
        try:
            project = ProjectRepository(session).get_or_create(resolved)
            row, created = GrantRepository(session).add(
                project_id=project.id,
                tool=tool,
                scope=scope or "",
                granted_by=actor,
                note=note,
            )
            view = GrantView(
                key=row.key,
                tool=row.tool,
                scope=row.scope or None,
                granted_at=row.granted_at,
                granted_by=row.granted_by,
                note=row.note,
            )
            project_id = project.id
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        self._cache.invalidate(project_id)
        self._metrics.cache(event="invalidation")
        self._metrics.grant(action="created" if created else "unchanged")
        return GrantCreated(project_root=resolved, grant=view, created=created)

    def revoke(self, *, project_root: str, key: str) -> RevokeResult:
        resolved = find_project_root(project_root)
        session = self._session_factory()
        try:
            project = ProjectRepository(session).get_by_root(resolved)
            if project is None:
                raise ProjectNotFound(f"no project at {resolved}")
            removed = GrantRepository(session).revoke(project_id=project.id, key=key)
            project_id = project.id
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        # Invalidate whether or not a row went away. A revoke that matched
        # nothing still means the caller believed something was there, and
        # serving the cached set would tell them it still is.
        self._cache.invalidate(project_id)
        self._metrics.cache(event="invalidation")
        if removed:
            self._metrics.grant(action="revoked")
        return RevokeResult(project_root=resolved, key=key, removed=1 if removed else 0)

    def clear(self, *, project_root: str) -> RevokeResult:
        resolved = find_project_root(project_root)
        session = self._session_factory()
        try:
            project = ProjectRepository(session).get_by_root(resolved)
            if project is None:
                raise ProjectNotFound(f"no project at {resolved}")
            dropped = GrantRepository(session).clear(project_id=project.id)
            project_id = project.id
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        self._cache.invalidate(project_id)
        self._metrics.cache(event="invalidation")
        if dropped:
            self._metrics.grant(action="cleared")
        return RevokeResult(project_root=resolved, key=None, removed=dropped)


class AuditService:
    def __init__(self, *, session_factory: sessionmaker[Session], settings: Settings) -> None:
        self._session_factory = session_factory
        self._settings = settings

    def recent(
        self,
        *,
        project_root: str | None = None,
        visible_prefixes: tuple[str, ...] | None = None,
        limit: int = 50,
        verdict: str | None = None,
    ) -> Sequence[AuditView]:
        """Decisions, narrowed to what the caller is allowed to read.

        ``project_root`` is a single workspace the caller asked for; the router
        has already checked it is one they may name. ``visible_prefixes`` is the
        allowlist to apply when they did not ask -- and it is **not** optional
        cosmetics: without it, a request that simply omits ``project_root``
        would return every tenant's audit trail, which is a worse bug than the
        unauthenticated one it sits behind.

        Filtering happens here rather than in SQL because the rule is
        component-wise path containment, which is exactly the thing a ``LIKE``
        gets subtly wrong (``/srv/app`` matching ``/srv/app-2``). The cost is
        reading the project table and comparing in Python; workspaces number in
        the tens while decisions number in the millions, so it is the right side
        of that trade.
        """
        session = self._session_factory()
        try:
            projects = ProjectRepository(session)
            project_id: int | None = None
            project_ids: Sequence[int] | None = None

            if project_root is not None:
                project = projects.get_by_root(project_root)
                if project is None:
                    return []
                project_id = project.id
            elif visible_prefixes is not None:
                project_ids = [
                    candidate.id
                    for candidate in projects.all()
                    if any(is_within(candidate.root, prefix) for prefix in visible_prefixes)
                ]

            rows = DecisionRepository(session).recent(
                project_id=project_id,
                project_ids=project_ids,
                limit=limit,
                verdict=verdict,
            )
            return [
                AuditView(
                    decision_id=row.id,
                    occurred_at=row.occurred_at,
                    tool=row.tool,
                    verdict=row.verdict,
                    rule=row.rule,
                    reason=row.reason,
                    scope=row.scope,
                    run_mode=row.run_mode,
                    latency_us=row.latency_us,
                    actor=row.actor,
                    answer=row.answer,
                    granted_key=row.granted_key,
                    arguments=_load_json(row.arguments),
                    arguments_digest=row.arguments_digest,
                )
                for row in rows
            ]
        finally:
            session.close()


def _load_json(raw: str | None) -> dict[str, Any] | None:
    if raw is None:
        return None
    import json

    try:
        loaded = json.loads(raw)
    except ValueError:
        return None
    return loaded if isinstance(loaded, dict) else None
