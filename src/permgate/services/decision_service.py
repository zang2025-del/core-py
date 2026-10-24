"""The decision service: one request, one transaction, one audit row.

The whole request path in one place, because the ordering is the contract:

    1. resolve the project                 (read)
    2. load its grant set                  (read, cached)
    3. decide                              (pure, no IO)
    4. write the audit row                 (write)
    5. commit
    6. update the cache and the metrics    (after the commit, never before)

Step 6 being after step 5 is the part worth being careful about. Invalidating
the cache before the commit opens a window in which a concurrent request
re-reads the pre-commit grant set and caches it with a fresh TTL -- so the write
lands and the cache never learns about it. The metrics have the same shape for a
different reason: counting a decision that a rollback then erased makes the
dashboards lie in exactly the situation where someone is reading them.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from ..config import Settings
from ..domain.decision import Decision, Rule, RunMode, Verdict
from ..domain.engine import GrantSet, PolicyProfile, decide, grant_for_answer
from ..domain.policies import DEFAULT_REGISTRY, PolicyRegistry
from ..observability.metrics import MetricsSink, NullMetrics
from ..storage.cache import GrantCache, NullGrantCache
from ..storage.repositories import DecisionRepository, GrantRepository, ProjectRepository
from .errors import (
    AlreadyAnswered,
    DecisionNotFound,
    InvalidAnswer,
    ModeNotAllowed,
)

VALID_ANSWERS = frozenset({"once", "always", "scoped", "deny"})


@dataclass(frozen=True, slots=True)
class DecisionResult:
    """What the API hands back. Plain data: the HTTP layer owns serialisation."""

    decision_id: str
    verdict: Verdict
    rule: str
    reason: str | None
    scope: str | None
    latency_us: int
    project_root: str

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW


@dataclass(frozen=True, slots=True)
class AnswerResult:
    decision_id: str
    answer: str
    granted_key: str | None
    grant_created: bool


class DecisionService:
    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        settings: Settings,
        cache: GrantCache | None = None,
        registry: PolicyRegistry = DEFAULT_REGISTRY,
        metrics: MetricsSink | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._settings = settings
        self._cache: GrantCache = cache or NullGrantCache()
        self._registry = registry
        self._metrics: MetricsSink = metrics or NullMetrics()

    # ---------------------------------------------------------------- read

    def _grant_set(self, session: Session, project_id: int) -> GrantSet:
        """Grants for a project, from the cache when it has them.

        A miss is not an error -- it is the expected first request for a
        project, and the metric distinguishes the two so a permanently cold
        cache is visible.
        """
        cached = self._cache.get(project_id)
        if cached is not None:
            self._metrics.cache(event="hit")
            return cached

        self._metrics.cache(event="miss")
        grants = GrantSet(GrantRepository(session).keys_for_project(project_id))
        self._cache.put(project_id, grants)
        return grants

    # ------------------------------------------------------------- decide

    def evaluate(
        self,
        *,
        project_root: str,
        tool: str,
        arguments: Mapping[str, Any],
        mode: RunMode | None = None,
        actor: str | None = None,
        request_id: str | None = None,
    ) -> DecisionResult:
        resolved_mode = mode or self._settings.default_run_mode
        if resolved_mode is RunMode.BYPASS and not self._settings.allow_bypass_mode:
            # Refused before the transaction opens: nothing to roll back, no
            # audit row for a request that never ran, and no chance of the
            # engine's first branch being reachable by accident.
            raise ModeNotAllowed(
                "bypass mode is not enabled on this deployment",
                details={"mode": resolved_mode.value},
            )

        profile = PolicyProfile(
            mode=resolved_mode,
            preapproved_scopes=self._settings.preapproved_scope_set,
        )

        started = time.perf_counter()
        session = self._session_factory()
        try:
            projects = ProjectRepository(session)
            project = projects.get_or_create(project_root)
            grants = self._grant_set(session, project.id)

            decision = decide(
                tool=tool,
                arguments=arguments,
                grants=grants,
                profile=profile,
                registry=self._registry,
            )

            latency_us = int((time.perf_counter() - started) * 1_000_000)
            decision_id = str(uuid.uuid4())

            if self._settings.audit_enabled:
                DecisionRepository(session).record(
                    decision_id=decision_id,
                    project_id=project.id,
                    tool=tool,
                    arguments=arguments,
                    arguments_json=(
                        _dump(arguments) if self._settings.audit_store_arguments else None
                    ),
                    verdict=decision.verdict.value,
                    rule=decision.rule.value,
                    reason=decision.reason,
                    scope=decision.scope,
                    run_mode=resolved_mode.value,
                    latency_us=latency_us,
                    actor=actor,
                    request_id=request_id,
                )

            root = project.root
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        elapsed = time.perf_counter() - started
        self._metrics.decision(
            verdict=decision.verdict.value,
            rule=decision.rule.value,
            tool=tool,
            latency_seconds=elapsed,
        )

        return DecisionResult(
            decision_id=decision_id,
            verdict=decision.verdict,
            rule=decision.rule.value,
            reason=decision.reason,
            scope=decision.scope,
            latency_us=latency_us,
            project_root=root,
        )

    # ------------------------------------------------------------- answer

    def answer(
        self,
        *,
        decision_id: str,
        answer: str,
        actor: str | None = None,
    ) -> AnswerResult:
        """Record what a human decided about a prompt.

        This is where the security model's asymmetry is enforced, and it is
        enforced by ``grant_for_answer`` rather than by a check here -- there is
        one place that decides which grant an answer produces, and it is the
        same function the offline evaluation uses. A second implementation here
        would be a second thing to keep in sync, and the divergence would be a
        silent widening of what an "always" click authorises.
        """
        if answer not in VALID_ANSWERS:
            raise InvalidAnswer(
                f"answer must be one of {sorted(VALID_ANSWERS)}", details={"answer": answer}
            )

        session = self._session_factory()
        try:
            decisions = DecisionRepository(session)
            row = decisions.get(decision_id)
            if row is None:
                raise DecisionNotFound(f"no decision {decision_id}")
            if row.answer is not None:
                raise AlreadyAnswered(
                    f"decision {decision_id} was already answered as {row.answer!r}"
                )

            decision = Decision(
                verdict=Verdict(row.verdict),
                rule=_rule_of(row),
                reason=row.reason,
                scope=row.scope,
            )

            granted_key: str | None = None
            created = False
            if answer in ("always", "scoped"):
                grant = grant_for_answer(answer, decision, row.tool)
                if grant is not None:
                    _, created = GrantRepository(session).add(
                        project_id=row.project_id,
                        tool=grant.tool,
                        scope=grant.scope or "",
                        granted_by=actor,
                        note=f"answer to decision {decision_id}",
                    )
                    granted_key = grant.key

            # The conditional UPDATE is the only atomic step in this method, so
            # it is also the only thing that can be trusted to pick a winner.
            # The read at the top gives the two distinct rejections -- 404 for a
            # decision that never existed, 409 for one already answered -- but it
            # cannot be the gate: two requests both read "unanswered" before
            # either writes. Raising here rolls the grant back too, so a loser
            # leaves no trace of having tried.
            won = decisions.answer(
                decision_id=decision_id,
                answer=answer,
                actor=actor,
                granted_key=granted_key,
            )
            if not won:
                raise AlreadyAnswered(f"decision {decision_id} was answered by another request")
            project_id = row.project_id
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

        # After the commit. See the module docstring for why.
        self._cache.invalidate(project_id)
        self._metrics.cache(event="invalidation")

        if granted_key is not None:
            self._metrics.grant(action="created" if created else "unchanged")

        return AnswerResult(
            decision_id=decision_id,
            answer=answer,
            granted_key=granted_key,
            grant_created=created,
        )

    def invalidate_project_cache(self, project_id: int) -> None:
        """Used by the grant endpoints after a revoke. Public so the API layer
        cannot forget it -- every grant write goes through one of these."""
        self._cache.invalidate(project_id)
        self._metrics.cache(event="invalidation")


def _dump(arguments: Mapping[str, Any]) -> str:
    import json

    return json.dumps(arguments, sort_keys=True, default=str)


def _rule_of(row: Any) -> Rule:
    try:
        return Rule(row.rule)
    except ValueError:  # a rule that was renamed after the row was written
        return Rule.UNRECOGNISED
