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

import json
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
from ..storage.repositories import (
    DecisionRepository,
    GrantRepository,
    IdempotencyRepository,
    ProjectRepository,
    StoredResponse,
    fingerprint_request,
)
from .errors import (
    AlreadyAnswered,
    DecisionNotFound,
    IdempotencyConflict,
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
    replayed: bool = False

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
        idempotency_key: str | None = None,
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
            root = project.root

            # Scoped to the authenticated identity, which in this service is
            # ``actor`` -- the router fills it from the credential and never from
            # the request body. Without authentication every caller is the same
            # ``anonymous``, so they share one namespace; that is consistent with
            # a deployment where they already share every other permission.
            key_owner = actor or "anonymous"
            keys = IdempotencyRepository(session) if idempotency_key else None
            fingerprint: str | None = None
            if keys is not None and idempotency_key is not None:
                # Fingerprinted on the *resolved* root, so `proj` and `./proj/`
                # are the same call rather than two spellings of it -- a key that
                # only matched an exact string would miss the retry it exists
                # for, because a retry is usually rebuilt from other code.
                fingerprint = fingerprint_request(
                    project_root=root,
                    tool=tool,
                    arguments=arguments,
                    mode=resolved_mode.value,
                )
                previous = keys.find(client=key_owner, key=idempotency_key)
                if previous is not None:
                    # Returned before the decision is evaluated and before any
                    # metric counts one, because no decision happened. Counting
                    # a replay as a decision would make a client's retry budget
                    # look like traffic.
                    return self._replay(previous, fingerprint=fingerprint)

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

            result = DecisionResult(
                decision_id=decision_id,
                verdict=decision.verdict,
                rule=decision.rule.value,
                reason=decision.reason,
                scope=decision.scope,
                latency_us=latency_us,
                project_root=root,
            )

            if keys is not None and idempotency_key is not None and fingerprint is not None:
                # Written in the same transaction as the audit row, so the two
                # cannot disagree: a committed key always names a committed
                # decision, and a replay that finds no key is a replay of a call
                # whose transaction rolled back -- the one case where deciding
                # again is the right answer.
                stored, created = keys.record(
                    client=key_owner,
                    key=idempotency_key,
                    fingerprint=fingerprint,
                    response=_dump_result(result),
                )
                if not created:
                    # A concurrent request with this key won. ``record`` rolled
                    # this transaction back, which also discarded the audit row
                    # written above -- deliberately, or a retried call would
                    # appear in the trail twice. The winner's response is what
                    # the caller gets.
                    return self._replay(stored, fingerprint=fingerprint)

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

        return result

    @staticmethod
    def _replay(stored: StoredResponse, *, fingerprint: str) -> DecisionResult:
        """The response a previous call with this key produced.

        Raises ``IdempotencyConflict`` if the key was used for a different
        request, and treats an unreadable snapshot the same way rather than as a
        500: both mean "this key cannot answer the question being asked", and the
        caller can act on that by using a new key. Returning the first call's
        verdict for a different call would decide something nobody evaluated.
        """
        if stored.fingerprint != fingerprint:
            raise IdempotencyConflict(
                "this Idempotency-Key was already used for a different request",
                details={"reason": "the request does not match the one that used this key"},
            )
        try:
            payload = json.loads(stored.response)
            return DecisionResult(
                decision_id=payload["decision_id"],
                verdict=Verdict(payload["verdict"]),
                rule=payload["rule"],
                reason=payload["reason"],
                scope=payload["scope"],
                latency_us=payload["latency_us"],
                project_root=payload["project_root"],
                replayed=True,
            )
        except (ValueError, KeyError, TypeError) as exc:
            raise IdempotencyConflict(
                "the stored response for this Idempotency-Key could not be read",
                details={"reason": str(exc)},
            ) from exc

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
    return json.dumps(arguments, sort_keys=True, default=str)


def _dump_result(result: DecisionResult) -> str:
    """A decision, in a form a replay can rebuild.

    ``verdict`` and ``rule`` are stored as their string values rather than as
    the enum objects, because this goes into a text column and comes back as
    JSON: writing an enum name would work and then break the day one of them is
    renamed, with the failure landing on whoever replays an old key.
    """
    return json.dumps(
        {
            "decision_id": result.decision_id,
            "verdict": result.verdict.value,
            "rule": result.rule,
            "reason": result.reason,
            "scope": result.scope,
            "latency_us": result.latency_us,
            "project_root": result.project_root,
        },
        sort_keys=True,
    )


def _rule_of(row: Any) -> Rule:
    try:
        return Rule(row.rule)
    except ValueError:  # a rule that was renamed after the row was written
        return Rule.UNRECOGNISED
