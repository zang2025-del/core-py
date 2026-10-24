"""HTTP routes.

The API is deliberately small. Every endpoint exists because something outside
the service needs it, and the shape of the decision endpoints follows from one
fact: **a prompt is a round trip**. The agent asks, a human answers, and the
service has to remember the question in between -- which is why a decision is a
row with an id rather than a stateless function call.

    POST   /v1/decisions                    evaluate one tool call
    POST   /v1/decisions/{id}/answer        record what the human said
    GET    /v1/grants                       what is currently pre-approved
    POST   /v1/grants                       pre-approve something deliberately
    DELETE /v1/grants/{key}                 withdraw one
    DELETE /v1/grants                       withdraw all, for one project
    GET    /v1/audit                        what was decided, and what ran
    GET    /healthz  /readyz  /metrics      operations
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, Response, status

from ..observability.metrics import PrometheusMetrics
from ..services.errors import ModeNotAllowed
from .deps import Container, get_container
from .schemas import (
    AnswerRequest,
    AnswerResponse,
    AuditEntry,
    AuditListResponse,
    CreateGrantRequest,
    CreateGrantResponse,
    DecisionRequest,
    DecisionResponse,
    GrantListResponse,
    GrantResponse,
    HealthResponse,
    ReadinessResponse,
    RevokeResponse,
)

router = APIRouter()

ProjectRootQuery = Query(
    ...,
    min_length=1,
    max_length=1024,
    description="Path to the workspace. Normalised server-side.",
)


# --------------------------------------------------------------------- policy


@router.post(
    "/v1/decisions",
    response_model=DecisionResponse,
    summary="Evaluate one tool call",
    responses={
        403: {"description": "The requested run mode is not served by this deployment"},
        422: {"description": "Malformed request"},
    },
)
def create_decision(
    payload: DecisionRequest,
    request: Request,
    container: Container = Depends(get_container),
) -> DecisionResponse:
    """Decide whether a tool call may proceed.

    ``ALLOW`` -- run it. ``ASK`` -- stop and get a human, then POST the answer to
    ``/v1/decisions/{id}/answer``. ``DENY`` -- refuse, and hand ``reason`` back
    to the model so it can route around the refusal instead of retrying it.
    """
    if payload.mode is not None and not container.settings.allow_client_supplied_mode:
        # A client that can choose its own run mode can choose BYPASS, which
        # would make the rest of this service decorative. Refused here rather
        # than in the engine so it is impossible to reach that branch by
        # forgetting a check somewhere else.
        raise ModeNotAllowed(
            "this deployment does not accept a client-supplied run mode",
            details={"mode": payload.mode.value},
        )

    result = container.decisions.evaluate(
        project_root=payload.project_root,
        tool=payload.tool,
        arguments=payload.arguments,
        mode=payload.mode,
        actor=payload.actor,
        request_id=getattr(request.state, "request_id", None),
    )
    return DecisionResponse(
        decision_id=result.decision_id,
        verdict=result.verdict,
        rule=result.rule,
        reason=result.reason,
        scope=result.scope,
        latency_us=result.latency_us,
        project_root=result.project_root,
    )


@router.post(
    "/v1/decisions/{decision_id}/answer",
    response_model=AnswerResponse,
    summary="Record what the human decided",
    responses={
        404: {"description": "No such decision"},
        409: {"description": "Already answered"},
        422: {"description": "Unknown answer"},
    },
)
def answer_decision(
    decision_id: str,
    payload: AnswerRequest,
    container: Container = Depends(get_container),
) -> AnswerResponse:
    """Attach the human's answer to the prompt this decision raised.

    The asymmetry of the model shows up here. ``always`` on a call the
    classifier flagged records **nothing** -- agreeing to one destructive
    command says nothing about the next one. The only answer that covers a
    flagged call is ``scoped``, which names the command family explicitly.
    """
    result = container.decisions.answer(
        decision_id=decision_id, answer=payload.answer, actor=payload.actor
    )
    return AnswerResponse(
        decision_id=result.decision_id,
        answer=result.answer,  # type: ignore[arg-type]
        granted_key=result.granted_key,
        grant_created=result.grant_created,
    )


# --------------------------------------------------------------------- grants


@router.get("/v1/grants", response_model=GrantListResponse, summary="List standing grants")
def list_grants(
    project_root: str = ProjectRootQuery,
    container: Container = Depends(get_container),
) -> GrantListResponse:
    listing = container.grants.list_for_project(project_root)
    return GrantListResponse(
        project_root=listing.project_root,
        grants=[
            GrantResponse(
                key=grant.key,
                tool=grant.tool,
                scope=grant.scope,
                strength=grant.strength,
                granted_at=grant.granted_at,
                granted_by=grant.granted_by,
                note=grant.note,
            )
            for grant in listing.grants
        ],
    )


@router.post(
    "/v1/grants",
    response_model=CreateGrantResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Pre-approve something deliberately",
)
def create_grant(
    payload: CreateGrantRequest,
    container: Container = Depends(get_container),
) -> GrantResponse:
    """Write a standing grant without going through a prompt.

    This is the operator's path -- an unattended pipeline that needs a handful
    of command families pre-approved. Supplying ``scope`` produces a *narrow and
    strong* grant that covers flagged calls in that family; omitting it produces
    a *broad and weak* one that does not. The ``strength`` field in the response
    says which one you got, because the key alone does not.
    """
    result = container.grants.create(
        project_root=payload.project_root,
        tool=payload.tool,
        scope=payload.scope,
        actor=payload.actor,
        note=payload.note,
    )
    grant = result.grant
    return CreateGrantResponse(
        project_root=result.project_root,
        created=result.created,
        key=grant.key,
        tool=grant.tool,
        scope=grant.scope,
        strength=grant.strength,
        granted_at=grant.granted_at,
        granted_by=grant.granted_by,
        note=grant.note,
    )


@router.delete("/v1/grants/{key}", response_model=RevokeResponse, summary="Withdraw one grant")
def revoke_grant(
    key: str,
    project_root: str = ProjectRootQuery,
    container: Container = Depends(get_container),
) -> RevokeResponse:
    result = container.grants.revoke(project_root=project_root, key=key)
    return RevokeResponse(project_root=result.project_root, key=result.key, removed=result.removed)


@router.delete("/v1/grants", response_model=RevokeResponse, summary="Withdraw every grant")
def clear_grants(
    project_root: str = ProjectRootQuery,
    container: Container = Depends(get_container),
) -> RevokeResponse:
    result = container.grants.clear(project_root=project_root)
    return RevokeResponse(project_root=result.project_root, key=result.key, removed=result.removed)


# ---------------------------------------------------------------------- audit


@router.get("/v1/audit", response_model=AuditListResponse, summary="Recent decisions")
def list_audit(
    project_root: str | None = Query(default=None, max_length=1024),
    limit: int = Query(default=50, ge=1, le=500),
    verdict: str | None = Query(default=None, pattern="^(allow|ask|deny)$"),
    container: Container = Depends(get_container),
) -> AuditListResponse:
    entries = container.audit.recent(project_root=project_root, limit=limit, verdict=verdict)
    return AuditListResponse(
        entries=[
            AuditEntry(
                decision_id=entry.decision_id,
                occurred_at=entry.occurred_at,
                tool=entry.tool,
                verdict=entry.verdict,
                rule=entry.rule,
                reason=entry.reason,
                scope=entry.scope,
                run_mode=entry.run_mode,
                latency_us=entry.latency_us,
                actor=entry.actor,
                answer=entry.answer,
                granted_key=entry.granted_key,
                arguments=entry.arguments,
                arguments_digest=entry.arguments_digest,
            )
            for entry in entries
        ]
    )


# ----------------------------------------------------------------- operations

ops = APIRouter()


@ops.get("/healthz", response_model=HealthResponse, summary="Liveness")
def healthz() -> HealthResponse:
    """Liveness only: this process is up and serving.

    Deliberately does not touch the database. A liveness probe that fails when
    the database is slow gets the process killed and restarted, which does not
    fix the database and does lose the in-flight work.
    """
    from .. import __version__

    return HealthResponse(status="ok", version=__version__)


@ops.get("/readyz", response_model=ReadinessResponse, summary="Readiness")
def readyz(container: Container = Depends(get_container)) -> ReadinessResponse:
    """Readiness: can this process actually serve a decision?

    This one *does* touch the database, because that is the question. It is
    also where the schema revision is reported -- a process running against a
    database migrated by a newer version must not be sent traffic.
    """
    from sqlalchemy import text

    from .deps import schema_revision

    try:
        with container.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        return ReadinessResponse(status="degraded", database=False, detail=str(exc))

    return ReadinessResponse(
        status="ready", database=True, schema_version=schema_revision(container.engine)
    )


@ops.get("/metrics", summary="Prometheus metrics", response_class=Response)
def metrics(container: Container = Depends(get_container)) -> Response:
    if not isinstance(container.metrics, PrometheusMetrics):
        return Response(content=b"# metrics disabled\n", media_type="text/plain; version=0.0.4")
    return Response(content=container.metrics.render(), media_type="text/plain; version=0.0.4")


@ops.get("/v1/rules", summary="The rule tables, as data")
def rules() -> dict[str, object]:
    """Publish the rules the service is actually running.

    A rule layer nobody can inspect is a rule layer nobody can argue with. This
    endpoint exists so that "what exactly is on the allowlist right now" is a
    question with a curl-length answer, rather than a question about which
    version is deployed.
    """
    from ..domain import rules as rule_tables

    return {
        "safe_programs": sorted(rule_tables.SAFE_PROGRAMS),
        "never_safe": sorted(rule_tables.NEVER_SAFE),
        "bounded_mutators": sorted(rule_tables.BOUNDED_MUTATORS),
        "regenerable": sorted(rule_tables.REGENERABLE),
        "safe_git_verbs": sorted(rule_tables.SAFE_GIT_VERBS),
        "read_only_tools": sorted(rule_tables.READ_ONLY_TOOLS),
        "mutating_tools": sorted(rule_tables.MUTATING_TOOLS),
    }
