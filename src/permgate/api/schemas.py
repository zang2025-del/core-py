"""Request and response bodies.

Pydantic models rather than dicts, so that the wire contract is one readable
file and a malformed request is a 422 with a field path instead of a 500 from
somewhere deep in the service.

Two conventions worth stating:

* **Responses are explicit, not ``from_attributes`` mirrors of ORM rows.** A
  model that follows the database will one day publish a column nobody meant to
  publish. Every field here was chosen.
* **Timestamps go out as UTC with an offset.** A local-time audit trail is
  unreadable across a fleet, and "was that before or after the deploy" is the
  first question anyone asks of one.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..domain.decision import RunMode, Verdict

Answer = Literal["once", "always", "scoped", "deny"]


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_root: str = Field(
        min_length=1,
        max_length=1024,
        description="Path to the workspace. Resolved and normalised server-side "
        "before it is used as anything, so ``proj``, ``./proj/`` and an absolute "
        "path are one project.",
        examples=["/home/dev/checkout-api"],
    )
    tool: str = Field(min_length=1, max_length=64, examples=["bash"])
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="The tool's arguments exactly as the agent is about to pass them.",
    )
    mode: RunMode | None = Field(
        default=None,
        description="Overrides the deployment default. Refused unless the "
        "deployment sets PERMGATE_ALLOW_CLIENT_SUPPLIED_MODE.",
    )
    actor: str | None = Field(default=None, max_length=128, description="Who is asking.")


class DecisionResponse(BaseModel):
    decision_id: str = Field(
        description="Use this to answer the prompt, and to find the row in the audit trail."
    )
    verdict: Verdict
    rule: str = Field(
        description="Which rule produced the verdict. The audit trail's unit of explanation."
    )
    reason: str | None = Field(
        default=None,
        description="Shown to the human, and returned to the model on a refusal so it "
        "can route around it.",
    )
    scope: str | None = Field(
        default=None,
        description="The command family this call belongs to, when it has exactly one. "
        "This is what a *narrow* grant would name.",
    )
    latency_us: int
    project_root: str


class AnswerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer: Answer
    actor: str | None = Field(default=None, max_length=128)


class AnswerResponse(BaseModel):
    decision_id: str
    answer: Answer
    granted_key: str | None = Field(
        default=None,
        description="The grant this answer recorded, if any. Null for ``once`` and "
        "``deny``, and also null for ``always`` on a flagged call -- agreeing to one "
        "destructive command says nothing about the next one.",
    )
    grant_created: bool


class GrantResponse(BaseModel):
    key: str = Field(examples=["bash", "bash:git push"])
    tool: str
    scope: str | None
    strength: str = Field(
        description="'broad (unflagged calls only)' or 'narrow (covers flagged calls)'."
    )
    granted_at: datetime
    granted_by: str | None
    note: str | None


class GrantListResponse(BaseModel):
    project_root: str = Field(
        description="The resolved project root, not the string that was sent. Every "
        "endpoint answers with this same value, so a client can use it as one "
        "identifier across all of them."
    )
    grants: list[GrantResponse]


class CreateGrantResponse(GrantResponse):
    project_root: str = Field(description="Resolved project root.")
    created: bool = Field(
        description="False when an identical grant was already present. The write is "
        "idempotent, so replaying a provisioning script reports False rather than "
        "failing or duplicating."
    )


class CreateGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_root: str = Field(min_length=1, max_length=1024)
    tool: str = Field(min_length=1, max_length=64)
    scope: str | None = Field(
        default=None,
        max_length=255,
        description="Omit for a tool-level grant. Supplying a scope makes the grant "
        "narrow *and strong*: it will cover flagged calls in that family.",
    )
    actor: str | None = Field(default=None, max_length=128)
    note: str | None = Field(default=None, max_length=512)


class RevokeResponse(BaseModel):
    project_root: str
    key: str | None
    removed: int


class AuditEntry(BaseModel):
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


class AuditListResponse(BaseModel):
    entries: list[AuditEntry]


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str


class ReadinessResponse(BaseModel):
    status: Literal["ready", "degraded"]
    database: bool
    schema_version: str | None = None
    detail: str | None = None
