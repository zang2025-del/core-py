"""SQLAlchemy models.

Three tables, and the shape of each one is a decision worth stating.

``projects``
    Grants are scoped to a project, so a project has to be a row rather than a
    string repeated on every grant. The row is keyed on the **resolved** project
    root, and the filename-safe form of it lives in ``storage/keys.py``.

``grants``
    The standing pre-approvals. ``scope`` is **NOT NULL with an empty-string
    default** rather than nullable, and that is not a style preference: SQLite,
    PostgreSQL and MySQL all treat NULLs as distinct in a UNIQUE index, so
    ``UNIQUE(project_id, tool, scope)`` with a nullable ``scope`` would happily
    accept two identical tool-level grants. Empty string means "no scope,
    tool-level" and makes the constraint do its job.

``decisions``
    The audit trail. Append-only by convention -- nothing in the service issues
    an UPDATE or DELETE against it -- and every request writes exactly one row,
    including the ones that were allowed. An audit log that only records
    refusals cannot answer "what did the agent actually run last Tuesday",
    which is the question people ask.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Project(Base):
    """One workspace the gateway has seen a request for."""

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    root: Mapped[str] = mapped_column(String(1024), nullable=False, unique=True, index=True)
    key: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
        doc="Filename-safe, collision-resistant key derived from the root.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    grants: Mapped[list[Grant]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class Grant(Base):
    """A standing pre-approval, scoped to one project.

    Two shapes share this table, and the difference is the whole security model:

    * ``scope == ""`` -- tool-level. Broad, therefore **weak**: it covers
      unflagged calls only.
    * ``scope == "git push"`` -- narrowed to a command family. Narrow, therefore
      **strong**: it covers that family, flagged calls included.
    """

    __tablename__ = "grants"
    __table_args__ = (
        # The constraint that makes concurrent "always allow" clicks idempotent
        # instead of duplicating. See the module docstring on why scope is "".
        UniqueConstraint("project_id", "tool", "scope", name="uq_grant_project_tool_scope"),
        Index("ix_grant_project_tool", "project_id", "tool"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )

    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[str] = mapped_column(String(255), nullable=False, default="")

    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    granted_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    note: Mapped[str | None] = mapped_column(String(512), nullable=True)

    project: Mapped[Project] = relationship(back_populates="grants")

    @property
    def key(self) -> str:
        """``bash`` or ``bash:git push`` -- the form the engine compares against."""
        return self.tool if not self.scope else f"{self.tool}:{self.scope}"


class Decision(Base):
    """One evaluated tool call. Append-only.

    Every request lands here, allow or deny. The row is written inside the same
    transaction as the grant it may have created, so a crash cannot leave a
    grant with no record of who asked for it.
    """

    __tablename__ = "decisions"
    __table_args__ = (
        Index("ix_decision_project_time", "project_id", "occurred_at"),
        Index("ix_decision_verdict_time", "verdict", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )

    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    arguments: Mapped[str | None] = mapped_column(
        Text, nullable=True, doc="JSON, or NULL when argument storage is off."
    )
    arguments_digest: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        doc="SHA-256 of the canonicalised arguments. Present even when the "
        "arguments themselves are not stored, so a row still proves which call it was.",
    )

    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    rule: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    scope: Mapped[str | None] = mapped_column(String(255), nullable=True)
    run_mode: Mapped[str] = mapped_column(String(16), nullable=False)

    latency_us: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    # Set when a human answered the prompt this decision raised.
    answer: Mapped[str | None] = mapped_column(String(16), nullable=True)
    answered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    answer_actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    granted_key: Mapped[str | None] = mapped_column(
        String(255), nullable=True, doc="Grant recorded by the answer, if any."
    )


class SchemaVersion(Base):
    """Which migrations have run.

    Alembic keeps its own table, but the service also records a version it can
    read without invoking Alembic -- a process that starts against a database
    newer than itself has to refuse rather than guess.
    """

    __tablename__ = "schema_version"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    applied_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
