"""Runtime configuration.

Twelve-factor style: everything comes from the environment, nothing is read from
a file the process happens to sit next to, and every default is safe enough to
run in production without being read first. The exceptions are the two settings
that are *not* safe by default and are named to say so.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .domain.decision import RunMode


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PERMGATE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ---- storage ---------------------------------------------------------
    database_url: str = Field(
        default="sqlite+pysqlite:///./permgate.db",
        description=(
            "SQLAlchemy URL. SQLite is the default because the service is small "
            "and a single file is the whole deployment, but nothing in the "
            "storage layer is SQLite-specific -- the tests run the same suite "
            "against PostgreSQL through TEST_DATABASE_URL."
        ),
    )
    db_pool_size: int = Field(default=5, ge=1, le=64)
    db_max_overflow: int = Field(default=10, ge=0, le=128)
    db_echo: bool = False

    # ---- the grant cache -------------------------------------------------
    #
    # The cache is the only place in the service where a stale read is possible,
    # so both knobs are exposed and both are loud in the metrics. See
    # ``storage/cache.py`` for why it exists and what invalidates it.
    grant_cache_enabled: bool = True
    grant_cache_ttl_seconds: float = Field(default=15.0, ge=0.0)
    grant_cache_max_entries: int = Field(default=4096, ge=1)

    # ---- policy ----------------------------------------------------------
    default_run_mode: RunMode = RunMode.INTERACTIVE
    preapproved_scopes: list[str] = Field(
        default_factory=list,
        description=(
            "Command scopes an unattended run may use without asking. Empty by "
            "default: a pre-approval that ships switched on is a pre-approval "
            "nobody chose."
        ),
    )

    allow_bypass_mode: bool = Field(
        default=False,
        description=(
            "Whether the API will serve RunMode.BYPASS. Named for what it does "
            "rather than what it skips, because --dangerously-skip-permissions "
            "is a phrase people learn to skim. Off by default and refused at "
            "the edge, not deep in the engine."
        ),
    )
    allow_client_supplied_mode: bool = Field(
        default=False,
        description=(
            "Whether a request may choose its own run mode. Off by default: a "
            "client that can ask for BYPASS can grant itself everything, which "
            "makes the whole service decorative."
        ),
    )

    # ---- authentication --------------------------------------------------
    #
    # Identity is on by default, and that is the whole point of the section.
    # With it off, ``POST /v1/grants`` writes a standing pre-approval for anyone
    # who can reach the port, and ``project_root`` is whatever string the caller
    # sent -- so naming a colleague's workspace is enough to inherit their
    # grants. A service whose subject is "who may vouch for what" cannot leave
    # its own caller unidentified, and a security control that ships switched
    # off is a security control nobody turns on.
    auth_required: bool = Field(
        default=True,
        description=(
            "Identify every caller. Turning this off is a deliberate act: the "
            "service refuses to start when it is on and no client exists, "
            "rather than coming up open."
        ),
    )
    auth_bootstrap_token: str | None = Field(
        default=None,
        description=(
            "Create or refresh a client named 'bootstrap' from this token at "
            "startup, allowed to name the roots in auth_bootstrap_roots. Exists "
            "so a first deployment has a way in without a chicken-and-egg "
            "problem; leave it unset once real clients exist, and treat the "
            "value as a secret."
        ),
    )
    auth_bootstrap_roots: list[str] = Field(
        default_factory=list,
        description=(
            "Project roots the bootstrap client may name. Empty means it may "
            "name nothing, which is the safe default for a setting that is "
            "usually a mistake to populate widely."
        ),
    )

    # ---- audit -----------------------------------------------------------
    audit_enabled: bool = True
    audit_store_arguments: bool = Field(
        default=True,
        description=(
            "Store the raw tool arguments in the audit row. On by default "
            "because an audit trail you cannot read is not one, but it is a "
            "real tradeoff: arguments can contain secrets. Turning it off "
            "keeps the digest, so a row still proves *which* call it was."
        ),
    )

    # ---- observability ---------------------------------------------------
    log_level: str = "INFO"
    log_json: bool = True
    metrics_enabled: bool = True
    request_id_header: str = "X-Request-ID"

    # ---- server ----------------------------------------------------------
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    max_request_bytes: int = Field(default=1 << 20, ge=1024)

    @field_validator("log_level")
    @classmethod
    def _upper_log_level(cls, value: str) -> str:
        normalised = value.upper()
        if normalised not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"unknown log level: {value}")
        return normalised

    @field_validator("preapproved_scopes")
    @classmethod
    def _strip_scopes(cls, value: list[str]) -> list[str]:
        return [scope.strip() for scope in value if scope.strip()]

    @field_validator("auth_bootstrap_roots")
    @classmethod
    def _strip_bootstrap_roots(cls, value: list[str]) -> list[str]:
        # Only whitespace is removed here. Normalisation (resolve, forward
        # slashes) happens in ``api/security.py``, on both sides of every
        # comparison, so there is exactly one place that decides what "the same
        # workspace" means -- storing ``./proj`` here and comparing it against a
        # resolved ``/abs/proj`` at request time is how an allowlist silently
        # matches nothing.
        return [scope.strip() for scope in value if scope.strip()]

    @property
    def preapproved_scope_set(self) -> frozenset[str]:
        return frozenset(self.preapproved_scopes)

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings. Cached because constructing Settings re-reads the
    environment and the .env file, and doing that per request would be a
    filesystem read on the hot path."""
    return Settings()
