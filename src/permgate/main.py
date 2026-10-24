"""Application factory.

``create_app`` takes its settings rather than reading them, so a test can build
an app against an in-memory database without touching the environment, and an
operator can run two configurations in one process if they ever need to. The
convenience of reading the environment inside is exactly the thing that makes a
service untestable.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from . import __version__
from .api.deps import Container, build_container, create_schema
from .api.errors import install_error_handlers
from .api.routes import ops, router
from .api.security import configure_clients
from .config import Settings, get_settings
from .observability.logging import configure_logging
from .observability.metrics import MetricsSink
from .observability.middleware import BodySizeLimitMiddleware, RequestContextMiddleware


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    container: Container = app.state.container
    if container.settings.is_sqlite:
        # SQLite has no migration step worth the name for a single-file
        # database, so a first run creates it. A real deployment runs
        # ``alembic upgrade head`` and this is a no-op.
        create_schema(container.engine)

    # After the schema, before the first request is accepted. This raises when
    # identity is required and no client could ever authenticate, which is the
    # point: the process must fail to start rather than come up answering every
    # caller, because the second failure mode is silent and this one is a log
    # line in the deploy.
    configure_clients(container.session_factory, container.settings)
    try:
        yield
    finally:
        container.close()


def create_app(settings: Settings | None = None, *, metrics: MetricsSink | None = None) -> FastAPI:
    resolved = settings or get_settings()
    configure_logging(level=resolved.log_level, json_output=resolved.log_json)

    app = FastAPI(
        title="permgate",
        version=__version__,
        summary="Permission gateway for AI agent tool calls",
        description=(
            "Decides whether an agent's tool call may proceed, keeps the grants "
            "that make the answer stable, and records every decision.\n\n"
            "The verdict is one of `allow`, `ask` or `deny`, and every verdict "
            "names the rule that produced it -- `policy said allow` is not an "
            "audit trail."
        ),
        lifespan=_lifespan,
        docs_url="/docs",
        openapi_url="/openapi.json",
    )

    app.state.container = build_container(resolved, metrics=metrics)

    # Order is the contract: context outermost so a rejected request still gets
    # an id and a log line, size limit next so an oversized body is refused
    # before anything parses it.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=resolved.max_request_bytes)
    app.add_middleware(RequestContextMiddleware, header=resolved.request_id_header)

    install_error_handlers(app)
    app.include_router(router)
    app.include_router(ops)
    return app


def __getattr__(name: str) -> Any:
    """``uvicorn permgate.main:app`` support (PEP 562).

    The ASGI app is built on first attribute access rather than at import time,
    so importing this module does not open a database connection. Importing a
    module should not have side effects, and "the import failed because the
    database was down" is a bewildering failure for something that is not a
    query.
    """
    if name == "app":
        return create_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
