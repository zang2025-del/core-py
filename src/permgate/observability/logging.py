"""Structured logging.

JSON in production, human-readable in development, same events either way. The
renderer is the only thing that changes, so a log line that is useful locally is
the same line that is searchable in production -- rather than two logging
statements that drift apart.

Every request-scoped event carries ``request_id`` and every decision event
carries ``decision_id``. Those two are what turn a pile of lines into a story:
without them, "the agent ran something it should not have" is a grep through
everything, and with them it is one query.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

_configured = False


def configure_logging(*, level: str = "INFO", json_output: bool = True) -> None:
    """Idempotent: calling it twice does not double every log line.

    That matters because tests and the CLI both call it and both may run after
    the app factory already has.
    """
    global _configured
    if _configured:
        return

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )

    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    renderer = (
        structlog.processors.JSONRenderer(ensure_ascii=False)
        if json_output
        else structlog.dev.ConsoleRenderer(colors=False)
    )

    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # uvicorn installs its own handlers; leaving them on produces duplicate
    # lines in a different format, which is worse than either format alone.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = False

    _configured = True


def get_logger(name: str | None = None) -> Any:
    return structlog.get_logger(name)
