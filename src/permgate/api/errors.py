"""Error handling.

One shape for every failure, because a client that has to parse three different
error formats will parse none of them::

    {"error": {"code": "...", "message": "...", "details": {...}, "request_id": "..."}}

Two decisions worth defending:

* **Service errors carry their own status code.** The mapping lives on the
  exception class, next to the code that raises it, so adding a failure mode is
  a one-line change rather than a branch in a handler three modules away.
* **Unexpected exceptions do not leak their text.** A stack trace in a response
  body is an information disclosure; the ``request_id`` is what actually helps,
  because it ties the client's report to the full traceback in the logs.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..services.errors import ServiceError

log = structlog.get_logger(__name__)


def error_body(
    *,
    code: str,
    message: str,
    request_id: str | None,
    details: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
            "request_id": request_id,
        }
    }


def _request_id(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ServiceError)
    async def _service_error(request: Request, exc: ServiceError) -> JSONResponse:
        # Expected failures are logged at warning, not error: they are the
        # system working, and paging on them is how a real outage gets missed.
        log.warning(
            "service_error",
            code=exc.code,
            message=exc.message,
            details=exc.details,
            path=request.url.path,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(
                code=exc.code,
                message=exc.message,
                details=exc.details,
                request_id=_request_id(request),
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=error_body(
                code="validation_error",
                message="request body failed validation",
                details={"errors": _clean(exc.errors())},
                request_id=_request_id(request),
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(
                code=f"http_{exc.status_code}",
                message=str(exc.detail),
                request_id=_request_id(request),
            ),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        request_id = _request_id(request)
        # Full detail to the log, none to the client. ``exc_info`` is what makes
        # the log line worth having; the request id is what makes it findable.
        log.error("unhandled_exception", path=request.url.path, exc_info=exc)
        return JSONResponse(
            status_code=500,
            content=error_body(
                code="internal_error",
                message="internal error",
                request_id=request_id,
            ),
        )


def _clean(errors: Sequence[Any]) -> list[dict[str, object]]:
    """Pydantic error dicts can contain exception objects, which do not
    serialise. Keep the parts a client can act on.

    The shape is checked rather than assumed: a validation error is a
    422 the client should be able to read, and an error formatter that
    itself raises turns a bad request into a 500.
    """
    cleaned: list[dict[str, object]] = []
    for error in errors:
        if not isinstance(error, dict):
            continue
        loc = error.get("loc", [])
        cleaned.append(
            {
                "loc": [str(part) for part in loc] if isinstance(loc, (list, tuple)) else [],
                "msg": str(error.get("msg", "")),
                "type": str(error.get("type", "")),
            }
        )
    return cleaned
