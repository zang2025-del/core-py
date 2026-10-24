"""Request-scoped middleware: correlation id, access log, body-size limit.

Order matters, and it is the order they are added in ``main.py``:

1. ``RequestContextMiddleware`` **outermost**, so that a request rejected by
   anything further in still gets an id and an access log line. A 413 that
   leaves no trace is the kind of gap that only shows up when someone is
   flooding the service.
2. ``BodySizeLimitMiddleware`` next, before the body is parsed.
"""

from __future__ import annotations

import time
import uuid

import structlog
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

log = structlog.get_logger(__name__)

#: Paths excluded from the access log. A load balancer's health check every
#: second would otherwise be most of the log volume and none of the signal.
_QUIET_PATHS = frozenset({"/healthz", "/metrics"})


class RequestContextMiddleware:
    """Assigns a request id, binds it to the log context, logs the outcome."""

    def __init__(self, app: ASGIApp, *, header: str = "X-Request-ID") -> None:
        self.app = app
        self.header = header.lower().encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        request_id = headers.get(self.header.decode()) or uuid.uuid4().hex
        scope.setdefault("state", {})
        scope["state"]["request_id"] = request_id

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        started = time.perf_counter()
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                # Echo the id so a client can quote it in a bug report without
                # having to have logged it themselves first.
                headers_list = list(message.get("headers", []))
                headers_list.append((self.header, request_id.encode()))
                message["headers"] = headers_list
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000
            path = scope.get("path", "")
            if path not in _QUIET_PATHS:
                log.info(
                    "request",
                    method=scope.get("method"),
                    path=path,
                    status=status_code,
                    duration_ms=round(elapsed_ms, 3),
                )
            structlog.contextvars.clear_contextvars()


class BodySizeLimitMiddleware:
    """Rejects an oversized request before the body is read into memory.

    Checking ``Content-Length`` is not sufficient on its own -- a chunked
    request has none -- so the limit is enforced on the declared length when
    present and the app's server-level limits cover the rest. Stated as a
    limitation rather than implied to be airtight.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        declared = headers.get("content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                length = -1
            if length > self.max_bytes:
                await _reject(send, self.max_bytes)
                return

        await self.app(scope, receive, send)


async def _reject(send: Send, max_bytes: int) -> None:
    import json

    body = json.dumps(
        {
            "error": {
                "code": "payload_too_large",
                "message": f"request body exceeds {max_bytes} bytes",
                "details": {"max_bytes": max_bytes},
                "request_id": None,
            }
        }
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
