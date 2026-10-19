"""Structured API errors. Every failure path returns a stable machine code."""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse


class ApiError(Exception):
    """Base for all handled API failures.

    ``code`` is the stable machine-readable string returned to the caller and
    the key used in redacted logs/metrics. ``status`` is the HTTP status.
    """

    def __init__(self, status: int, code: str, detail: str = "") -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.detail = detail

    def response(self) -> JSONResponse:
        body = {"error": self.code}
        if self.detail:
            body["detail"] = self.detail
        return JSONResponse(status_code=self.status, content=body)


class BadRequest(ApiError):
    def __init__(self, code: str = "bad_request", detail: str = "") -> None:
        super().__init__(400, code, detail)


class Unauthorized(ApiError):
    def __init__(self, code: str = "unauthorized", detail: str = "") -> None:
        super().__init__(401, code, detail)


class Forbidden(ApiError):
    def __init__(self, code: str = "forbidden", detail: str = "") -> None:
        super().__init__(403, code, detail)


class NotFound(ApiError):
    def __init__(self, code: str = "not_found", detail: str = "") -> None:
        super().__init__(404, code, detail)


class Conflict(ApiError):
    def __init__(self, code: str = "conflict", detail: str = "") -> None:
        super().__init__(409, code, detail)


class TooManyRequests(ApiError):
    def __init__(self, code: str = "rate_limited", detail: str = "") -> None:
        super().__init__(429, code, detail)


class Unprocessable(ApiError):
    def __init__(self, code: str = "rejected", detail: str = "") -> None:
        super().__init__(422, code, detail)


async def api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
    return exc.response()
