"""ApiError bodies and the per-subclass status/code matrix."""

from __future__ import annotations

import json

import pytest
from starlette.requests import Request

from apns_relay.errors import (
    ApiError,
    BadRequest,
    Conflict,
    Forbidden,
    NotFound,
    TooManyRequests,
    Unauthorized,
    Unprocessable,
    api_error_handler,
)


def body_of(response) -> dict:
    return json.loads(response.body)


def test_base_response_with_detail() -> None:
    error = ApiError(418, "teapot", "I'm a teapot")
    response = error.response()
    assert response.status_code == 418
    assert body_of(response) == {"error": "teapot", "detail": "I'm a teapot"}


def test_detail_omitted_when_empty() -> None:
    response = ApiError(500, "internal").response()
    assert response.status_code == 500
    assert body_of(response) == {"error": "internal"}


def test_detail_omitted_when_falsy() -> None:
    response = ApiError(400, "bad_request", "").response()
    assert "detail" not in body_of(response)


@pytest.mark.parametrize(
    ("cls", "status", "default_code"),
    [
        (BadRequest, 400, "bad_request"),
        (Unauthorized, 401, "unauthorized"),
        (Forbidden, 403, "forbidden"),
        (NotFound, 404, "not_found"),
        (Conflict, 409, "conflict"),
        (TooManyRequests, 429, "rate_limited"),
        (Unprocessable, 422, "rejected"),
    ],
)
def test_subclass_status_and_default_code(cls, status: int, default_code: str) -> None:
    error = cls()
    assert isinstance(error, ApiError)
    assert error.status == status
    assert error.code == default_code
    response = error.response()
    assert response.status_code == status
    assert body_of(response) == {"error": default_code}


@pytest.mark.parametrize(
    "cls", [BadRequest, Unauthorized, Forbidden, NotFound, Conflict, TooManyRequests, Unprocessable]
)
def test_subclass_custom_code_and_detail(cls) -> None:
    error = cls("custom_code", "extra info")
    assert error.code == "custom_code"
    assert error.detail == "extra info"
    assert body_of(error.response()) == {"error": "custom_code", "detail": "extra info"}


def test_exception_str_is_the_code() -> None:
    assert str(BadRequest("invalid_grant")) == "invalid_grant"


async def test_api_error_handler_returns_response() -> None:
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    error = NotFound("no_such_thing", "try again")
    response = await api_error_handler(request, error)
    assert response.status_code == 404
    assert body_of(response) == {"error": "no_such_thing", "detail": "try again"}
