"""Local core backend security regression tests."""

from __future__ import annotations

import asyncio

import pytest

from avikal_backend.core import services


def test_dispatch_strips_diagnostic_context_before_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    async def handler(params: dict[str, object]) -> dict[str, object]:
        captured.update(params)
        return {"success": True}

    monkeypatch.setitem(services.METHODS, "security.testContextStrip", handler)

    result = asyncio.run(
        services.dispatch(
            "security.testContextStrip",
            {
                "safe_value": "kept",
                "__diagnostic_context": {
                    "correlation_id": "test-correlation",
                    "method": "security.testContextStrip",
                },
            },
        )
    )

    assert result == {"success": True}
    assert captured == {"safe_value": "kept"}


def test_dispatch_rejects_unknown_core_method() -> None:
    with pytest.raises(services.ServiceError) as exc_info:
        asyncio.run(services.dispatch("security.notRegistered", {}))

    assert exc_info.value.code == 404
    assert "Unknown core method" in str(exc_info.value)


def test_validate_public_route_inputs_requires_declared_secrets() -> None:
    request = services.DecryptRequest(input_file="archive.avk")

    with pytest.raises(services.ServiceError) as exc_info:
        services._validate_public_route_inputs(
            request,
            {
                "available": True,
                "requires_password": True,
                "requires_keyphrase": True,
                "requires_pqc": True,
                "pqc_storage_mode": "external",
            },
        )

    assert exc_info.value.code == 400
    message = str(exc_info.value)
    assert "password" in message
    assert "21-word keyphrase" in message
    assert ".avkkey" in message
