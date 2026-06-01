"""
Runtime requirement enforcement for native-backed Avikal builds.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from dataclasses import dataclass

from .archive.security import native_bridge


@dataclass(frozen=True)
class NativeRuntimeStatus:
    available: bool
    import_error: str | None


def get_native_runtime_status() -> NativeRuntimeStatus:
    return NativeRuntimeStatus(
        available=native_bridge.native_available(),
        import_error=None if native_bridge.NATIVE_IMPORT_ERROR is None else str(native_bridge.NATIVE_IMPORT_ERROR),
    )


def ensure_native_crypto_runtime(surface: str) -> None:
    try:
        native_bridge.require_native_available()
    except RuntimeError as exc:
        raise RuntimeError(
            f"{surface} requires the Avikal native cryptography module. "
            "This build must not fall back to Python crypto. "
            "Install a native-backed package or rebuild the backend extension."
        ) from exc
