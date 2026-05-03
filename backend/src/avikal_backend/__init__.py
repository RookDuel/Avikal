"""
Avikal Time-Locked File Format (.avk).

Package exports stay lazy so lightweight imports, especially the Electron API
server, do not load archive crypto modules before the backend can answer health
checks.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from importlib import import_module

from .version import __version__


_LAZY_EXPORTS = {
    "create_avk_file": ("avikal_backend.archive.pipeline.encoder", "create_avk_file"),
    "extract_avk_file": ("avikal_backend.archive.pipeline.decoder", "extract_avk_file"),
    "datetime_to_timestamp": ("avikal_backend.archive.security.time_lock", "datetime_to_timestamp"),
    "get_ist_now": ("avikal_backend.archive.security.time_lock", "get_ist_now"),
    "get_trusted_now": ("avikal_backend.archive.security.time_lock", "get_trusted_now"),
    "timestamp_to_datetime": ("avikal_backend.archive.security.time_lock", "timestamp_to_datetime"),
}


def __getattr__(name: str):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module_name, attribute_name = target
    value = getattr(import_module(module_name), attribute_name)
    globals()[name] = value
    return value


__all__ = [
    "create_avk_file",
    "extract_avk_file",
    "get_ist_now",
    "get_trusted_now",
    "datetime_to_timestamp",
    "timestamp_to_datetime",
    "__version__",
]
