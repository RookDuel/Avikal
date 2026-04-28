"""
Runtime health checks for the Avikal CLI package.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import argparse
import importlib
import logging
import platform
import ssl
import sys
import time
from pathlib import Path
from typing import Any

import requests


log = logging.getLogger("avikal.cli")

REQUIRED_RUNTIME_IMPORTS = {
    "requests": "requests",
    "cryptography": "cryptography",
    "nacl": "PyNaCl",
    "Crypto": "pycryptodome",
    "pqcrypto": "pqcrypto",
    "brotli": "brotli",
    "psutil": "psutil",
}


def _probe_http(url: str, *, timeout: float) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        response = requests.get(url, timeout=timeout)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "ok": response.ok,
            "status_code": response.status_code,
            "elapsed_ms": elapsed_ms,
        }
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "ok": False,
            "elapsed_ms": elapsed_ms,
            "error": str(exc),
        }


def doctor_backend(args: argparse.Namespace) -> dict[str, Any]:
    checks: dict[str, Any] = {}

    checks["python"] = {
        "version": sys.version.split()[0],
        "executable": sys.executable,
        "platform": platform.platform(),
        "openssl": ssl.OPENSSL_VERSION,
    }

    import_results: dict[str, bool] = {}
    for module_name, friendly_name in REQUIRED_RUNTIME_IMPORTS.items():
        try:
            importlib.import_module(module_name)
            import_results[friendly_name] = True
        except Exception:
            import_results[friendly_name] = False
    checks["imports"] = import_results

    probe_path = Path.cwd() / ".avikal-doctor-probe.txt"
    try:
        probe_path.write_text("ok", encoding="utf-8")
        checks["filesystem"] = {
            "probe_path": str(probe_path),
            "write_ok": probe_path.exists(),
        }
    finally:
        try:
            probe_path.unlink(missing_ok=True)
        except Exception as exc:
            log.debug("Failed to remove backend doctor probe %s: %s", probe_path, exc)

    aavrit_ok = True
    if args.aavrit_url:
        base_url = args.aavrit_url.rstrip("/")
        aavrit_checks: dict[str, Any] = {"base_url": base_url, "timeout_seconds": args.timeout}
        for route_name, route_path in {
            "health": "/health",
            "config": "/config",
        }.items():
            probe_result = _probe_http(f"{base_url}{route_path}", timeout=args.timeout)
            aavrit_checks[route_name] = probe_result
            aavrit_ok = aavrit_ok and probe_result["ok"]
        checks["aavrit"] = aavrit_checks

    return {
        "ok": all(checks["imports"].values()) and checks["filesystem"]["write_ok"] and aavrit_ok,
        "mode": "doctor",
        "checks": checks,
    }
