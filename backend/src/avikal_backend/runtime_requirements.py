"""
Runtime requirement enforcement for native-backed Avikal builds.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from .archive.security import native_bridge
from .runtime_paths import is_frozen, project_root
from .version import __version__


_RELEASE_SIGNING_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAkGczVephZ5KfvQuJMcrWtfZMGsmii9wnzGK1nFlLzk0=
-----END PUBLIC KEY-----
"""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class NativeRuntimeStatus:
    available: bool
    import_error: str | None
    memory_lock_available: bool
    process_hardening_available: bool


def get_native_runtime_status() -> NativeRuntimeStatus:
    memory_lock_available = False
    process_hardening_available = False
    if native_bridge.native_available():
        try:
            memory_lock_available = native_bridge.native_memory_lock_self_test()
        except Exception:
            memory_lock_available = False
        if os.name == "nt":
            try:
                process_hardening_available = native_bridge.native_harden_windows_process()
            except Exception:
                process_hardening_available = False
    return NativeRuntimeStatus(
        available=native_bridge.native_available(),
        import_error=None if native_bridge.NATIVE_IMPORT_ERROR is None else str(native_bridge.NATIVE_IMPORT_ERROR),
        memory_lock_available=memory_lock_available,
        process_hardening_available=process_hardening_available,
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


def harden_process_runtime(surface: str) -> None:
    """Enable process-level hardening before crypto or temp-cleanup work."""

    if os.name != "nt":
        return
    ensure_native_crypto_runtime(surface)
    try:
        if not native_bridge.native_harden_windows_process():
            raise RuntimeError("Windows process hardening was not applied")
    except Exception as exc:
        raise RuntimeError(
            f"{surface} could not enable required Windows process hardening."
        ) from exc


def verify_publisher_runtime_manifest() -> None:
    """Verify signed hashes for critical files in a frozen production runtime."""
    if not is_frozen():
        return
    root = project_root().resolve()
    manifest_path = root / "backend-runtime" / "avikal-runtime-integrity.json"
    signature_path = Path(f"{manifest_path}.sig")
    try:
        manifest_bytes = manifest_path.read_bytes()
        signature = base64.b64decode(signature_path.read_text(encoding="ascii").strip(), validate=True)
        public_key = load_pem_public_key(_RELEASE_SIGNING_PUBLIC_KEY)
        public_key.verify(signature, manifest_bytes)
        document = json.loads(manifest_bytes.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("Avikal publisher runtime signature verification failed") from exc

    if (
        document.get("format") != "avikal-runtime-integrity"
        or document.get("version") != 1
        or document.get("product_version") != __version__
    ):
        raise RuntimeError("Avikal publisher runtime manifest is incompatible")
    files = document.get("files")
    if not isinstance(files, list) or not 4 <= len(files) <= 32:
        raise RuntimeError("Avikal publisher runtime manifest file list is invalid")
    for entry in files:
        relative = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(relative, str) or not relative or "\\" in relative:
            raise RuntimeError("Avikal publisher runtime path is invalid")
        target = (root / relative).resolve()
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise RuntimeError("Avikal publisher runtime path escapes its root") from exc
        if not target.is_file() or target.stat().st_size != entry.get("size"):
            raise RuntimeError(f"Avikal publisher runtime file is missing or changed: {relative}")
        digest = _sha256_file(target)
        if digest != entry.get("sha256"):
            raise RuntimeError(f"Avikal publisher runtime hash mismatch: {relative}")
