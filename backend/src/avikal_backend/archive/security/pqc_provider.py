"""
OpenSSL-backed PQC provider boundary for Avikal.

The archive pipeline intentionally talks to PQC through this module only. The
production build bundles an OpenSSL 3.5+ runtime and this module invokes its
openssl.exe with strict argument lists, no shell, isolated temporary files, and
explicit suite validation. If the runtime is absent, PQC mode fails closed.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


PQC_PROVIDER_NAME = "openssl"
PQC_SUITE_VERSION = 2
PQC_SUITE_ID = "avikal-pqc-openssl-triple-stack-v2"
ML_KEM_ALGORITHM = "ML-KEM-1024"
ML_DSA_ALGORITHM = "ML-DSA-87"
SLH_DSA_ALGORITHM = "SLH-DSA-SHA2-256s"
OPENSSL_EXE_NAME = "openssl.exe"
PQC_PROVIDER_TIMEOUT_SECONDS = 60

PQC_SUITE = {
    "suite_id": PQC_SUITE_ID,
    "suite_version": PQC_SUITE_VERSION,
    "provider": PQC_PROVIDER_NAME,
    "provider_minimum": "OpenSSL 3.5",
    "algorithms": {
        "kem": ML_KEM_ALGORITHM,
        "authentication_signature": ML_DSA_ALGORITHM,
        "long_term_signature": SLH_DSA_ALGORITHM,
    },
}


class PQCProviderUnavailable(RuntimeError):
    """Raised when PQC was requested but the bundled OpenSSL runtime is absent."""


class PQCProviderError(RuntimeError):
    """Raised when OpenSSL returns malformed or failed output."""


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: Any, field_name: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise PQCProviderError(f"PQC provider returned missing {field_name}")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise PQCProviderError(f"PQC provider returned malformed {field_name}") from exc


def _canonical_json(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _backend_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _project_root() -> Path:
    return _backend_root().parent


def _candidate_openssl_paths() -> list[Path]:
    candidates: list[Path] = []

    env_path = os.environ.get("AVIKAL_OPENSSL_EXEC")
    if env_path:
        candidates.append(Path(env_path))

    executable_dir = Path(sys.executable).resolve().parent
    candidates.extend(
        [
            executable_dir / "pqc" / OPENSSL_EXE_NAME,
            executable_dir / "pqc" / "bin" / OPENSSL_EXE_NAME,
            executable_dir / OPENSSL_EXE_NAME,
            executable_dir.parent / "pqc" / OPENSSL_EXE_NAME,
            executable_dir.parent / "pqc" / "bin" / OPENSSL_EXE_NAME,
            executable_dir.parent / "backend-runtime" / "pqc" / OPENSSL_EXE_NAME,
            executable_dir.parent / "backend-runtime" / "pqc" / "bin" / OPENSSL_EXE_NAME,
        ]
    )

    project_root = _project_root()
    candidates.extend(
        [
            project_root / "runtime" / "pqc" / OPENSSL_EXE_NAME,
            project_root / "runtime" / "pqc" / "bin" / OPENSSL_EXE_NAME,
            project_root / ".app-build" / "backend-runtime" / "pqc" / OPENSSL_EXE_NAME,
            project_root / ".app-build" / "backend-runtime" / "pqc" / "bin" / OPENSSL_EXE_NAME,
            _backend_root() / "runtime" / "pqc" / OPENSSL_EXE_NAME,
            _backend_root() / "runtime" / "pqc" / "bin" / OPENSSL_EXE_NAME,
            _backend_root() / "backend-runtime" / "pqc" / OPENSSL_EXE_NAME,
            _backend_root() / "backend-runtime" / "pqc" / "bin" / OPENSSL_EXE_NAME,
        ]
    )
    return candidates


def resolve_openssl_executable() -> Path | None:
    """Return the bundled OpenSSL executable, if present."""
    for candidate in _candidate_openssl_paths():
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if resolved.is_file():
            return resolved
    return None


def _openssl_modules_dir(openssl_executable: Path) -> Path | None:
    runtime_root = openssl_executable.parent.parent
    candidates = [
        runtime_root / "lib" / "ossl-modules",
        runtime_root / "lib64" / "ossl-modules",
        openssl_executable.parent / "ossl-modules",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _run_openssl(args: list[str], *, cwd: Path | None = None, input_data: bytes | None = None) -> bytes:
    openssl_executable = require_openssl()
    env = os.environ.copy()
    modules_dir = _openssl_modules_dir(openssl_executable)
    if modules_dir is not None:
        env["OPENSSL_MODULES"] = str(modules_dir)

    try:
        completed = subprocess.run(
            [str(openssl_executable), *args],
            input=input_data,
            capture_output=True,
            cwd=str(cwd) if cwd else None,
            env=env,
            timeout=PQC_PROVIDER_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PQCProviderError("OpenSSL PQC provider timed out") from exc
    except OSError as exc:
        raise PQCProviderUnavailable(f"Unable to execute bundled OpenSSL runtime: {exc}") from exc

    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        stdout = completed.stdout.decode("utf-8", errors="replace").strip()
        detail = stderr or stdout or "unknown OpenSSL failure"
        raise PQCProviderError(f"OpenSSL PQC provider failed: {detail}")
    return completed.stdout


def _openssl_version() -> str:
    output = _run_openssl(["version"])
    return output.decode("utf-8", errors="replace").strip()


def provider_status() -> dict[str, Any]:
    """Report whether the bundled OpenSSL PQC runtime is available."""
    executable = resolve_openssl_executable()
    if executable is None:
        return {
            "available": False,
            "provider": PQC_PROVIDER_NAME,
            "suite": PQC_SUITE,
            "reason": (
                "OpenSSL PQC provider is unavailable. Bundle OpenSSL 3.5+ "
                f"{OPENSSL_EXE_NAME} under runtime/pqc or set AVIKAL_OPENSSL_EXEC."
            ),
        }

    status: dict[str, Any] = {
        "available": True,
        "provider": PQC_PROVIDER_NAME,
        "suite": PQC_SUITE,
        "executable": str(executable),
    }
    try:
        status["openssl_version"] = _openssl_version()
    except Exception as exc:
        status["available"] = False
        status["reason"] = f"Bundled OpenSSL runtime is not usable: {exc}"
    return status


def require_openssl() -> Path:
    """Resolve the OpenSSL executable or raise a fail-closed error."""
    executable = resolve_openssl_executable()
    if executable is None:
        raise PQCProviderUnavailable(provider_status()["reason"])
    return executable


def _write_bytes(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def _write_text(path: Path, data: str) -> None:
    path.write_text(data, encoding="utf-8", newline="\n")


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _generate_keypair(work_dir: Path, algorithm: str, stem: str) -> tuple[str, str]:
    private_path = work_dir / f"{stem}_private.pem"
    public_path = work_dir / f"{stem}_public.pem"
    _run_openssl(["genpkey", "-algorithm", algorithm, "-out", str(private_path)], cwd=work_dir)
    _run_openssl(["pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)], cwd=work_dir)
    return _read_text(private_path), _read_text(public_path)


def _public_binding(public_bundle: dict[str, Any]) -> bytes:
    binding = dict(public_bundle)
    binding.pop("signatures", None)
    return _canonical_json(binding)


def _sign_message(work_dir: Path, private_pem: str, message: bytes, stem: str) -> bytes:
    private_path = work_dir / f"{stem}_sign_private.pem"
    message_path = work_dir / f"{stem}_message.bin"
    signature_path = work_dir / f"{stem}_signature.bin"
    _write_text(private_path, private_pem)
    _write_bytes(message_path, message)
    _run_openssl(
        [
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private_path),
            "-in",
            str(message_path),
            "-out",
            str(signature_path),
        ],
        cwd=work_dir,
    )
    return signature_path.read_bytes()


def _verify_signature(work_dir: Path, public_pem: str, message: bytes, signature: bytes, stem: str) -> None:
    public_path = work_dir / f"{stem}_verify_public.pem"
    message_path = work_dir / f"{stem}_verify_message.bin"
    signature_path = work_dir / f"{stem}_verify_signature.bin"
    _write_text(public_path, public_pem)
    _write_bytes(message_path, message)
    _write_bytes(signature_path, signature)
    _run_openssl(
        [
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey",
            str(public_path),
            "-in",
            str(message_path),
            "-sigfile",
            str(signature_path),
        ],
        cwd=work_dir,
    )


def _encapsulate_mlkem(work_dir: Path, public_pem: str) -> tuple[bytes, bytes]:
    public_path = work_dir / "mlkem_public.pem"
    ciphertext_path = work_dir / "mlkem_ciphertext.bin"
    secret_path = work_dir / "mlkem_shared_secret.bin"
    _write_text(public_path, public_pem)
    _run_openssl(
        [
            "pkeyutl",
            "-encap",
            "-pubin",
            "-inkey",
            str(public_path),
            "-out",
            str(ciphertext_path),
            "-secret",
            str(secret_path),
        ],
        cwd=work_dir,
    )
    return ciphertext_path.read_bytes(), secret_path.read_bytes()


def _decapsulate_mlkem(work_dir: Path, private_pem: str, pqc_ciphertext: bytes) -> bytes:
    private_path = work_dir / "mlkem_private.pem"
    ciphertext_path = work_dir / "mlkem_ciphertext.bin"
    secret_path = work_dir / "mlkem_shared_secret.bin"
    _write_text(private_path, private_pem)
    _write_bytes(ciphertext_path, pqc_ciphertext)
    _run_openssl(
        [
            "pkeyutl",
            "-decap",
            "-inkey",
            str(private_path),
            "-in",
            str(ciphertext_path),
            "-secret",
            str(secret_path),
        ],
        cwd=work_dir,
    )
    return secret_path.read_bytes()


def compute_pqc_key_id(public_bundle: dict[str, Any], pqc_ciphertext: bytes) -> str:
    """Bind the archive to the public PQC suite material and KEM ciphertext."""
    if not isinstance(public_bundle, dict) or not public_bundle:
        raise ValueError("PQC public bundle is required")
    if not pqc_ciphertext:
        raise ValueError("PQC ciphertext is required")
    digest = hashlib.sha256()
    digest.update(PQC_SUITE_ID.encode("ascii"))
    digest.update(b"\x00")
    digest.update(_canonical_json(public_bundle))
    digest.update(b"\x00")
    digest.update(pqc_ciphertext)
    return digest.hexdigest()


def create_pqc_archive_material(*, archive_filename: str) -> dict[str, Any]:
    """
    Generate archive-specific PQC material through the bundled OpenSSL runtime.
    """
    status = provider_status()
    if not status.get("available"):
        raise PQCProviderUnavailable(str(status.get("reason")))

    with tempfile.TemporaryDirectory(prefix="avikal-pqc-") as temp_dir:
        work_dir = Path(temp_dir)
        mlkem_private, mlkem_public = _generate_keypair(work_dir, ML_KEM_ALGORITHM, "mlkem")
        mldsa_private, mldsa_public = _generate_keypair(work_dir, ML_DSA_ALGORITHM, "mldsa")
        slhdsa_private, slhdsa_public = _generate_keypair(work_dir, SLH_DSA_ALGORITHM, "slhdsa")
        ciphertext, shared_secret = _encapsulate_mlkem(work_dir, mlkem_public)

        public_bundle: dict[str, Any] = {
            "suite_id": PQC_SUITE_ID,
            "suite_version": PQC_SUITE_VERSION,
            "provider": PQC_PROVIDER_NAME,
            "openssl_version": status.get("openssl_version"),
            "archive_filename": archive_filename,
            "algorithms": dict(PQC_SUITE["algorithms"]),
            "keys": {
                "ml_kem_public_pem": mlkem_public,
                "ml_dsa_public_pem": mldsa_public,
                "slh_dsa_public_pem": slhdsa_public,
            },
        }
        binding = _public_binding(public_bundle)
        public_bundle["signatures"] = {
            "ml_dsa_binding": _b64encode(_sign_message(work_dir, mldsa_private, binding, "mldsa")),
            "slh_dsa_binding": _b64encode(_sign_message(work_dir, slhdsa_private, binding, "slhdsa")),
        }

        private_bundle = {
            "suite_id": PQC_SUITE_ID,
            "suite_version": PQC_SUITE_VERSION,
            "provider": PQC_PROVIDER_NAME,
            "openssl_version": status.get("openssl_version"),
            "algorithms": dict(PQC_SUITE["algorithms"]),
            "keys": {
                "ml_kem_private_pem": mlkem_private,
                "ml_dsa_private_pem": mldsa_private,
                "slh_dsa_private_pem": slhdsa_private,
            },
        }

    return {
        "suite": PQC_SUITE,
        "algorithm": PQC_SUITE_ID,
        "key_id": compute_pqc_key_id(public_bundle, ciphertext),
        "public_bundle": public_bundle,
        "private_bundle": private_bundle,
        "ciphertext": ciphertext,
        "shared_secret": shared_secret,
    }


def _validate_public_bundle(public_bundle: dict[str, Any]) -> None:
    if public_bundle.get("suite_id") != PQC_SUITE_ID:
        raise ValueError("Unsupported PQC public bundle")
    keys = public_bundle.get("keys")
    signatures = public_bundle.get("signatures")
    if not isinstance(keys, dict) or not isinstance(signatures, dict):
        raise ValueError("Invalid PQC public bundle")
    for field_name in ("ml_kem_public_pem", "ml_dsa_public_pem", "slh_dsa_public_pem"):
        if not isinstance(keys.get(field_name), str) or not keys[field_name].strip():
            raise ValueError("Invalid PQC public bundle")
    for field_name in ("ml_dsa_binding", "slh_dsa_binding"):
        _b64decode(signatures.get(field_name), field_name)


def _validate_private_bundle(private_bundle: dict[str, Any]) -> None:
    if private_bundle.get("suite_id") != PQC_SUITE_ID:
        raise ValueError("Unsupported PQC private bundle")
    keys = private_bundle.get("keys")
    if not isinstance(keys, dict):
        raise ValueError("Invalid PQC private bundle")
    for field_name in ("ml_kem_private_pem", "ml_dsa_private_pem", "slh_dsa_private_pem"):
        if not isinstance(keys.get(field_name), str) or not keys[field_name].strip():
            raise ValueError("Invalid PQC private bundle")


def decapsulate_pqc_archive_material(
    *,
    private_bundle: dict[str, Any],
    public_bundle: dict[str, Any],
    pqc_ciphertext: bytes,
    expected_key_id: str | None,
) -> bytes:
    """Recover the PQC shared secret through the bundled OpenSSL runtime."""
    status = provider_status()
    if not status.get("available"):
        raise PQCProviderUnavailable(str(status.get("reason")))
    _validate_private_bundle(private_bundle)
    _validate_public_bundle(public_bundle)

    computed_key_id = compute_pqc_key_id(public_bundle, pqc_ciphertext)
    if expected_key_id and computed_key_id != expected_key_id:
        raise ValueError("PQC keyfile does not match this archive.")

    public_keys = public_bundle["keys"]
    private_keys = private_bundle["keys"]
    binding = _public_binding(public_bundle)
    with tempfile.TemporaryDirectory(prefix="avikal-pqc-") as temp_dir:
        work_dir = Path(temp_dir)
        _verify_signature(
            work_dir,
            public_keys["ml_dsa_public_pem"],
            binding,
            _b64decode(public_bundle["signatures"]["ml_dsa_binding"], "ml_dsa_binding"),
            "mldsa",
        )
        _verify_signature(
            work_dir,
            public_keys["slh_dsa_public_pem"],
            binding,
            _b64decode(public_bundle["signatures"]["slh_dsa_binding"], "slh_dsa_binding"),
            "slhdsa",
        )
        return _decapsulate_mlkem(work_dir, private_keys["ml_kem_private_pem"], pqc_ciphertext)
