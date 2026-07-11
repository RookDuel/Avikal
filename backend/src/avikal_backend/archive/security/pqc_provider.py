"""OpenSSL-backed PQC provider boundary for Avikal.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ...runtime_paths import backend_root as runtime_backend_root
from ...runtime_paths import is_frozen as runtime_is_frozen
from ...runtime_paths import project_root as runtime_project_root
from .native_bridge import (
    openssl_derive_secret,
    openssl_generate_keypair,
    openssl_kem_decapsulate,
    openssl_kem_encapsulate,
    openssl_runtime_version,
    openssl_sign_message,
    openssl_verify_signature,
)


PQC_PROVIDER_NAME = "openssl"
PQC_SUITE_VERSION = 1
PQC_SUITE_ID = "avikal-pqc-openssl-hybrid-kem-triple-stack-v1"
PQC_STANDARD_SUITE_ID = "avikal-pqc-std-v1"
PQC_CUSTOM_SUITE_ID = "avikal-pqc-custom-v1"
PQC_DEFAULT_SUITE_ID = PQC_SUITE_ID
ML_KEM_ALGORITHMS = {"ML-KEM-768", "ML-KEM-1024"}
ML_DSA_ALGORITHMS = {"ML-DSA-65", "ML-DSA-87"}
SLH_DSA_ALGORITHMS = {
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-192s",
    "SLH-DSA-SHA2-256s",
}
ML_KEM_ALGORITHM = "ML-KEM-1024"
X25519_ALGORITHM = "X25519"
ML_DSA_ALGORITHM = "ML-DSA-87"
SLH_DSA_ALGORITHM = "SLH-DSA-SHA2-256s"
ARCHIVE_SIGNING_IDENTITY_FORMAT = "avikal-signing-identity"
ARCHIVE_SIGNING_IDENTITY_VERSION = 1
OPENSSL_EXE_NAME = "openssl.exe"
HYBRID_CIPHERTEXT_MAGIC = b"AVKH"
HYBRID_CIPHERTEXT_VERSION = 1
MAX_MLKEM_CIPHERTEXT_BYTES = 2048
MAX_X25519_PUBLIC_PEM_BYTES = 512
_RUNTIME_INTEGRITY_VERIFIED = False


def _ensure_runtime_integrity_verified() -> None:
    """Fail closed if a frozen runtime's signed crypto files changed."""

    global _RUNTIME_INTEGRITY_VERIFIED
    if _RUNTIME_INTEGRITY_VERIFIED:
        return
    from avikal_backend.runtime_requirements import verify_publisher_runtime_manifest

    verify_publisher_runtime_manifest()
    _RUNTIME_INTEGRITY_VERIFIED = True


def _build_suite(
    *,
    suite_id: str,
    profile: str,
    post_quantum_kem: str,
    authentication_signature: str,
    long_term_signature: str,
    custom: bool = False,
) -> dict[str, Any]:
    return {
        "suite_id": suite_id,
        "suite_version": PQC_SUITE_VERSION,
        "profile": profile,
        "provider": PQC_PROVIDER_NAME,
        "provider_minimum": "OpenSSL 3.5",
        "custom": custom,
        "algorithms": {
            "kem": f"{post_quantum_kem}+{X25519_ALGORITHM}",
            "post_quantum_kem": post_quantum_kem,
            "classical_kem": X25519_ALGORITHM,
            "kem_combiner": "HKDF-SHA3-256",
            "authentication_signature": authentication_signature,
            "long_term_signature": long_term_signature,
        },
    }


PQC_SUITE = _build_suite(
    suite_id=PQC_SUITE_ID,
    profile="maximum",
    post_quantum_kem=ML_KEM_ALGORITHM,
    authentication_signature=ML_DSA_ALGORITHM,
    long_term_signature=SLH_DSA_ALGORITHM,
)

PQC_STANDARD_SUITE = _build_suite(
    suite_id=PQC_STANDARD_SUITE_ID,
    profile="standard",
    post_quantum_kem="ML-KEM-768",
    authentication_signature="ML-DSA-65",
    long_term_signature="SLH-DSA-SHA2-128s",
)

PQC_SUITE_REGISTRY = {
    PQC_SUITE_ID: PQC_SUITE,
    PQC_STANDARD_SUITE_ID: PQC_STANDARD_SUITE,
}


class PQCProviderUnavailable(RuntimeError):
    """Raised when PQC was requested but the bundled OpenSSL runtime is absent."""


class PQCProviderError(RuntimeError):
    """Raised when OpenSSL returns malformed or failed output."""


def pqc_suite_options() -> dict[str, Any]:
    """Return the safe PQC choices exposed to UI and CLI callers."""
    return {
        "default_suite_id": PQC_DEFAULT_SUITE_ID,
        "profiles": {
            "standard": PQC_STANDARD_SUITE,
            "maximum": PQC_SUITE,
            "custom": {
                "suite_id": PQC_CUSTOM_SUITE_ID,
                "suite_version": PQC_SUITE_VERSION,
                "profile": "custom",
                "provider": PQC_PROVIDER_NAME,
                "provider_minimum": "OpenSSL 3.5",
                "custom": True,
                "choices": {
                    "post_quantum_kem": sorted(ML_KEM_ALGORITHMS),
                    "authentication_signature": sorted(ML_DSA_ALGORITHMS),
                    "long_term_signature": sorted(SLH_DSA_ALGORITHMS),
                    "classical_kem": [X25519_ALGORITHM],
                    "kem_combiner": ["HKDF-SHA3-256"],
                },
            },
        },
    }


def is_supported_pqc_suite_id(suite_id: str | None) -> bool:
    return suite_id in PQC_SUITE_REGISTRY or suite_id == PQC_CUSTOM_SUITE_ID


def resolve_pqc_suite(
    suite_id: str | None = None,
    custom_algorithms: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve and validate an Avikal PQC suite description."""
    normalized_suite_id = (suite_id or PQC_DEFAULT_SUITE_ID).strip()
    if normalized_suite_id in PQC_SUITE_REGISTRY:
        return json.loads(json.dumps(PQC_SUITE_REGISTRY[normalized_suite_id]))
    if normalized_suite_id != PQC_CUSTOM_SUITE_ID:
        raise ValueError("Unsupported PQC suite")

    algorithms = custom_algorithms or {}
    post_quantum_kem = algorithms.get("post_quantum_kem")
    authentication_signature = algorithms.get("authentication_signature")
    long_term_signature = algorithms.get("long_term_signature")
    if post_quantum_kem not in ML_KEM_ALGORITHMS:
        raise ValueError("Unsupported custom PQC KEM")
    if authentication_signature not in ML_DSA_ALGORITHMS:
        raise ValueError("Unsupported custom PQC authentication signature")
    if long_term_signature not in SLH_DSA_ALGORITHMS:
        raise ValueError("Unsupported custom PQC long-term signature")
    return _build_suite(
        suite_id=PQC_CUSTOM_SUITE_ID,
        profile="custom",
        post_quantum_kem=post_quantum_kem,
        authentication_signature=authentication_signature,
        long_term_signature=long_term_signature,
        custom=True,
    )


def _suite_from_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    suite_id = bundle.get("suite_id")
    algorithms = bundle.get("algorithms") if isinstance(bundle.get("algorithms"), dict) else {}
    if suite_id == PQC_CUSTOM_SUITE_ID:
        return resolve_pqc_suite(suite_id, algorithms)
    suite = resolve_pqc_suite(suite_id)
    if algorithms != suite.get("algorithms"):
        raise ValueError("Invalid PQC bundle algorithm set")
    return suite


def _openssl_binary_name(platform_name: str | None = None) -> str:
    return OPENSSL_EXE_NAME if (platform_name or sys.platform) == "win32" else "openssl"


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
    return runtime_backend_root()


def _project_root() -> Path:
    return runtime_project_root()


def _package_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _candidate_openssl_paths() -> list[Path]:
    candidates: list[Path] = []
    openssl_binary_name = _openssl_binary_name()

    env_path = os.environ.get("AVIKAL_OPENSSL_EXEC") if not runtime_is_frozen() else None
    if env_path:
        candidates.append(Path(env_path))

    runtime_dir = os.environ.get("AVIKAL_PQC_RUNTIME_DIR") if not runtime_is_frozen() else None
    if runtime_dir:
        runtime_root = Path(runtime_dir)
        candidates.extend(
            [
                runtime_root / "bin" / openssl_binary_name,
                runtime_root / openssl_binary_name,
            ]
        )

    executable_dir = Path(sys.executable).resolve().parent
    candidates.extend(
        [
            executable_dir / "pqc" / openssl_binary_name,
            executable_dir / "pqc" / "bin" / openssl_binary_name,
            executable_dir / openssl_binary_name,
            executable_dir.parent / "pqc" / openssl_binary_name,
            executable_dir.parent / "pqc" / "bin" / openssl_binary_name,
            executable_dir.parent / "backend-runtime" / "pqc" / openssl_binary_name,
            executable_dir.parent / "backend-runtime" / "pqc" / "bin" / openssl_binary_name,
        ]
    )

    project_root = _project_root()
    package_root = _package_root()
    candidates.extend(
        [
            package_root / "runtime" / "pqc" / openssl_binary_name,
            package_root / "runtime" / "pqc" / "bin" / openssl_binary_name,
            project_root / "runtime" / "pqc" / openssl_binary_name,
            project_root / "runtime" / "pqc" / "bin" / openssl_binary_name,
            project_root / ".app-build" / "backend-runtime" / "pqc" / openssl_binary_name,
            project_root / ".app-build" / "backend-runtime" / "pqc" / "bin" / openssl_binary_name,
            _backend_root() / "runtime" / "pqc" / openssl_binary_name,
            _backend_root() / "runtime" / "pqc" / "bin" / openssl_binary_name,
            _backend_root() / "backend-runtime" / "pqc" / openssl_binary_name,
            _backend_root() / "backend-runtime" / "pqc" / "bin" / openssl_binary_name,
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


def resolve_libcrypto_library() -> Path | None:
    """Resolve the bundled OpenSSL 3 libcrypto used by the native EVP bridge."""
    candidates: list[Path] = []
    if sys.platform == "win32":
        names = ("libcrypto-3-x64.dll", "libcrypto-3.dll")
    elif sys.platform == "darwin":
        names = ("libcrypto.3.dylib", "libcrypto.dylib")
    else:
        names = ("libcrypto.so.3", "libcrypto.so")
    for executable_candidate in _candidate_openssl_paths():
        parent = executable_candidate.parent
        for library_parent in (parent, parent.parent / "lib", parent.parent / "lib64"):
            candidates.extend(library_parent / name for name in names)
    configured = os.environ.get("AVIKAL_LIBCRYPTO_PATH") if not runtime_is_frozen() else None
    if configured:
        candidates.insert(0, Path(configured))
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except OSError:
            continue
        if resolved.is_file():
            return resolved
    return None


def require_libcrypto(*, verify_runtime_integrity: bool = True) -> Path:
    if verify_runtime_integrity:
        _ensure_runtime_integrity_verified()
    library = resolve_libcrypto_library()
    if library is None:
        raise PQCProviderUnavailable(
            "Bundled OpenSSL libcrypto is unavailable for native PQC operations."
        )
    return library


def _openssl_version(*, verify_runtime_integrity: bool = True) -> str:
    return openssl_runtime_version(str(require_libcrypto(verify_runtime_integrity=verify_runtime_integrity)))


def provider_status(*, verify_runtime_integrity: bool = True) -> dict[str, Any]:
    """Report whether the bundled OpenSSL PQC runtime is available."""
    executable = resolve_openssl_executable()
    library = resolve_libcrypto_library()
    if library is None:
        return {
            "available": False,
            "provider": PQC_PROVIDER_NAME,
            "suite": PQC_SUITE,
            "suite_options": pqc_suite_options(),
            "reason": (
                "OpenSSL PQC provider is unavailable. Bundle the OpenSSL 3.5+ "
                "libcrypto runtime under runtime/pqc."
            ),
        }

    status: dict[str, Any] = {
        "available": True,
        "provider": PQC_PROVIDER_NAME,
        "suite": PQC_SUITE,
        "suite_options": pqc_suite_options(),
        "executable": str(executable) if executable else None,
        "libcrypto": str(library),
        "execution_mode": "native_evp",
    }
    try:
        status["openssl_version"] = _openssl_version(verify_runtime_integrity=verify_runtime_integrity)
    except Exception as exc:
        status["available"] = False
        status["reason"] = f"Bundled OpenSSL runtime is not usable: {exc}"
    return status


def require_openssl() -> Path:
    """Resolve the OpenSSL executable or raise a fail-closed error."""
    _ensure_runtime_integrity_verified()
    executable = resolve_openssl_executable()
    if executable is None:
        raise PQCProviderUnavailable(provider_status()["reason"])
    return executable


def _generate_keypair(algorithm: str) -> tuple[str, str]:
    return openssl_generate_keypair(str(require_libcrypto()), algorithm)


def _public_binding(public_bundle: dict[str, Any]) -> bytes:
    binding = dict(public_bundle)
    binding.pop("signatures", None)
    return _canonical_json(binding)


def _sign_message(private_pem: str, message: bytes) -> bytes:
    return openssl_sign_message(str(require_libcrypto()), private_pem, message)


def _verify_signature(public_pem: str, message: bytes, signature: bytes) -> None:
    if not openssl_verify_signature(str(require_libcrypto()), public_pem, message, signature):
        raise PQCProviderError("OpenSSL PQC signature verification failed")


def _encapsulate_mlkem(public_pem: str) -> tuple[bytes, bytes]:
    return openssl_kem_encapsulate(str(require_libcrypto()), public_pem)


def _decapsulate_mlkem(private_pem: str, pqc_ciphertext: bytes) -> bytes:
    return openssl_kem_decapsulate(str(require_libcrypto()), private_pem, pqc_ciphertext)


def _derive_x25519(private_pem: str, peer_public_pem: str) -> bytes:
    return openssl_derive_secret(str(require_libcrypto()), private_pem, peer_public_pem)


def _length_prefixed(*parts: bytes) -> bytes:
    encoded = bytearray()
    for part in parts:
        if not isinstance(part, (bytes, bytearray)) or not part:
            raise PQCProviderError("PQC hybrid KEM produced an empty shared secret")
        encoded += struct.pack(">H", len(part))
        encoded += bytes(part)
    return bytes(encoded)


def _combine_hybrid_kem_secrets(mlkem_secret: bytes, x25519_secret: bytes, suite: dict[str, Any]) -> bytes:
    """Combine independent KEM secrets into one domain-separated suite secret."""
    suite_id = suite.get("suite_id") or PQC_SUITE_ID
    info = b"avikal_pqc_hybrid_kem_v1"
    if suite_id != PQC_SUITE_ID:
        info = f"avikal_pqc_hybrid_kem_v1|{suite_id}".encode("ascii")
    hkdf = HKDF(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(_length_prefixed(mlkem_secret, x25519_secret))


def _pack_hybrid_ciphertext(mlkem_ciphertext: bytes, x25519_ephemeral_public_pem: str) -> bytes:
    if len(mlkem_ciphertext) == 0 or len(mlkem_ciphertext) > MAX_MLKEM_CIPHERTEXT_BYTES:
        raise PQCProviderError("OpenSSL produced an invalid ML-KEM ciphertext")
    public_bytes = x25519_ephemeral_public_pem.encode("utf-8")
    if len(public_bytes) == 0 or len(public_bytes) > MAX_X25519_PUBLIC_PEM_BYTES:
        raise PQCProviderError("OpenSSL produced an invalid X25519 ephemeral public key")
    return (
        HYBRID_CIPHERTEXT_MAGIC
        + bytes([HYBRID_CIPHERTEXT_VERSION])
        + struct.pack(">HH", len(mlkem_ciphertext), len(public_bytes))
        + mlkem_ciphertext
        + public_bytes
    )


def _unpack_hybrid_ciphertext(hybrid_ciphertext: bytes) -> tuple[bytes, str]:
    if not isinstance(hybrid_ciphertext, (bytes, bytearray)):
        raise ValueError("PQC ciphertext must be bytes")
    hybrid_ciphertext = bytes(hybrid_ciphertext)
    header_size = len(HYBRID_CIPHERTEXT_MAGIC) + 1 + 4
    if len(hybrid_ciphertext) < header_size:
        raise ValueError("PQC ciphertext is truncated")
    if hybrid_ciphertext[:4] != HYBRID_CIPHERTEXT_MAGIC:
        raise ValueError("Unsupported PQC hybrid ciphertext")
    version = hybrid_ciphertext[4]
    if version != HYBRID_CIPHERTEXT_VERSION:
        raise ValueError("Unsupported PQC hybrid ciphertext version")
    mlkem_length, public_length = struct.unpack(">HH", hybrid_ciphertext[5:9])
    if mlkem_length == 0 or mlkem_length > MAX_MLKEM_CIPHERTEXT_BYTES:
        raise ValueError("PQC ML-KEM ciphertext length is invalid")
    if public_length == 0 or public_length > MAX_X25519_PUBLIC_PEM_BYTES:
        raise ValueError("PQC X25519 public key length is invalid")
    expected_length = header_size + mlkem_length + public_length
    if len(hybrid_ciphertext) != expected_length:
        raise ValueError("PQC hybrid ciphertext length is invalid")
    mlkem_ciphertext = hybrid_ciphertext[header_size:header_size + mlkem_length]
    public_start = header_size + mlkem_length
    try:
        x25519_public = hybrid_ciphertext[public_start:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("PQC X25519 public key is not valid UTF-8") from exc
    if "PUBLIC KEY" not in x25519_public:
        raise ValueError("PQC X25519 public key is malformed")
    return mlkem_ciphertext, x25519_public


def compute_pqc_key_id(public_bundle: dict[str, Any], pqc_ciphertext: bytes) -> str:
    """Bind the archive to the public PQC suite material and KEM ciphertext."""
    if not isinstance(public_bundle, dict) or not public_bundle:
        raise ValueError("PQC public bundle is required")
    if not pqc_ciphertext:
        raise ValueError("PQC ciphertext is required")
    suite_id = public_bundle.get("suite_id")
    if not is_supported_pqc_suite_id(suite_id):
        raise ValueError("Unsupported PQC public bundle")
    digest = hashlib.sha256()
    digest.update(str(suite_id).encode("ascii"))
    digest.update(b"\x00")
    digest.update(_canonical_json(public_bundle))
    digest.update(b"\x00")
    digest.update(pqc_ciphertext)
    return digest.hexdigest()


def create_pqc_archive_material(
    *,
    archive_filename: str,
    suite_id: str | None = None,
    custom_algorithms: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Generate archive-specific PQC material through the bundled OpenSSL runtime.
    """
    status = provider_status()
    if not status.get("available"):
        raise PQCProviderUnavailable(str(status.get("reason")))
    suite = resolve_pqc_suite(suite_id, custom_algorithms)
    algorithms = suite["algorithms"]
    ml_kem_algorithm = algorithms["post_quantum_kem"]
    ml_dsa_algorithm = algorithms["authentication_signature"]
    slh_dsa_algorithm = algorithms["long_term_signature"]

    operation_started = time.perf_counter()
    keygen_started = time.perf_counter()
    mlkem_private, mlkem_public = _generate_keypair(ml_kem_algorithm)
    x25519_private, x25519_public = _generate_keypair(X25519_ALGORITHM)
    x25519_ephemeral_private, x25519_ephemeral_public = _generate_keypair(X25519_ALGORITHM)
    mldsa_private, mldsa_public = _generate_keypair(ml_dsa_algorithm)
    slhdsa_private, slhdsa_public = _generate_keypair(slh_dsa_algorithm)
    keygen_ms = (time.perf_counter() - keygen_started) * 1000
    kem_started = time.perf_counter()
    mlkem_ciphertext, mlkem_shared_secret = _encapsulate_mlkem(mlkem_public)
    x25519_shared_secret = _derive_x25519(x25519_ephemeral_private, x25519_public)
    ciphertext = _pack_hybrid_ciphertext(mlkem_ciphertext, x25519_ephemeral_public)
    shared_secret = _combine_hybrid_kem_secrets(mlkem_shared_secret, x25519_shared_secret, suite)
    kem_ms = (time.perf_counter() - kem_started) * 1000

    public_bundle: dict[str, Any] = {
        "suite_id": suite["suite_id"],
        "suite_version": suite["suite_version"],
        "suite_profile": suite.get("profile"),
        "provider": PQC_PROVIDER_NAME,
        "openssl_version": status.get("openssl_version"),
        "archive_filename": archive_filename,
        "algorithms": dict(suite["algorithms"]),
        "keys": {
            "ml_kem_public_pem": mlkem_public,
            "x25519_public_pem": x25519_public,
            "ml_dsa_public_pem": mldsa_public,
            "slh_dsa_public_pem": slhdsa_public,
        },
    }
    binding = _public_binding(public_bundle)
    bundle_signing_started = time.perf_counter()
    public_bundle["signatures"] = {
        "ml_dsa_binding": _b64encode(_sign_message(mldsa_private, binding)),
        "slh_dsa_binding": _b64encode(_sign_message(slhdsa_private, binding)),
    }
    bundle_signing_ms = (time.perf_counter() - bundle_signing_started) * 1000

    private_bundle = {
        "suite_id": suite["suite_id"],
        "suite_version": suite["suite_version"],
        "suite_profile": suite.get("profile"),
        "provider": PQC_PROVIDER_NAME,
        "openssl_version": status.get("openssl_version"),
        "algorithms": dict(suite["algorithms"]),
        "keys": {
            "ml_kem_private_pem": mlkem_private,
            "x25519_private_pem": x25519_private,
            "ml_dsa_private_pem": mldsa_private,
            "slh_dsa_private_pem": slhdsa_private,
        },
    }

    return {
        "suite": suite,
        "algorithm": suite["suite_id"],
        "key_id": compute_pqc_key_id(public_bundle, ciphertext),
        "public_bundle": public_bundle,
        "private_bundle": private_bundle,
        "ciphertext": ciphertext,
        "shared_secret": shared_secret,
        "telemetry": {
            "keygen_ms": round(keygen_ms, 2),
            "kem_ms": round(kem_ms, 2),
            "bundle_signing_ms": round(bundle_signing_ms, 2),
            "total_ms": round((time.perf_counter() - operation_started) * 1000, 2),
            "execution_mode": "native_evp",
        },
    }


def create_archive_signing_identity(*, label: str = "", persistent: bool = False) -> dict[str, Any]:
    """Generate a dedicated dual-PQC archive signing identity."""
    status = provider_status()
    if not status.get("available"):
        raise PQCProviderUnavailable(str(status.get("reason")))
    keygen_started = time.perf_counter()
    ml_private, ml_public = _generate_keypair(ML_DSA_ALGORITHM)
    slh_private, slh_public = _generate_keypair(SLH_DSA_ALGORITHM)
    keygen_ms = (time.perf_counter() - keygen_started) * 1000
    public_core = {
        "algorithms": {"ml_dsa": ML_DSA_ALGORITHM, "slh_dsa": SLH_DSA_ALGORITHM},
        "format": ARCHIVE_SIGNING_IDENTITY_FORMAT,
        "keys": {"ml_dsa_public_pem": ml_public, "slh_dsa_public_pem": slh_public},
        "persistent": bool(persistent),
        "version": ARCHIVE_SIGNING_IDENTITY_VERSION,
    }
    identity_id = hashlib.sha256(_canonical_json(public_core)).hexdigest()
    public_bundle = dict(public_core)
    public_bundle["identity_id"] = identity_id
    public_bundle["label"] = str(label or "")[:128]
    private_bundle = {
        "algorithms": dict(public_core["algorithms"]),
        "format": ARCHIVE_SIGNING_IDENTITY_FORMAT,
        "identity_id": identity_id,
        "keys": {"ml_dsa_private_pem": ml_private, "slh_dsa_private_pem": slh_private},
        "persistent": bool(persistent),
        "version": ARCHIVE_SIGNING_IDENTITY_VERSION,
    }
    return {
        "identity_id": identity_id,
        "public_bundle": public_bundle,
        "private_bundle": private_bundle,
        "telemetry": {"keygen_ms": round(keygen_ms, 2), "execution_mode": "native_evp"},
    }


def _validate_signing_public_bundle(public_bundle: dict[str, Any]) -> None:
    if public_bundle.get("format") != ARCHIVE_SIGNING_IDENTITY_FORMAT:
        _validate_public_bundle(public_bundle)
        return
    if public_bundle.get("version") != ARCHIVE_SIGNING_IDENTITY_VERSION:
        raise ValueError("Unsupported archive signing identity")
    keys = public_bundle.get("keys")
    algorithms = public_bundle.get("algorithms")
    if not isinstance(keys, dict) or not isinstance(algorithms, dict):
        raise ValueError("Invalid archive signing identity")
    if algorithms.get("ml_dsa") not in ML_DSA_ALGORITHMS or algorithms.get("slh_dsa") not in SLH_DSA_ALGORITHMS:
        raise ValueError("Unsupported archive signing identity algorithms")
    for name in ("ml_dsa_public_pem", "slh_dsa_public_pem"):
        if not isinstance(keys.get(name), str) or "PUBLIC KEY" not in keys[name]:
            raise ValueError("Invalid archive signing public key")
    core = {key: public_bundle[key] for key in ("algorithms", "format", "keys", "persistent", "version")}
    expected_id = hashlib.sha256(_canonical_json(core)).hexdigest()
    if not hmac.compare_digest(str(public_bundle.get("identity_id") or ""), expected_id):
        raise ValueError("Archive signing identity fingerprint is invalid")


def _validate_signing_private_bundle(private_bundle: dict[str, Any]) -> None:
    if private_bundle.get("format") != ARCHIVE_SIGNING_IDENTITY_FORMAT:
        _validate_private_bundle(private_bundle)
        return
    if private_bundle.get("version") != ARCHIVE_SIGNING_IDENTITY_VERSION:
        raise ValueError("Unsupported archive signing identity")
    keys = private_bundle.get("keys")
    algorithms = private_bundle.get("algorithms")
    if not isinstance(keys, dict) or not isinstance(algorithms, dict):
        raise ValueError("Invalid archive signing identity")
    if algorithms.get("ml_dsa") not in ML_DSA_ALGORITHMS or algorithms.get("slh_dsa") not in SLH_DSA_ALGORITHMS:
        raise ValueError("Unsupported archive signing identity algorithms")
    for name in ("ml_dsa_private_pem", "slh_dsa_private_pem"):
        if not isinstance(keys.get(name), str) or "PRIVATE KEY" not in keys[name]:
            raise ValueError("Invalid archive signing private key")


def validate_archive_signing_identity(identity: dict[str, Any], *, require_private: bool = True) -> dict[str, Any]:
    """Validate matching public/private signing identity material."""
    if not isinstance(identity, dict):
        raise ValueError("Archive signing identity must be an object")
    public_bundle = identity.get("public_bundle")
    private_bundle = identity.get("private_bundle")
    if not isinstance(public_bundle, dict):
        raise ValueError("Archive signing public identity is missing")
    _validate_signing_public_bundle(public_bundle)
    if require_private:
        if not isinstance(private_bundle, dict):
            raise ValueError("Archive signing private identity is missing")
        _validate_signing_private_bundle(private_bundle)
        if public_bundle.get("identity_id") != private_bundle.get("identity_id"):
            raise ValueError("Archive signing identity key material does not match")
    return {"identity_id": public_bundle["identity_id"], "public_bundle": public_bundle, "private_bundle": private_bundle}


def _validate_public_bundle(public_bundle: dict[str, Any]) -> None:
    suite = _suite_from_bundle(public_bundle)
    keys = public_bundle.get("keys")
    signatures = public_bundle.get("signatures")
    if not isinstance(keys, dict) or not isinstance(signatures, dict):
        raise ValueError("Invalid PQC public bundle")
    for field_name in ("ml_kem_public_pem", "x25519_public_pem", "ml_dsa_public_pem", "slh_dsa_public_pem"):
        if not isinstance(keys.get(field_name), str) or not keys[field_name].strip():
            raise ValueError("Invalid PQC public bundle")
    for field_name in ("ml_dsa_binding", "slh_dsa_binding"):
        _b64decode(signatures.get(field_name), field_name)


def _validate_private_bundle(private_bundle: dict[str, Any]) -> None:
    _suite_from_bundle(private_bundle)
    keys = private_bundle.get("keys")
    if not isinstance(keys, dict):
        raise ValueError("Invalid PQC private bundle")
    for field_name in ("ml_kem_private_pem", "x25519_private_pem", "ml_dsa_private_pem", "slh_dsa_private_pem"):
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
    public_suite = _suite_from_bundle(public_bundle)
    private_suite = _suite_from_bundle(private_bundle)
    if public_suite["suite_id"] != private_suite["suite_id"] or public_suite["algorithms"] != private_suite["algorithms"]:
        raise ValueError("PQC public and private bundles use different suites")

    computed_key_id = compute_pqc_key_id(public_bundle, pqc_ciphertext)
    if expected_key_id and computed_key_id != expected_key_id:
        raise ValueError("PQC keyfile does not match this archive.")

    public_keys = public_bundle["keys"]
    private_keys = private_bundle["keys"]
    binding = _public_binding(public_bundle)
    mlkem_ciphertext, x25519_ephemeral_public = _unpack_hybrid_ciphertext(pqc_ciphertext)
    _verify_signature(
        public_keys["ml_dsa_public_pem"],
        binding,
        _b64decode(public_bundle["signatures"]["ml_dsa_binding"], "ml_dsa_binding"),
    )
    _verify_signature(
        public_keys["slh_dsa_public_pem"],
        binding,
        _b64decode(public_bundle["signatures"]["slh_dsa_binding"], "slh_dsa_binding"),
    )
    mlkem_shared_secret = _decapsulate_mlkem(private_keys["ml_kem_private_pem"], mlkem_ciphertext)
    x25519_shared_secret = _derive_x25519(
        private_keys["x25519_private_pem"],
        x25519_ephemeral_public,
    )
    return _combine_hybrid_kem_secrets(mlkem_shared_secret, x25519_shared_secret, public_suite)


MAX_ARCHIVE_SIGNING_MESSAGE_BYTES = 16 * 1024


def sign_pqc_archive_manifest(
    *,
    private_bundle: dict[str, Any],
    manifest: bytes,
) -> dict[str, str]:
    """Sign a bounded canonical archive manifest with both configured PQC schemes."""
    status = provider_status()
    if not status.get("available"):
        raise PQCProviderUnavailable(str(status.get("reason")))
    _validate_signing_private_bundle(private_bundle)
    message = bytes(manifest)
    if not message or len(message) > MAX_ARCHIVE_SIGNING_MESSAGE_BYTES:
        raise ValueError("Archive signing manifest size is out of bounds")

    keys = private_bundle["keys"]
    return {
        "ml_dsa": _b64encode(_sign_message(keys["ml_dsa_private_pem"], message)),
        "slh_dsa": _b64encode(_sign_message(keys["slh_dsa_private_pem"], message)),
    }


def verify_pqc_archive_manifest(
    *,
    public_bundle: dict[str, Any],
    manifest: bytes,
    signatures: dict[str, str],
) -> None:
    """Require valid ML-DSA and SLH-DSA signatures for an archive manifest."""
    status = provider_status()
    if not status.get("available"):
        raise PQCProviderUnavailable(str(status.get("reason")))
    _validate_signing_public_bundle(public_bundle)
    message = bytes(manifest)
    if not message or len(message) > MAX_ARCHIVE_SIGNING_MESSAGE_BYTES:
        raise ValueError("Archive signing manifest size is out of bounds")
    if not isinstance(signatures, dict):
        raise ValueError("Archive signatures are missing")

    keys = public_bundle["keys"]
    ml_public_name = "ml_dsa_public_pem"
    slh_public_name = "slh_dsa_public_pem"
    if public_bundle.get("format") != ARCHIVE_SIGNING_IDENTITY_FORMAT:
        ml_public_name = "ml_dsa_public_pem"
        slh_public_name = "slh_dsa_public_pem"
    try:
        _verify_signature(
            keys[ml_public_name],
            message,
            _b64decode(signatures.get("ml_dsa"), "archive_ml_dsa"),
        )
        _verify_signature(
            keys[slh_public_name],
            message,
            _b64decode(signatures.get("slh_dsa"), "archive_slh_dsa"),
        )
    except Exception as exc:
        raise ValueError("Archive PQC signature verification failed") from exc
