"""Encrypted external and embedded PQC material support.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from avikal_backend.core.secure_delete import secure_remove_file
from avikal_backend.core.temp_janitor import register_temp_artifact, unregister_temp_artifact

from ..security.crypto import derive_argon2id_key
from ..security.native_bridge import aes256gcm_decrypt, aes256gcm_encrypt, hkdf_sha256, random_bytes
from ..security.password_validator import validate_password_strength
from ..security.pqc_provider import (
    PQC_DEFAULT_SUITE_ID,
    compute_pqc_key_id,
    is_supported_pqc_suite_id,
    resolve_pqc_suite,
)


PQC_KEYFILE_FORMAT = "avikal-pqc-keyfile"
PQC_KEYFILE_VERSION = 1
PQC_KEYFILE_ALGORITHM = PQC_DEFAULT_SUITE_ID
PQC_KEYFILE_EXTENSION = ".avkkey"
PQC_KEYFILE_MAX_BYTES = 4 * 1024 * 1024
PQC_KEYFILE_PROTECTION_ARCHIVE_SECRET = "archive_secret"
PQC_KEYFILE_PROTECTION_DUAL_PASSWORD = "dual_password"
PQC_KEYFILE_PROTECTION_MODES = {
    PQC_KEYFILE_PROTECTION_ARCHIVE_SECRET,
    PQC_KEYFILE_PROTECTION_DUAL_PASSWORD,
}
PQC_KEYFILE_WRAPPER_FORMAT = "avikal-pqc-keyfile-wrapper"
PQC_KEYFILE_WRAPPER_VERSION = 1
PQC_STORAGE_MODE_EXTERNAL = "external"
PQC_STORAGE_MODE_EMBEDDED = "embedded"
PQC_STORAGE_MODES = {PQC_STORAGE_MODE_EXTERNAL, PQC_STORAGE_MODE_EMBEDDED}
PQC_EMBEDDED_FORMAT = "avikal-pqc-embedded"
PQC_EMBEDDED_VERSION = 1
PQC_EMBEDDED_MEMBER_NAME = "pqc.enc"


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except Exception as exc:
        raise ValueError(f"Invalid PQC keyfile: malformed {field_name}") from exc


def _require_secret(password: str | None, keyphrase: list | None) -> None:
    if password:
        return
    if keyphrase and isinstance(keyphrase, list) and any(str(word).strip() for word in keyphrase):
        return
    raise ValueError(
        "PQC keyfile protection requires a password or keyphrase. "
        "Enable PQC only when archive secrets are configured."
    )


def _derive_keyfile_encryption_key(password: str | None, keyphrase: list | None, salt: bytes) -> bytes:
    """Derive a domain-separated AES key for the external PQC keyfile."""
    _require_secret(password, keyphrase)
    master_key, _ = derive_argon2id_key(password=password, keyphrase=keyphrase, salt=salt)
    return hkdf_sha256(master_key, salt, b"avikal_pqc_keyfile_v1", length=32)


def _require_keyfile_password(keyfile_password: str | None) -> str:
    if not isinstance(keyfile_password, str) or not keyfile_password.strip():
        raise ValueError("This .avkkey requires its keyfile password.")
    return keyfile_password


def _derive_keyfile_outer_key(keyfile_password: str | None, salt: bytes) -> bytes:
    password = _require_keyfile_password(keyfile_password)
    master_key, _ = derive_argon2id_key(password=password, keyphrase=None, salt=salt)
    return hkdf_sha256(master_key, salt, b"avikal_pqc_keyfile_outer_v1", length=32)


def _derive_embedded_encryption_key(password: str | None, keyphrase: list | None, salt: bytes) -> bytes:
    """Derive a domain-separated AES key for the embedded PQC bundle."""
    _require_secret(password, keyphrase)
    master_key, _ = derive_argon2id_key(password=password, keyphrase=keyphrase, salt=salt)
    return hkdf_sha256(master_key, salt, b"avikal_pqc_embedded_v1", length=32)


def _canonical_json_size(document: dict[str, Any]) -> int:
    return len(json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _require_bundle(value: dict[str, Any], bundle_name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        raise ValueError(f"PQC {bundle_name} bundle is missing")
    return value


def _suite_for_document_algorithm(
    algorithm: str,
    bundle: dict[str, Any] | None = None,
    document: dict[str, Any] | None = None,
) -> dict[str, Any]:
    algorithms = bundle.get("algorithms") if isinstance(bundle, dict) and isinstance(bundle.get("algorithms"), dict) else None
    if algorithms is None and isinstance(document, dict):
        suite = document.get("suite")
        if isinstance(suite, dict) and isinstance(suite.get("algorithms"), dict):
            algorithms = suite["algorithms"]
    return resolve_pqc_suite(algorithm, algorithms)


def _embedded_pqc_aad(header_aad: bytes, *, algorithm: str, key_id: str) -> bytes:
    if not isinstance(header_aad, (bytes, bytearray)) or not header_aad:
        raise ValueError("Embedded PQC protection requires archive header bytes")
    if not isinstance(key_id, str) or not key_id:
        raise ValueError("Embedded PQC protection requires a key identifier")
    if not is_supported_pqc_suite_id(algorithm):
        raise ValueError("Unsupported embedded PQC algorithm")
    return b"|".join(
        [
            PQC_EMBEDDED_FORMAT.encode("utf-8"),
            str(PQC_EMBEDDED_VERSION).encode("ascii"),
            algorithm.encode("utf-8"),
            key_id.encode("ascii"),
            _b64encode(bytes(header_aad)).encode("ascii"),
        ]
    )


def _keyfile_aad(*, algorithm: str, key_id: str) -> bytes:
    return f"{PQC_KEYFILE_FORMAT}|{PQC_KEYFILE_VERSION}|{algorithm}|{key_id}".encode("utf-8")


def _keyfile_wrapper_aad(*, algorithm: str, key_id: str) -> bytes:
    return f"{PQC_KEYFILE_WRAPPER_FORMAT}|{PQC_KEYFILE_WRAPPER_VERSION}|{algorithm}|{key_id}".encode("utf-8")


def _load_keyfile_document(keyfile_path: str) -> dict[str, Any]:
    if not keyfile_path:
        raise ValueError(
            "This archive requires an external PQC keyfile. "
            "Please provide the .avkkey file created during encryption."
        )

    resolved_path = os.path.abspath(keyfile_path)
    if not os.path.exists(resolved_path):
        raise ValueError(f"PQC keyfile not found: {resolved_path}")
    if os.path.getsize(resolved_path) > PQC_KEYFILE_MAX_BYTES:
        raise ValueError("Invalid PQC keyfile: file is too large")

    try:
        with open(resolved_path, "r", encoding="utf-8") as f:
            document = json.load(f)
    except Exception as exc:
        raise ValueError("Invalid PQC keyfile: unable to read JSON document") from exc

    if not isinstance(document, dict):
        raise ValueError("Invalid PQC keyfile: top-level document must be an object")
    return document


def default_keyfile_path_for_archive(output_filepath: str) -> str:
    """Generate a sibling .avkkey path next to an .avk archive."""
    path = Path(output_filepath)
    if path.suffix:
        return str(path.with_suffix(PQC_KEYFILE_EXTENSION))
    return str(path.with_name(path.name + PQC_KEYFILE_EXTENSION))


def wrap_pqc_keyfile_document(
    inner_document_bytes: bytes,
    keyfile_password: str | None,
    *,
    key_id: str,
    algorithm: str,
) -> dict[str, Any]:
    """Encrypt a normal .avkkey JSON document inside a second password envelope."""
    if not is_supported_pqc_suite_id(algorithm):
        raise ValueError("Unsupported PQC keyfile wrapper algorithm")
    if not isinstance(inner_document_bytes, (bytes, bytearray)) or not inner_document_bytes:
        raise ValueError("PQC keyfile wrapper requires an inner document")
    if not isinstance(key_id, str) or not key_id:
        raise ValueError("PQC keyfile wrapper requires a key identifier")
    try:
        inner_document = json.loads(bytes(inner_document_bytes).decode("utf-8"))
    except Exception as exc:
        raise ValueError("PQC keyfile wrapper inner document is malformed") from exc
    if not isinstance(inner_document, dict):
        raise ValueError("PQC keyfile wrapper inner document must be an object")
    suite = _suite_for_document_algorithm(algorithm, inner_document.get("public_bundle"), inner_document)

    salt = random_bytes(32)
    nonce = random_bytes(12)
    outer_key = _derive_keyfile_outer_key(keyfile_password, salt)
    ciphertext = aes256gcm_encrypt(
        outer_key,
        nonce,
        bytes(inner_document_bytes),
        _keyfile_wrapper_aad(algorithm=algorithm, key_id=key_id),
    )
    document = {
        "format": PQC_KEYFILE_WRAPPER_FORMAT,
        "version": PQC_KEYFILE_WRAPPER_VERSION,
        "protection_mode": PQC_KEYFILE_PROTECTION_DUAL_PASSWORD,
        "algorithm": algorithm,
        "key_id": key_id,
        "suite": suite,
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }
    if _canonical_json_size(document) > PQC_KEYFILE_MAX_BYTES:
        raise ValueError("PQC keyfile wrapper document is too large")
    return document


def unwrap_pqc_keyfile_document(
    wrapper_document: dict[str, Any],
    keyfile_password: str | None,
) -> dict[str, Any]:
    """Decrypt a dual-password .avkkey wrapper and return the normal v1 document."""
    if not isinstance(wrapper_document, dict):
        raise ValueError("Invalid PQC keyfile wrapper: top-level document must be an object")
    if wrapper_document.get("format") != PQC_KEYFILE_WRAPPER_FORMAT:
        raise ValueError("Invalid PQC keyfile wrapper: unexpected file format")
    if wrapper_document.get("version") != PQC_KEYFILE_WRAPPER_VERSION:
        raise ValueError("Invalid PQC keyfile wrapper: unsupported version")
    if wrapper_document.get("protection_mode") != PQC_KEYFILE_PROTECTION_DUAL_PASSWORD:
        raise ValueError("Invalid PQC keyfile wrapper: unsupported protection mode")

    algorithm = wrapper_document.get("algorithm")
    key_id = wrapper_document.get("key_id")
    if not is_supported_pqc_suite_id(algorithm):
        raise ValueError("Invalid PQC keyfile wrapper: unsupported algorithm")
    if not isinstance(key_id, str) or not key_id:
        raise ValueError("Invalid PQC keyfile wrapper: missing key identifier")

    salt = _b64decode(wrapper_document.get("salt", ""), "salt")
    nonce = _b64decode(wrapper_document.get("nonce", ""), "nonce")
    ciphertext = _b64decode(wrapper_document.get("ciphertext", ""), "ciphertext")
    if len(salt) != 32 or len(nonce) != 12:
        raise ValueError("Invalid PQC keyfile wrapper: malformed encryption parameters")

    outer_key = _derive_keyfile_outer_key(keyfile_password, salt)
    try:
        plaintext = aes256gcm_decrypt(
            outer_key,
            nonce,
            ciphertext,
            _keyfile_wrapper_aad(algorithm=algorithm, key_id=key_id),
        )
    except Exception as exc:
        raise ValueError("Incorrect .avkkey password or corrupted keyfile.") from exc

    try:
        document = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Invalid PQC keyfile wrapper: inner document is malformed") from exc
    if not isinstance(document, dict):
        raise ValueError("Invalid PQC keyfile wrapper: inner document must be an object")
    if document.get("format") != PQC_KEYFILE_FORMAT:
        raise ValueError("Invalid PQC keyfile wrapper: inner document format mismatch")
    if document.get("key_id") != key_id:
        raise ValueError("Invalid PQC keyfile wrapper: inner key identifier mismatch")
    return document


def inspect_pqc_keyfile(keyfile_path: str) -> dict[str, Any]:
    """Inspect public .avkkey metadata without decrypting private PQC material."""
    document = _load_keyfile_document(keyfile_path)
    fmt = document.get("format")
    if fmt == PQC_KEYFILE_FORMAT:
        version = document.get("version")
        if version != PQC_KEYFILE_VERSION:
            raise ValueError("Invalid PQC keyfile: unsupported version")
        if not is_supported_pqc_suite_id(document.get("algorithm")):
            raise ValueError("Invalid PQC keyfile: unsupported algorithm")
        if not isinstance(document.get("key_id"), str) or not document.get("key_id"):
            raise ValueError("Invalid PQC keyfile: missing key identifier")
        return {
            "success": True,
            "format": PQC_KEYFILE_FORMAT,
            "version": version,
            "algorithm": document.get("algorithm"),
            "key_id": document.get("key_id"),
            "protection_mode": PQC_KEYFILE_PROTECTION_ARCHIVE_SECRET,
            "requires_keyfile_password": False,
        }
    if fmt == PQC_KEYFILE_WRAPPER_FORMAT:
        version = document.get("version")
        if version != PQC_KEYFILE_WRAPPER_VERSION:
            raise ValueError("Invalid PQC keyfile wrapper: unsupported version")
        if not is_supported_pqc_suite_id(document.get("algorithm")):
            raise ValueError("Invalid PQC keyfile wrapper: unsupported algorithm")
        if not isinstance(document.get("key_id"), str) or not document.get("key_id"):
            raise ValueError("Invalid PQC keyfile wrapper: missing key identifier")
        return {
            "success": True,
            "format": PQC_KEYFILE_WRAPPER_FORMAT,
            "version": version,
            "algorithm": document.get("algorithm"),
            "key_id": document.get("key_id"),
            "protection_mode": PQC_KEYFILE_PROTECTION_DUAL_PASSWORD,
            "requires_keyfile_password": True,
        }
    raise ValueError("Invalid PQC keyfile: unexpected file format")


def write_pqc_keyfile(
    output_path: str,
    *,
    password: str | None,
    keyphrase: list | None,
    private_bundle: dict[str, Any],
    public_bundle: dict[str, Any],
    pqc_ciphertext: bytes,
    archive_filename: str,
    algorithm: str = PQC_KEYFILE_ALGORITHM,
    protection_mode: str = PQC_KEYFILE_PROTECTION_ARCHIVE_SECRET,
    keyfile_password: str | None = None,
) -> dict[str, Any]:
    """
    Create an encrypted external PQC keyfile.

    The private bundle never appears in the .avk container. It is AES-GCM
    protected with a key derived from the same user secret that unlocks the
    archive.
    """
    if not is_supported_pqc_suite_id(algorithm):
        raise ValueError("Unsupported PQC keyfile algorithm")
    if protection_mode is None:
        protection_mode = PQC_KEYFILE_PROTECTION_ARCHIVE_SECRET
    if protection_mode not in PQC_KEYFILE_PROTECTION_MODES:
        raise ValueError("Unsupported PQC keyfile protection mode")
    if protection_mode == PQC_KEYFILE_PROTECTION_DUAL_PASSWORD:
        password_text = _require_keyfile_password(keyfile_password)
        if password and password_text == password:
            raise ValueError("The .avkkey password must be different from the archive password.")
        validate_password_strength(password_text, min_length=12)
    if not isinstance(private_bundle, dict) or not private_bundle:
        raise ValueError("PQC private bundle is missing")
    if not isinstance(public_bundle, dict) or not public_bundle:
        raise ValueError("PQC public bundle is missing")
    if not pqc_ciphertext:
        raise ValueError("PQC ciphertext is missing")

    output_path = os.path.abspath(output_path)
    if os.path.exists(output_path):
        raise ValueError(
            f"PQC keyfile already exists: {output_path}. "
            "Choose a different path or remove the existing keyfile first."
        )

    salt = random_bytes(32)
    nonce = random_bytes(12)
    key_id = compute_pqc_key_id(public_bundle, pqc_ciphertext)
    suite = _suite_for_document_algorithm(algorithm, public_bundle)
    inner_kdf_started = time.perf_counter()
    keyfile_key = _derive_keyfile_encryption_key(password, keyphrase, salt)
    inner_kdf_ms = (time.perf_counter() - inner_kdf_started) * 1000

    inner_payload = {
        "format": PQC_KEYFILE_FORMAT,
        "version": PQC_KEYFILE_VERSION,
        "algorithm": algorithm,
        "suite": suite,
        "key_id": key_id,
        "archive_filename": archive_filename,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "private_bundle": private_bundle,
        "public_bundle": public_bundle,
    }
    if _canonical_json_size(inner_payload) > PQC_KEYFILE_MAX_BYTES:
        raise ValueError("PQC keyfile payload is too large")

    plaintext = json.dumps(inner_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    aad = f"{PQC_KEYFILE_FORMAT}|{PQC_KEYFILE_VERSION}|{algorithm}|{key_id}".encode("utf-8")
    ciphertext = aes256gcm_encrypt(keyfile_key, nonce, plaintext, aad)

    outer_document = {
        "format": PQC_KEYFILE_FORMAT,
        "version": PQC_KEYFILE_VERSION,
        "algorithm": algorithm,
        "key_id": key_id,
        "suite": suite,
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }
    if _canonical_json_size(outer_document) > PQC_KEYFILE_MAX_BYTES:
        raise ValueError("PQC keyfile document is too large")

    document_to_write = outer_document
    outer_wrapper_ms = 0.0
    if protection_mode == PQC_KEYFILE_PROTECTION_DUAL_PASSWORD:
        inner_document_bytes = json.dumps(outer_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        outer_wrapper_started = time.perf_counter()
        document_to_write = wrap_pqc_keyfile_document(
            inner_document_bytes,
            keyfile_password,
            key_id=key_id,
            algorithm=algorithm,
        )
        outer_wrapper_ms = (time.perf_counter() - outer_wrapper_started) * 1000

    write_started = time.perf_counter()
    output_directory = os.path.dirname(output_path) or os.getcwd()
    temporary = tempfile.NamedTemporaryFile(
        prefix=".avikal-keyfile-",
        suffix=PQC_KEYFILE_EXTENSION,
        dir=output_directory,
        delete=False,
    )
    temporary_path = temporary.name
    temporary.close()
    register_temp_artifact(temporary_path)
    try:
        with open(temporary_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(document_to_write, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        # Hard-link publication is atomic and refuses to replace an existing keyfile.
        # After the link succeeds both paths reference the same file content, so
        # only unlink the temporary name. Secure-wiping the temp path would also
        # wipe the published .avkkey on filesystems with hard-link semantics.
        os.link(temporary_path, output_path)
        os.unlink(temporary_path)
        unregister_temp_artifact(temporary_path)
    except Exception:
        try:
            if os.path.exists(temporary_path):
                secure_remove_file(temporary_path)
        finally:
            unregister_temp_artifact(temporary_path)
        raise
    write_ms = (time.perf_counter() - write_started) * 1000

    return {
        "key_id": key_id,
        "algorithm": algorithm,
        "path": output_path,
        "protection_mode": protection_mode,
        "requires_keyfile_password": protection_mode == PQC_KEYFILE_PROTECTION_DUAL_PASSWORD,
        "telemetry": {
            "inner_kdf_ms": round(inner_kdf_ms, 2),
            "outer_wrapper_ms": round(outer_wrapper_ms, 2),
            "write_ms": round(write_ms, 2),
        },
    }


def build_embedded_pqc_blob(
    *,
    password: str | None,
    keyphrase: list | None,
    private_bundle: dict[str, Any],
    public_bundle: dict[str, Any],
    pqc_ciphertext: bytes,
    archive_filename: str,
    header_aad: bytes,
    key_id: str | None = None,
    algorithm: str = PQC_KEYFILE_ALGORITHM,
) -> bytes:
    """Create the encrypted pqc.enc member for embedded PQC archives."""
    if not is_supported_pqc_suite_id(algorithm):
        raise ValueError("Unsupported embedded PQC algorithm")
    private_bundle = _require_bundle(private_bundle, "private")
    public_bundle = _require_bundle(public_bundle, "public")
    if not pqc_ciphertext:
        raise ValueError("PQC ciphertext is missing")

    resolved_key_id = key_id or compute_pqc_key_id(public_bundle, pqc_ciphertext)
    suite = _suite_for_document_algorithm(algorithm, public_bundle)
    salt = random_bytes(32)
    nonce = random_bytes(12)
    embedded_key = _derive_embedded_encryption_key(password, keyphrase, salt)

    inner_payload = {
        "format": PQC_EMBEDDED_FORMAT,
        "version": PQC_EMBEDDED_VERSION,
        "storage_mode": PQC_STORAGE_MODE_EMBEDDED,
        "algorithm": algorithm,
        "suite": suite,
        "key_id": resolved_key_id,
        "archive_filename": archive_filename,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "private_bundle": private_bundle,
        "public_bundle": public_bundle,
    }
    if _canonical_json_size(inner_payload) > PQC_KEYFILE_MAX_BYTES:
        raise ValueError("Embedded PQC bundle payload is too large")

    plaintext = json.dumps(inner_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    aad = _embedded_pqc_aad(header_aad, algorithm=algorithm, key_id=resolved_key_id)
    ciphertext = aes256gcm_encrypt(embedded_key, nonce, plaintext, aad)

    outer_document = {
        "format": PQC_EMBEDDED_FORMAT,
        "version": PQC_EMBEDDED_VERSION,
        "storage_mode": PQC_STORAGE_MODE_EMBEDDED,
        "algorithm": algorithm,
        "key_id": resolved_key_id,
        "suite": suite,
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }
    encoded = json.dumps(outer_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > PQC_KEYFILE_MAX_BYTES:
        raise ValueError("Embedded PQC bundle document is too large")
    return encoded


def read_pqc_keyfile(
    keyfile_path: str,
    *,
    password: str | None,
    keyphrase: list | None,
    expected_key_id: str | None = None,
    expected_algorithm: str = PQC_KEYFILE_ALGORITHM,
    pqc_keyfile_password: str | None = None,
) -> dict[str, Any]:
    """Read and decrypt an external PQC keyfile."""
    keyfile_path = os.path.abspath(keyfile_path)
    document = _load_keyfile_document(keyfile_path)

    if document.get("format") == PQC_KEYFILE_WRAPPER_FORMAT:
        document = unwrap_pqc_keyfile_document(document, pqc_keyfile_password)

    if document.get("format") != PQC_KEYFILE_FORMAT:
        raise ValueError("Invalid PQC keyfile: unexpected file format")
    if document.get("version") != PQC_KEYFILE_VERSION:
        raise ValueError("Invalid PQC keyfile: unsupported version")

    algorithm = document.get("algorithm")
    key_id = document.get("key_id")
    if algorithm != expected_algorithm or not is_supported_pqc_suite_id(algorithm):
        raise ValueError("Invalid PQC keyfile: unsupported algorithm")
    if expected_key_id and key_id != expected_key_id:
        raise ValueError("PQC keyfile does not match this archive.")

    salt = _b64decode(document.get("salt", ""), "salt")
    nonce = _b64decode(document.get("nonce", ""), "nonce")
    ciphertext = _b64decode(document.get("ciphertext", ""), "ciphertext")
    if len(salt) != 32 or len(nonce) != 12:
        raise ValueError("Invalid PQC keyfile: malformed encryption parameters")

    keyfile_key = _derive_keyfile_encryption_key(password, keyphrase, salt)
    aad = _keyfile_aad(algorithm=algorithm, key_id=key_id)
    try:
        plaintext = aes256gcm_decrypt(keyfile_key, nonce, ciphertext, aad)
    except Exception as exc:
        raise ValueError(
            "Failed to decrypt the PQC keyfile. Check the password/keyphrase and keyfile."
        ) from exc

    try:
        inner_payload = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Invalid PQC keyfile: decrypted payload is malformed") from exc

    if not isinstance(inner_payload, dict):
        raise ValueError("Invalid PQC keyfile: decrypted payload must be an object")
    if inner_payload.get("version") != PQC_KEYFILE_VERSION:
        raise ValueError("Invalid PQC keyfile: decrypted payload version mismatch")
    if inner_payload.get("algorithm") != expected_algorithm:
        raise ValueError("Invalid PQC keyfile: algorithm mismatch")
    if expected_key_id and inner_payload.get("key_id") != expected_key_id:
        raise ValueError("PQC keyfile does not match this archive.")

    private_bundle = inner_payload.get("private_bundle")
    public_bundle = inner_payload.get("public_bundle")
    if not isinstance(private_bundle, dict) or not private_bundle:
        raise ValueError("Invalid PQC keyfile: private bundle is empty")
    if not isinstance(public_bundle, dict) or not public_bundle:
        raise ValueError("Invalid PQC keyfile: public bundle is empty")

    return {
        "key_id": inner_payload.get("key_id"),
        "algorithm": inner_payload.get("algorithm"),
        "suite": inner_payload.get("suite"),
        "private_bundle": private_bundle,
        "public_bundle": public_bundle,
        "archive_filename": inner_payload.get("archive_filename"),
        "created_at": inner_payload.get("created_at"),
        "path": keyfile_path,
    }


def read_embedded_pqc_blob(
    embedded_blob: bytes,
    *,
    password: str | None,
    keyphrase: list | None,
    header_aad: bytes,
    expected_key_id: str | None = None,
    expected_algorithm: str = PQC_KEYFILE_ALGORITHM,
) -> dict[str, Any]:
    """Read and decrypt the pqc.enc member for embedded PQC archives."""
    if not isinstance(embedded_blob, (bytes, bytearray)) or not embedded_blob:
        raise ValueError("Invalid embedded PQC bundle: missing encrypted member")
    if len(embedded_blob) > PQC_KEYFILE_MAX_BYTES:
        raise ValueError("Invalid embedded PQC bundle: file is too large")

    try:
        document = json.loads(bytes(embedded_blob).decode("utf-8"))
    except Exception as exc:
        raise ValueError("Invalid embedded PQC bundle: unable to read JSON document") from exc

    if not isinstance(document, dict):
        raise ValueError("Invalid embedded PQC bundle: top-level document must be an object")
    if document.get("format") != PQC_EMBEDDED_FORMAT:
        raise ValueError("Invalid embedded PQC bundle: unexpected file format")
    if document.get("version") != PQC_EMBEDDED_VERSION:
        raise ValueError("Invalid embedded PQC bundle: unsupported version")
    if document.get("storage_mode") != PQC_STORAGE_MODE_EMBEDDED:
        raise ValueError("Invalid embedded PQC bundle: unsupported storage mode")

    algorithm = document.get("algorithm")
    key_id = document.get("key_id")
    if algorithm != expected_algorithm or not is_supported_pqc_suite_id(algorithm):
        raise ValueError("Invalid embedded PQC bundle: unsupported algorithm")
    if expected_key_id and key_id != expected_key_id:
        raise ValueError("Embedded PQC bundle does not match this archive.")

    salt = _b64decode(document.get("salt", ""), "salt")
    nonce = _b64decode(document.get("nonce", ""), "nonce")
    ciphertext = _b64decode(document.get("ciphertext", ""), "ciphertext")
    if len(salt) != 32 or len(nonce) != 12:
        raise ValueError("Invalid embedded PQC bundle: malformed encryption parameters")

    embedded_key = _derive_embedded_encryption_key(password, keyphrase, salt)
    aad = _embedded_pqc_aad(header_aad, algorithm=algorithm, key_id=key_id)
    try:
        plaintext = aes256gcm_decrypt(embedded_key, nonce, ciphertext, aad)
    except Exception as exc:
        raise ValueError(
            "Failed to decrypt the embedded PQC bundle. Check the password or keyphrase."
        ) from exc

    try:
        inner_payload = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Invalid embedded PQC bundle: decrypted payload is malformed") from exc

    if not isinstance(inner_payload, dict):
        raise ValueError("Invalid embedded PQC bundle: decrypted payload must be an object")
    if inner_payload.get("version") != PQC_EMBEDDED_VERSION:
        raise ValueError("Invalid embedded PQC bundle: decrypted payload version mismatch")
    if inner_payload.get("storage_mode") != PQC_STORAGE_MODE_EMBEDDED:
        raise ValueError("Invalid embedded PQC bundle: decrypted payload storage mode mismatch")
    if inner_payload.get("algorithm") != expected_algorithm:
        raise ValueError("Invalid embedded PQC bundle: algorithm mismatch")
    if expected_key_id and inner_payload.get("key_id") != expected_key_id:
        raise ValueError("Embedded PQC bundle does not match this archive.")

    private_bundle = inner_payload.get("private_bundle")
    public_bundle = inner_payload.get("public_bundle")
    if not isinstance(private_bundle, dict) or not private_bundle:
        raise ValueError("Invalid embedded PQC bundle: private bundle is empty")
    if not isinstance(public_bundle, dict) or not public_bundle:
        raise ValueError("Invalid embedded PQC bundle: public bundle is empty")

    return {
        "key_id": inner_payload.get("key_id"),
        "algorithm": inner_payload.get("algorithm"),
        "suite": inner_payload.get("suite"),
        "private_bundle": private_bundle,
        "public_bundle": public_bundle,
        "archive_filename": inner_payload.get("archive_filename"),
        "created_at": inner_payload.get("created_at"),
        "storage_mode": PQC_STORAGE_MODE_EMBEDDED,
    }
